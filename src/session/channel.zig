//! Messages over a Unix stream socket, on the loop. txd and a session
//! process talk over one channel for each attached client, and one for
//! each request txd makes of the session.
//!
//! What is sent is copied into a queue and written in order. Past
//! `high_water` queued bytes the channel is `congested`, and
//! `Handler.drained` is called once the queue is back under `low_water`.
//! While reading is paused, the peer's writes back up in the socket.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const posix = std.posix;
const xev = @import("xev");
const proto = @import("proto");
const unix = @import("unix.zig");

pub const high_water = 256 << 10;
pub const low_water = 64 << 10;

/// The longest message body accepted, as from a client.
pub const max_message = 1 << 20;

/// The most bytes read from the socket at once.
const read_size = 64 << 10;

pub const Handler = struct {
    context: *anyopaque,
    /// A message arrived. Its bytes are valid until the callback returns.
    received: *const fn (context: *anyopaque, channel: *Channel, raw: proto.Decoder.Raw) void,
    /// The queue went back under `low_water` after the channel was
    /// congested.
    drained: ?*const fn (context: *anyopaque, channel: *Channel) void = null,
    /// The channel closed: the peer closed its end, a read or write
    /// failed, a message didn't decode, or `finish` wrote the queue. No
    /// call follows, and the channel frees itself.
    closed: *const fn (context: *anyopaque, channel: *Channel) void,
};

pub const Channel = struct {
    gpa: Allocator,
    loop: *xev.Loop,
    socket: xev.TCP,
    /// Null after `close`.
    handler: ?Handler,
    decoder: proto.Decoder,
    read_buf: []u8,
    read_c: xev.Completion = .{},
    /// A read is in flight, or its callback is running.
    reading: bool = false,
    /// Set by `pauseReading`.
    paused: bool = false,
    /// Bytes waiting for the write in flight.
    queue: std.ArrayList(u8) = .empty,
    /// The bytes of the write in flight, from `written` on.
    writing: std.ArrayList(u8) = .empty,
    written: usize = 0,
    write_c: xev.Completion = .{},
    /// A write is in flight, or its callback is running.
    write_active: bool = false,
    /// The queue went past `high_water`, and hasn't drained since.
    was_congested: bool = false,
    state: enum {
        open,
        /// Writing the queue, then closing.
        finishing,
        /// Waiting for the read and write in flight to end.
        closing,
        /// Being freed.
        done,
    } = .open,

    /// Takes `fd`, a socket from `unix`, and starts reading.
    pub fn create(gpa: Allocator, loop: *xev.Loop, fd: posix.fd_t, handler: Handler) Allocator.Error!*Channel {
        const ch = try gpa.create(Channel);
        errdefer gpa.destroy(ch);
        ch.* = .{
            .gpa = gpa,
            .loop = loop,
            .socket = .initFd(fd),
            .handler = handler,
            .decoder = .init(gpa, max_message),
            .read_buf = try gpa.alloc(u8, read_size),
        };
        ch.startRead();
        return ch;
    }

    /// Encodes `message` onto the queue. Out of memory closes the channel.
    pub fn send(ch: *Channel, message: proto.Message) void {
        if (ch.state != .open) return;
        const len = proto.encodedLen(message);
        ch.queue.ensureUnusedCapacity(ch.gpa, len) catch return ch.shut();
        var w: Io.Writer = .fixed(ch.queue.unusedCapacitySlice());
        proto.encode(&w, message) catch unreachable;
        ch.queue.items.len += len;
        ch.afterQueue();
    }

    /// Queues encoded messages, such as a `proto.Decoder.Raw`'s bytes.
    pub fn sendRaw(ch: *Channel, bytes: []const u8) void {
        if (ch.state != .open) return;
        ch.queue.appendSlice(ch.gpa, bytes) catch return ch.shut();
        ch.afterQueue();
    }

    /// Bytes sent and not yet written to the socket.
    pub fn queued(ch: *const Channel) usize {
        return ch.queue.items.len + ch.writing.items.len - ch.written;
    }

    /// The peer is behind: past `high_water` bytes are queued.
    pub fn congested(ch: *const Channel) bool {
        return ch.queued() > high_water;
    }

    /// Stops reading. Messages already read are delivered.
    pub fn pauseReading(ch: *Channel) void {
        ch.paused = true;
    }

    pub fn resumeReading(ch: *Channel) void {
        ch.paused = false;
        ch.startRead();
    }

    /// Writes what is queued, then closes. Messages that arrive meanwhile
    /// are dropped. `Handler.closed` follows, and may come before `finish`
    /// returns.
    pub fn finish(ch: *Channel) void {
        if (ch.state != .open) return;
        ch.state = .finishing;
        if (ch.write_active) return;
        ch.shut();
        ch.freeIfDone();
    }

    /// Closes the channel, dropping what is queued. No handler call
    /// follows. The channel is freed, now or once its operations end.
    pub fn close(ch: *Channel) void {
        if (ch.state == .done) return;
        ch.handler = null;
        ch.shut();
        ch.freeIfDone();
    }

    fn afterQueue(ch: *Channel) void {
        if (ch.congested()) ch.was_congested = true;
        if (!ch.write_active) ch.startWrite();
    }

    /// Writes the queue, if a write isn't in flight already.
    fn startWrite(ch: *Channel) void {
        if (ch.written == ch.writing.items.len) {
            if (ch.queue.items.len == 0) return;
            // The written bytes are dropped and the queue moves in.
            ch.writing.clearRetainingCapacity();
            ch.written = 0;
            std.mem.swap(std.ArrayList(u8), &ch.queue, &ch.writing);
        }
        ch.write_active = true;
        ch.socket.write(ch.loop, &ch.write_c, .{ .slice = ch.writing.items[ch.written..] }, Channel, ch, onWrite);
    }

    fn onWrite(ch_: ?*Channel, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.WriteBuffer, result: xev.WriteError!usize) xev.CallbackAction {
        const ch = ch_.?;
        if (result) |n| {
            ch.written += n;
        } else |_| ch.shut();

        // `write_active` stays set through the handler's call, so that a
        // `close` there doesn't free the channel under this callback.
        if (ch.state == .open and ch.was_congested and ch.queued() <= low_water) {
            ch.was_congested = false;
            if (ch.handler) |h| if (h.drained) |drained| drained(h.context, ch);
        }

        // The completion is dead during its callback, and can be reused.
        ch.write_active = false;
        switch (ch.state) {
            .open => ch.startWrite(),
            .finishing => {
                ch.startWrite();
                if (!ch.write_active) ch.shut();
            },
            .closing, .done => {},
        }
        ch.freeIfDone();
        return .disarm;
    }

    fn startRead(ch: *Channel) void {
        if (ch.reading or ch.paused or ch.state != .open) return;
        ch.reading = true;
        ch.socket.read(ch.loop, &ch.read_c, .{ .slice = ch.read_buf }, Channel, ch, onRead);
    }

    fn onRead(ch_: ?*Channel, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.ReadBuffer, result: xev.ReadError!usize) xev.CallbackAction {
        const ch = ch_.?;
        if (result) |n| {
            ch.deliver(ch.read_buf[0..n]);
        } else |_| {
            // End of file, or a failed read: the peer is gone.
            ch.shut();
        }

        if (ch.state == .open and !ch.paused) return .rearm;
        ch.reading = false;
        ch.freeIfDone();
        return .disarm;
    }

    /// Hands each complete message to the handler, until a callback stops
    /// the channel.
    fn deliver(ch: *Channel, bytes: []const u8) void {
        if (ch.state != .open) return;
        ch.decoder.feed(bytes);
        while (ch.state == .open) {
            const raw = ch.decoder.nextRaw() catch return ch.shut();
            const h = ch.handler orelse return;
            h.received(h.context, ch, raw orelse return);
        }
    }

    /// Ends the socket. The read and write in flight end with it.
    fn shut(ch: *Channel) void {
        if (ch.state == .closing or ch.state == .done) return;
        ch.state = .closing;
        _ = std.c.shutdown(ch.socket.fd, posix.SHUT.RDWR);
    }

    /// Frees a closing channel once no operation is in flight, after
    /// telling the handler.
    fn freeIfDone(ch: *Channel) void {
        if (ch.state != .closing or ch.reading or ch.write_active) return;
        ch.state = .done;
        unix.close(ch.socket.fd);
        if (ch.handler) |h| h.closed(h.context, ch);
        ch.decoder.deinit();
        ch.queue.deinit(ch.gpa);
        ch.writing.deinit(ch.gpa);
        ch.gpa.free(ch.read_buf);
        ch.gpa.destroy(ch);
    }
};

const testing = std.testing;

/// Keeps what a channel receives.
const TestEnd = struct {
    received: std.ArrayList(u8) = .empty,
    count: usize = 0,
    drained: usize = 0,
    closed: bool = false,

    fn handler(t: *TestEnd) Handler {
        return .{ .context = t, .received = onReceived, .drained = onDrained, .closed = onClosed };
    }

    fn of(context: *anyopaque) *TestEnd {
        return @ptrCast(@alignCast(context));
    }

    fn onReceived(context: *anyopaque, _: *Channel, raw: proto.Decoder.Raw) void {
        const t = of(context);
        t.count += 1;
        const message = raw.decode() catch @panic("decode");
        t.received.appendSlice(testing.allocator, message.input.bytes) catch @panic("OOM");
    }

    fn onDrained(context: *anyopaque, _: *Channel) void {
        of(context).drained += 1;
    }

    fn onClosed(context: *anyopaque, _: *Channel) void {
        of(context).closed = true;
    }
};

fn runUntil(loop: *xev.Loop, done: *const bool) !void {
    const deadline = Io.Clock.awake.now(testing.io).toMilliseconds() + 10_000;
    while (!done.*) {
        if (Io.Clock.awake.now(testing.io).toMilliseconds() > deadline) return error.Timeout;
        try loop.run(.once);
    }
}

test "messages arrive in order, past a congested queue" {
    unix.ignoreSigpipe();
    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();
    const fds = try unix.pair();

    var a: TestEnd = .{};
    defer a.received.deinit(testing.allocator);
    var b: TestEnd = .{};
    defer b.received.deinit(testing.allocator);
    const ca = try Channel.create(testing.allocator, &loop, fds[0], a.handler());
    _ = try Channel.create(testing.allocator, &loop, fds[1], b.handler());

    // More than the socket buffers and `high_water` hold.
    const chunk: [60_000]u8 = @splat('x');
    for (0..20) |_| ca.send(.{ .input = .{ .bytes = &chunk } });
    try testing.expect(ca.congested());
    const deadline = Io.Clock.awake.now(testing.io).toMilliseconds() + 10_000;
    while (b.count < 20) {
        if (Io.Clock.awake.now(testing.io).toMilliseconds() > deadline) return error.Timeout;
        try loop.run(.once);
    }
    try testing.expectEqual(20 * chunk.len, b.received.items.len);
    try testing.expectEqual(1, a.drained);

    // Finishing closes both ends.
    ca.finish();
    try runUntil(&loop, &b.closed);
    try testing.expect(a.closed);
    try loop.run(.until_done);
}

test "a closed channel stops calling its handler" {
    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();
    const fds = try unix.pair();

    var a: TestEnd = .{};
    var b: TestEnd = .{};
    const ca = try Channel.create(testing.allocator, &loop, fds[0], a.handler());
    _ = try Channel.create(testing.allocator, &loop, fds[1], b.handler());

    // The peer sees end of file.
    ca.send(.{ .input = .{ .bytes = "dropped" } });
    ca.close();
    try runUntil(&loop, &b.closed);
    try testing.expect(!a.closed);
    try loop.run(.until_done);
}

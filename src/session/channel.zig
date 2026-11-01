const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const posix = std.posix;
const xev = @import("xev");
const proto = @import("proto");
const unix = @import("unix.zig");

pub const high_water = 256 << 10;
pub const low_water = 64 << 10;

/// A frame with a larger body closes the channel.
pub const max_message = 1 << 20;

const read_size = 64 << 10;

pub const Handler = struct {
    context: *anyopaque,
    /// raw, and the slices of the message it decodes to, are valid during the
    /// call only.
    received: *const fn (context: *anyopaque, channel: *Channel, raw: proto.Decoder.Raw) void,
    drained: ?*const fn (context: *anyopaque, channel: *Channel) void = null,
    /// The socket is closed and the channel is about to be freed. It isn't
    /// called after close().
    closed: *const fn (context: *anyopaque, channel: *Channel) void,
};

pub const Channel = struct {
    gpa: Allocator,
    loop: *xev.Loop,
    socket: xev.TCP,
    handler: ?Handler,
    decoder: proto.Decoder,
    read_buf: []u8,
    read_c: xev.Completion = .{},
    reading: bool = false,
    paused: bool = false,
    queue: std.ArrayList(u8) = .empty,
    writing: std.ArrayList(u8) = .empty,
    written: usize = 0,
    write_c: xev.Completion = .{},
    write_active: bool = false,
    was_congested: bool = false,
    state: enum {
        open,
        finishing,
        closing,
        done,
    } = .open,

    /// Takes ownership of fd when it succeeds, and starts reading.
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

    /// Queues message. It is dropped unless the channel is open. Running out
    /// of memory closes the channel.
    pub fn send(ch: *Channel, message: proto.Message) void {
        if (ch.state != .open) return;
        const len = proto.encodedLen(message);
        ch.queue.ensureUnusedCapacity(ch.gpa, len) catch return ch.shut();
        var w: Io.Writer = .fixed(ch.queue.unusedCapacitySlice());
        proto.encode(&w, message) catch unreachable;
        ch.queue.items.len += len;
        ch.afterQueue();
    }

    pub fn sendRaw(ch: *Channel, bytes: []const u8) void {
        if (ch.state != .open) return;
        ch.queue.appendSlice(ch.gpa, bytes) catch return ch.shut();
        ch.afterQueue();
    }

    pub fn queued(ch: *const Channel) usize {
        return ch.queue.items.len + ch.writing.items.len - ch.written;
    }

    pub fn congested(ch: *const Channel) bool {
        return ch.queued() > high_water;
    }

    pub fn pauseReading(ch: *Channel) void {
        ch.paused = true;
    }

    pub fn resumeReading(ch: *Channel) void {
        ch.paused = false;
        ch.startRead();
    }

    /// Sends what is queued, then closes. Messages that arrive after are
    /// dropped. closed is called at the end.
    pub fn finish(ch: *Channel) void {
        if (ch.state != .open) return;
        ch.state = .finishing;
        if (ch.write_active) return;
        ch.shut();
        ch.freeIfDone();
    }

    /// Closes now and drops what is queued. The handler is called no more,
    /// closed included.
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

    fn startWrite(ch: *Channel) void {
        if (ch.written == ch.writing.items.len) {
            if (ch.queue.items.len == 0) return;
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

        if (ch.state == .open and ch.was_congested and ch.queued() <= low_water) {
            ch.was_congested = false;
            if (ch.handler) |h| if (h.drained) |drained| drained(h.context, ch);
        }

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
            ch.shut();
        }

        if (ch.state == .open and !ch.paused) return .rearm;
        ch.reading = false;
        ch.freeIfDone();
        return .disarm;
    }

    fn deliver(ch: *Channel, bytes: []const u8) void {
        if (ch.state != .open) return;
        ch.decoder.feed(bytes);

        // The handler may finish or close the channel between messages.
        while (ch.state == .open) {
            const raw = ch.decoder.nextRaw() catch return ch.shut();
            const h = ch.handler orelse return;
            h.received(h.context, ch, raw orelse return);
        }
    }

    /// shutdown makes the read and write in flight end, so their completions
    /// finish. freeIfDone closes the fd after both have.
    fn shut(ch: *Channel) void {
        if (ch.state == .closing or ch.state == .done) return;
        ch.state = .closing;
        _ = std.c.shutdown(ch.socket.fd, posix.SHUT.RDWR);
    }

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

    ca.send(.{ .input = .{ .bytes = "dropped" } });
    ca.close();
    try runUntil(&loop, &b.closed);
    try testing.expect(!a.closed);
    try loop.run(.until_done);
}

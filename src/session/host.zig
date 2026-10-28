//! A session host: a program on a pseudo-terminal and the primary terminal
//! its output feeds.
//!
//! A thread moves bytes between the pty and two queues with poll, as
//! Ghostty's read thread does, so the host works the same on every
//! platform. The caller owns the primary: after `Options.notify`, it calls
//! `processOutput` on its own thread, which logs and applies the queued
//! output.
//!
//! User input and the primary's query replies go to the pty through one
//! queue, in the order they were produced. The primary answers queries only
//! while `answer_queries` is set; while a client is attached, its own
//! terminal answers them.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const posix = std.posix;
const c = std.c;
const term = @import("term");
const Wake = @import("wake").Wake;
const pty_pkg = @import("pty.zig");

const Primary = term.Primary;
const Pty = pty_pkg.Pty;

const log = std.log.scoped(.host);

pub const Options = struct {
    /// See `pty.Options`.
    argv: []const []const u8,
    program: ?[]const u8 = null,
    environ: *const std.process.Environ.Map,
    cwd: std.process.Child.Cwd = .inherit,
    diagnostic: ?*pty_pkg.Diagnostic = null,

    size: term.log.Resize,
    /// The terminal's size comes from `size`.
    terminal: TerminalOptions = .{},

    /// Called on the host's thread when output is queued, at end of file
    /// and when the program exits. It must not call the host.
    notify: *const fn (context: ?*anyopaque) void,
    context: ?*anyopaque = null,
    /// The thread stops reading the pty while this much output is queued.
    output_limit: usize = 256 * 1024,

    pub const TerminalOptions = struct {
        max_scrollback_bytes: ?usize = 10_000_000,
        max_scrollback_lines: ?usize = null,
        kitty_image_storage_limit: usize = 320 * 1000 * 1000,
        log_capacity: usize = 8 * 1024 * 1024,
    };
};

/// The largest output record `processOutput` logs.
const max_record = 16 * 1024;

pub const Host = struct {
    gpa: Allocator,
    io: Io,
    pty: Pty,
    primary: *Primary,
    /// Clear while a client is attached. Queries then reach the client's
    /// terminal in the client stream, and its replies arrive as input.
    answer_queries: bool = true,
    /// Set by `processOutput` once the program has exited and all its
    /// output is processed. Then call `reap`.
    finished: bool = false,
    /// Output taken from `queues.output`, being processed.
    taken: std.ArrayList(u8) = .empty,

    notify: *const fn (context: ?*anyopaque) void,
    context: ?*anyopaque,
    output_limit: usize,
    wake: Wake,
    thread: ?std.Thread = null,
    mutex: Io.Mutex = .init,
    queues: Queues = .{},

    /// Shared with the thread, under `mutex`.
    const Queues = struct {
        /// Read from the pty, not yet taken by `processOutput`.
        output: std.ArrayList(u8) = .empty,
        /// User input and primary replies not yet written to the pty, from
        /// `input_start`. Unbounded: the transport's flow control must stop
        /// reading client input while the program isn't reading.
        input: std.ArrayList(u8) = .empty,
        input_start: usize = 0,
        /// End of file on the pty: every process closed the terminal.
        closed: bool = false,
        /// The program has exited. Set after `closed`, so no output
        /// follows it.
        exited: bool = false,
        stopping: bool = false,
    };

    /// Start the program and the thread. Heap-allocated because the
    /// primary's reply callback and the thread point to the host.
    pub fn create(gpa: Allocator, io: Io, options: Options) !*Host {
        const self = try gpa.create(Host);
        errdefer gpa.destroy(self);

        const t = options.terminal;
        const primary: *Primary = try .create(gpa, io, .{
            .cols = options.size.cols,
            .rows = options.size.rows,
            .max_scrollback_bytes = t.max_scrollback_bytes,
            .max_scrollback_lines = t.max_scrollback_lines,
            .kitty_image_storage_limit = t.kitty_image_storage_limit,
            .log_capacity = t.log_capacity,
        });
        errdefer primary.destroy();
        // The initial size isn't logged, so apply a cell size as a resize
        // to log it.
        if (options.size.cell_size_px != null) try primary.resize(options.size);

        var wake: Wake = try .init();
        errdefer wake.deinit();

        self.* = .{
            .gpa = gpa,
            .io = io,
            .pty = try .spawn(gpa, .{
                .argv = options.argv,
                .program = options.program,
                .environ = options.environ,
                .cwd = options.cwd,
                .size = ptySize(options.size),
                .diagnostic = options.diagnostic,
            }),
            .primary = primary,
            .notify = options.notify,
            .context = options.context,
            .output_limit = options.output_limit,
            .wake = wake,
        };
        errdefer self.pty.deinit();

        // The primary's query replies go to the pty through the input queue.
        primary.context = self;
        primary.handler().effects.write_pty = &writePty;

        self.thread = try std.Thread.spawn(.{}, threadMain, .{self});
        return self;
    }

    /// Kill the program if it is still running and free the host.
    pub fn destroy(self: *Host) void {
        const gpa = self.gpa;
        if (self.thread) |thread| {
            self.mutex.lockUncancelable(self.io);
            self.queues.stopping = true;
            self.mutex.unlock(self.io);

            // Wakes the thread from poll.
            self.wake.notify();

            // The thread may be waiting for the program to exit.
            self.pty.kill(.KILL) catch {};
            thread.join();
        }

        self.pty.deinit();
        self.primary.destroy();
        self.wake.deinit();
        self.taken.deinit(gpa);
        self.queues.output.deinit(gpa);
        self.queues.input.deinit(gpa);
        gpa.destroy(self);
    }

    /// Log and apply the output the thread has queued. Queues any replies.
    /// On error the rest of the taken output is dropped; `finished` is set
    /// either way.
    pub fn processOutput(self: *Host) term.log.AppendError!void {
        // Swap buffers with the thread and process the output without the
        // lock. `exited` is read under the same lock. No output follows it,
        // and all of the program's output is in what was taken.
        self.mutex.lockUncancelable(self.io);
        std.mem.swap(std.ArrayList(u8), &self.queues.output, &self.taken);
        const exited = self.queues.exited;
        self.mutex.unlock(self.io);

        // A full queue stopped the thread reading. It has room again.
        if (self.taken.items.len >= self.output_limit) self.wake.notify();

        self.finished = exited;

        // Logged in records of at most `max_record` bytes.
        defer self.taken.clearRetainingCapacity();
        var rest = self.taken.items;
        while (rest.len > 0) {
            const n = @min(rest.len, max_record);
            try self.primary.output(rest[0..n]);
            rest = rest[n..];
        }
    }

    /// After `finished` is set: ends the thread and reaps the program.
    pub fn reap(self: *Host) pty_pkg.WaitError!pty_pkg.Term {
        // The thread has set `exited` and is ending.
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }

        // The program is a zombie. This doesn't block.
        return self.pty.wait();
    }

    /// Queue input for the pty. Dropped after end of file.
    pub fn sendInput(self: *Host, bytes: []const u8) Allocator.Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const q = &self.queues;
        if (q.closed or bytes.len == 0) return;

        // The thread polls for writability while input is queued. It needs
        // a wakeup when the queue stops being empty.
        const was_empty = q.input_start == q.input.items.len;
        try q.input.appendSlice(self.gpa, bytes);
        if (was_empty) self.wake.notify();
    }

    /// Resize the terminal before the pty, so the program's redraw after
    /// SIGWINCH is logged after the resize.
    pub fn resize(self: *Host, size: term.log.Resize) !void {
        try self.primary.resize(size);
        try self.pty.resize(ptySize(size));
    }

    fn writePty(h: *term.primary.Handler, data: []const u8) void {
        const self: *Host = @ptrCast(@alignCast(Primary.fromHandler(h).context.?));
        if (!self.answer_queries) return;
        // A reply that can't be queued is dropped. To the program this
        // looks like a terminal that didn't answer.
        self.sendInput(data) catch return;
    }

    fn threadMain(self: *Host) void {
        const fd = self.pty.master;
        var buf: [max_record]u8 = undefined;
        while (true) {
            // Decide what to wait for. Reading stops while the output queue
            // is full, which leaves the program blocked on its writes.
            self.mutex.lockUncancelable(self.io);
            const q = &self.queues;
            const stopping = q.stopping;
            const closed = q.closed;
            const want_read = q.output.items.len < self.output_limit;
            const want_write = q.input_start < q.input.items.len;
            self.mutex.unlock(self.io);
            if (stopping) return;

            // After end of file there is nothing left to read or write.
            if (closed) return self.waitExited();

            var events: i16 = 0;
            if (want_read) events |= posix.POLL.IN;
            if (want_write) events |= posix.POLL.OUT;
            // poll ignores a negative fd. A closed slave reports POLLHUP
            // even with no events requested.
            // On macOS, the child's exit is what ends the output (see
            // `Pty.exit_fd`). It is -1 elsewhere, and once seen.
            var fds = [_]posix.pollfd{
                .{ .fd = self.wake.read_fd, .events = posix.POLL.IN, .revents = 0 },
                .{ .fd = if (events == 0) -1 else fd, .events = events, .revents = 0 },
                .{ .fd = if (want_read) self.pty.exit_fd else -1, .events = posix.POLL.IN, .revents = 0 },
            };
            if (c.poll(&fds, fds.len, -1) == -1) switch (posix.errno(-1)) {
                .INTR, .AGAIN => continue,
                else => |err| {
                    log.warn("poll failed: {t}", .{err});
                    return self.close();
                },
            };
            // A wakeup only means the queues changed. The loop's next pass
            // reads them.
            if (fds[0].revents != 0) self.wake.drain();

            // An error or hangup is reported by the read or write itself.
            const revents = fds[1].revents;
            const failed = posix.POLL.ERR | posix.POLL.HUP;
            if (want_write and revents & (posix.POLL.OUT | failed) != 0) self.writeInput();
            if (want_read and (revents & (posix.POLL.IN | failed) != 0 or fds[2].revents != 0)) self.readOutput(&buf);
        }
    }

    /// Reads until the pty would block or `buf` is full.
    fn readOutput(self: *Host, buf: []u8) void {
        // macOS returns at most 1 KiB per read from a pty master. Read until
        // `buf` is full, then take the lock once.
        var len: usize = 0;
        const eof = while (len < buf.len) {
            const n = self.pty.read(buf[len..]) catch |err| switch (err) {
                error.WouldBlock => break false,
                error.SystemResources, error.Unexpected => {
                    log.warn("read failed: {t}", .{err});
                    break true;
                },
            };
            if (n == 0) break true;
            len += n;
        } else false;

        self.mutex.lockUncancelable(self.io);
        const q = &self.queues;
        const was_empty = q.output.items.len == 0;
        q.output.appendSlice(self.gpa, buf[0..len]) catch log.warn("output dropped: out of memory", .{});
        if (eof) q.closed = true;
        self.mutex.unlock(self.io);

        // Notify when output arrives in an empty queue. The caller takes the
        // whole queue, and later appends don't need another notification.
        if (eof or (was_empty and len > 0)) self.notify(self.context);
    }

    /// Writes queued input until the pty would block.
    fn writeInput(self: *Host) void {
        // Held across the writes, which don't block: `sendInput` may move
        // the queue's buffer.
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const q = &self.queues;
        while (q.input_start < q.input.items.len) {
            const n = self.pty.write(q.input.items[q.input_start..]) catch |err| switch (err) {
                // Out of kernel buffers. Retry when the pty is writable.
                error.WouldBlock, error.SystemResources => break,
                // Drop the input. The program's exit shows up as end of
                // file on the next read.
                error.BrokenPipe, error.Unexpected => {
                    q.input_start = q.input.items.len;
                    break;
                },
            };
            q.input_start += n;
        }

        if (q.input_start == q.input.items.len) {
            q.input.clearRetainingCapacity();
            q.input_start = 0;
        } else if (q.input_start > q.input.items.len / 2) {
            // Discard written bytes so the buffer doesn't grow without
            // bound behind a slow reader.
            const rest = q.input.items[q.input_start..];
            std.mem.copyForwards(u8, q.input.items[0..rest.len], rest);
            q.input.shrinkRetainingCapacity(rest.len);
            q.input_start = 0;
        }
    }

    /// Ends reading and writing after poll fails.
    fn close(self: *Host) void {
        self.mutex.lockUncancelable(self.io);
        self.queues.closed = true;
        self.mutex.unlock(self.io);
        self.notify(self.context);
        self.waitExited();
    }

    /// After end of file. A program can close the terminal and keep
    /// running, so this can block for a long time; `destroy` kills it.
    fn waitExited(self: *Host) void {
        self.pty.waitExited() catch |err| log.warn("wait failed: {t}", .{err});

        self.mutex.lockUncancelable(self.io);
        self.queues.exited = true;
        const stopping = self.queues.stopping;
        self.mutex.unlock(self.io);

        // `destroy` killed the program and is joining the thread. The
        // caller may be freeing what `notify` points to.
        if (!stopping) self.notify(self.context);
    }
};

/// Converts the cell size in `size` to the grid's pixel size, which the
/// pty takes.
fn ptySize(size: term.log.Resize) pty_pkg.Size {
    const cell = size.cell_size_px orelse return .{ .cols = size.cols, .rows = size.rows };
    return .{
        .cols = size.cols,
        .rows = size.rows,
        .width_px = std.math.lossyCast(u16, @as(u64, cell.width) * size.cols),
        .height_px = std.math.lossyCast(u16, @as(u64, cell.height) * size.rows),
    };
}

const testing = std.testing;

const test_timeout_ms = 10_000;

fn testEnviron() !std.process.Environ.Map {
    var map: std.process.Environ.Map = .init(testing.allocator);
    errdefer map.deinit();
    try map.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");
    try map.put("TERM", "xterm-256color");
    return map;
}

fn spawnTest(environ: *const std.process.Environ.Map, script: []const u8) !*Host {
    return Host.create(testing.allocator, testing.io, .{
        .argv = &.{ "/bin/sh", "-c", script },
        .environ = environ,
        .size = .{ .cols = 80, .rows = 24 },
        .notify = ignoreNotify,
    });
}

/// The tests poll `processOutput` instead.
fn ignoreNotify(_: ?*anyopaque) void {}

fn now() i64 {
    return std.Io.Clock.awake.now(testing.io).toMilliseconds();
}

/// Process output until `done` returns true or the program has exited,
/// with a deadline.
fn run(host: *Host, done: ?*const fn (*Host) bool) !void {
    const deadline = now() + test_timeout_ms;
    while (true) {
        try host.processOutput();
        if (host.finished) return;
        if (done) |f| if (f(host)) return;
        if (now() > deadline) return error.Timeout;
        try testing.io.sleep(.fromMilliseconds(1), .awake);
    }
}

/// Run until the program exits and reap it.
fn finish(host: *Host) !pty_pkg.Term {
    try run(host, null);
    return host.reap();
}

fn screenText(host: *Host) ![]const u8 {
    return host.primary.terminal.plainString(testing.allocator);
}

fn screenContains(host: *Host, needle: []const u8) bool {
    const text = screenText(host) catch return false;
    defer testing.allocator.free(text);
    return std.mem.indexOf(u8, text, needle) != null;
}

test "output reaches the terminal and the log" {
    var environ = try testEnviron();
    defer environ.deinit();
    const host = try spawnTest(&environ, "printf 'hello \\033[1mbold\\033[m'");
    defer host.destroy();

    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try finish(host));
    try testing.expect(screenContains(host, "hello bold"));

    // The log holds the output unchanged.
    var logged: std.ArrayList(u8) = .empty;
    defer logged.deinit(testing.allocator);
    var it = try host.primary.log.iterator(0);
    while (it.next()) |record| try logged.appendSlice(testing.allocator, record.payload.output);
    try testing.expectEqualStrings("hello \x1b[1mbold\x1b[m", logged.items);
}

test "primary answers queries through the pty" {
    var environ = try testEnviron();
    defer environ.deinit();
    // Ask for the cursor position (DSR 6) and print the 6-byte reply in
    // hex.
    const host = try spawnTest(&environ,
        \\stty -icanon -echo min 1
        \\printf 'ab\033[6n'
        \\reply=$(dd bs=1 count=6 2>/dev/null | od -An -tx1)
        \\printf '\r\nreply:%s\r\n' "$(echo $reply)"
    );
    defer host.destroy();

    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try finish(host));
    // ESC [ 1 ; 3 R
    try testing.expect(screenContains(host, "reply:1b 5b 31 3b 33 52"));
}

test "primary stays silent while answer_queries is clear" {
    var environ = try testEnviron();
    defer environ.deinit();
    // The read gives up after 0.3 s without input.
    const host = try spawnTest(&environ,
        \\stty -icanon -echo min 0 time 3
        \\printf 'ab\033[6n'
        \\reply=$(dd bs=1 count=6 2>/dev/null | od -An -tx1)
        \\printf '\r\nreply:[%s]\r\n' "$(echo $reply)"
    );
    defer host.destroy();
    host.answer_queries = false;

    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try finish(host));
    try testing.expect(screenContains(host, "reply:[]"));
}

test "large input reaches the program intact" {
    var environ = try testEnviron();
    defer environ.deinit();
    // Larger than the tty's input queue, so most of it waits in the
    // host's queue. GNU stty's raw leaves IEXTEN set, and on macOS IEXTEN
    // makes ^V and ^O special even in raw mode.
    const len = 256 * 1024;
    const host = try spawnTest(&environ,
        \\stty raw -echo -iexten
        \\printf 'ready\r\n'
        \\head -c 262144 | cksum
    );
    defer host.destroy();

    try run(host, struct {
        fn f(h: *Host) bool {
            return screenContains(h, "ready");
        }
    }.f);
    const input = try testing.allocator.alloc(u8, len);
    defer testing.allocator.free(input);
    for (input, 0..) |*b, i| b.* = @truncate(i *% 7);
    try host.sendInput(input);
    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try finish(host));

    // POSIX cksum of the input.
    var crc: u32 = 0;
    var table: [256]u32 = undefined;
    for (&table, 0..) |*e, i| {
        var v: u32 = @as(u32, @intCast(i)) << 24;
        for (0..8) |_| v = if (v & 0x80000000 != 0) (v << 1) ^ 0x04c11db7 else v << 1;
        e.* = v;
    }
    for (input) |b| crc = (crc << 8) ^ table[(crc >> 24) ^ b];
    var n: usize = len;
    while (n != 0) : (n >>= 8) crc = (crc << 8) ^ table[(crc >> 24) ^ @as(u8, @truncate(n))];
    var want: [32]u8 = undefined;
    try testing.expect(screenContains(host, try std.fmt.bufPrint(&want, "{d} {d}", .{ ~crc, len })));
}

test "a terminal fed the log ends in the primary's state" {
    var environ = try testEnviron();
    defer environ.deinit();
    // Scrollback, the alternate screen, a read, a resize and a return to
    // the primary screen.
    const host = try spawnTest(&environ,
        \\i=0
        \\while [ $i -lt 60 ]; do printf '\033[3%dmline %d\033[m\r\n' $((i % 8)) $i; i=$((i + 1)); done
        \\printf '\033]2;a title\007\033[?1049h\033[2J\033[Hon the alternate screen\r\n'
        \\printf 'waiting\r\n'
        \\read -r answer
        \\printf '\033[?1049lback on the primary screen\r\n'
        \\printf 'got %s, size %s\r\n' "$answer" "$(stty size)"
    );
    defer host.destroy();

    try run(host, struct {
        fn f(h: *Host) bool {
            return screenContains(h, "waiting");
        }
    }.f);
    try host.resize(.{ .cols = 100, .rows = 30, .cell_size_px = .{ .width = 9, .height = 18 } });
    try host.sendInput("yes\r");
    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try finish(host));
    try testing.expect(screenContains(host, "got yes, size 30 100"));
    try testing.expect(screenContains(host, "back on the primary screen"));

    // A second Primary with no effect callbacks stands in for the client's
    // terminal.
    const stand_in: *Primary = try .create(testing.allocator, testing.io, .{ .cols = 80, .rows = 24 });
    defer stand_in.destroy();
    var it = try host.primary.log.iterator(0);
    while (it.next()) |record| switch (record.payload) {
        .output => |bytes| try stand_in.output(bytes),
        .resize => |size| try stand_in.resize(size),
    };

    const want = try term.state.dumpAlloc(testing.allocator, &host.primary.terminal);
    defer testing.allocator.free(want);
    const got = try term.state.dumpAlloc(testing.allocator, &stand_in.terminal);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

test "a program that closes its terminal is reaped when it exits" {
    var environ = try testEnviron();
    defer environ.deinit();
    // End of file arrives 0.2 s before the exit.
    const host = try spawnTest(&environ,
        \\printf 'closing\r\n'
        \\exec </dev/null >/dev/null 2>&1
        \\sleep 0.2
        \\exit 3
    );
    defer host.destroy();

    try testing.expectEqual(pty_pkg.Term{ .exited = 3 }, try finish(host));
    try testing.expect(screenContains(host, "closing"));
}

test "destroy kills a running program" {
    var environ = try testEnviron();
    defer environ.deinit();
    // One program holds the terminal open, the other has closed it, so
    // the thread is in poll or waiting for the exit.
    for ([_][]const u8{ "exec sleep 30", "exec </dev/null >/dev/null 2>&1; exec sleep 30" }) |script| {
        const host = try spawnTest(&environ, script);
        try testing.io.sleep(.fromMilliseconds(50), .awake);
        const start = now();
        host.destroy();
        try testing.expect(now() - start < 5000);
    }
}

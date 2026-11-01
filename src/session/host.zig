//! Host runs a program on a pty and feeds its output into a term Primary. A
//! thread of its own reads and writes the pty master, and trades output and
//! input with the loop thread through queues under a mutex. It calls notify,
//! and the owner then calls processOutput on the loop thread, which owns the
//! Primary.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const posix = std.posix;
const c = std.c;
const term = @import("term");
const proto = @import("proto");
const Wake = @import("wake").Wake;
const pty_pkg = @import("pty.zig");

const Primary = term.Primary;
const Pty = pty_pkg.Pty;

const log = std.log.scoped(.host);

pub const Options = struct {
    argv: []const []const u8,
    program: ?[]const u8 = null,
    environ: *const std.process.Environ.Map,
    cwd: std.process.Child.Cwd = .inherit,
    diagnostic: ?*pty_pkg.Diagnostic = null,

    size: term.log.Resize,
    terminal: TerminalOptions = .{},

    /// Called on the host thread when output is waiting, the pty has closed,
    /// or the program has exited.
    notify: *const fn (context: ?*anyopaque) void,
    context: ?*anyopaque = null,
    output_limit: usize = 256 * 1024,

    pub const TerminalOptions = struct {
        max_scrollback_bytes: ?usize = 10_000_000,
        max_scrollback_lines: ?usize = null,
        kitty_image_storage_limit: usize = 320 * 1000 * 1000,
        log_capacity: usize = 8 * 1024 * 1024,
    };
};

// The largest read from the pty and the largest log record. An Output frame
// carries one record and must decode under max_message (1 MiB) in the channel
// and the client.
const max_record = 16 * 1024;

pub const Host = struct {
    gpa: Allocator,
    io: Io,
    pty: Pty,
    primary: *Primary,
    /// Whether the Primary answers the program's queries through the pty.
    /// Session clears it while a client is attached; that client's terminal
    /// sees the same output and answers.
    answer_queries: bool = true,
    dark: ?bool = null,
    finished: bool = false,
    taken: std.ArrayList(u8) = .empty,

    notify: *const fn (context: ?*anyopaque) void,
    context: ?*anyopaque,
    output_limit: usize,
    wake: Wake,
    thread: ?std.Thread = null,
    mutex: Io.Mutex = .init,
    queues: Queues = .{},

    const Queues = struct {
        output: std.ArrayList(u8) = .empty,
        input: std.ArrayList(u8) = .empty,
        input_start: usize = 0,
        closed: bool = false,
        exited: bool = false,
        stopping: bool = false,
    };

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
        // Primary.create takes no cell size; the resize sets it.
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

        primary.context = self;
        primary.handler().effects.write_pty = &writePty;
        primary.handler().effects.color_scheme = &colorScheme;

        self.thread = try std.Thread.spawn(.{}, threadMain, .{self});
        return self;
    }

    pub fn destroy(self: *Host) void {
        const gpa = self.gpa;
        if (self.thread) |thread| {
            self.mutex.lockUncancelable(self.io);
            self.queues.stopping = true;
            self.mutex.unlock(self.io);

            self.wake.notify();

            // The thread may be blocked in waitExited until the program exits.
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

    pub fn processOutput(self: *Host) term.log.AppendError!void {
        self.mutex.lockUncancelable(self.io);
        std.mem.swap(std.ArrayList(u8), &self.queues.output, &self.taken);
        const exited = self.queues.exited;
        self.mutex.unlock(self.io);

        // The host thread stopped reading at output_limit. Waking it makes it
        // poll the pty again.
        if (self.taken.items.len >= self.output_limit) self.wake.notify();

        // exited is set after the last output was queued, so this batch holds
        // the rest of it.
        self.finished = exited;

        defer self.taken.clearRetainingCapacity();
        var rest = self.taken.items;
        while (rest.len > 0) {
            const n = @min(rest.len, max_record);
            try self.primary.output(rest[0..n]);
            rest = rest[n..];
        }
    }

    /// Joins the host thread and reaps the program. It blocks until the
    /// program exits; the owner calls it once finished is set.
    pub fn reap(self: *Host) pty_pkg.WaitError!pty_pkg.Term {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }

        return self.pty.wait();
    }

    pub fn sendInput(self: *Host, bytes: []const u8) Allocator.Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const q = &self.queues;
        if (q.closed or bytes.len == 0) return;

        // The thread polls for POLLOUT while input is pending.
        const was_empty = q.input_start == q.input.items.len;
        try q.input.appendSlice(self.gpa, bytes);
        if (was_empty) self.wake.notify();
    }

    pub fn resize(self: *Host, size: term.log.Resize) !void {
        try self.primary.resize(size);
        try self.pty.resize(ptySize(size));
    }

    pub fn setColors(self: *Host, m: proto.Attach) void {
        const colors = &self.primary.terminal.colors;
        if (m.foreground) |rgb| colors.foreground.default = toRgb(rgb);
        if (m.background) |rgb| colors.background.default = toRgb(rgb);
        if (m.dark) |dark| self.dark = dark;

        const entries = m.palette orelse return;
        var palette = colors.palette.original.*;
        var i: usize = 0;
        while (i + 4 <= entries.len) : (i += 4) {
            if (entries[i] >= 16) continue;
            palette[entries[i]] = .{ .r = entries[i + 1], .g = entries[i + 2], .b = entries[i + 3] };
        }
        colors.palette.changeDefault(self.primary.gpa, palette) catch log.warn("palette dropped: out of memory", .{});
    }

    fn toRgb(rgb: u32) term.vt.color.RGB {
        return .{ .r = @truncate(rgb >> 16), .g = @truncate(rgb >> 8), .b = @truncate(rgb) };
    }

    fn colorScheme(h: *term.primary.Handler) ?term.vt.device_status.ColorScheme {
        const self: *Host = @ptrCast(@alignCast(Primary.fromHandler(h).context.?));
        const dark = self.dark orelse return null;
        return if (dark) .dark else .light;
    }

    fn writePty(h: *term.primary.Handler, data: []const u8) void {
        const self: *Host = @ptrCast(@alignCast(Primary.fromHandler(h).context.?));
        if (!self.answer_queries) return;
        self.sendInput(data) catch return;
    }

    fn threadMain(self: *Host) void {
        const fd = self.pty.master;
        var buf: [max_record]u8 = undefined;
        while (true) {
            self.mutex.lockUncancelable(self.io);
            const q = &self.queues;
            const stopping = q.stopping;
            const closed = q.closed;
            const want_read = q.output.items.len < self.output_limit;
            const want_write = q.input_start < q.input.items.len;
            self.mutex.unlock(self.io);
            if (stopping) return;

            if (closed) return self.waitExited();

            var events: i16 = 0;
            if (want_read) events |= posix.POLL.IN;
            if (want_write) events |= posix.POLL.OUT;
            // poll skips an fd of -1. exit_fd is -1 except on Darwin, where the
            // held slave keeps the master from reaching end of file until the
            // program's exit is seen.
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
            if (fds[0].revents != 0) self.wake.drain();

            const revents = fds[1].revents;
            const failed = posix.POLL.ERR | posix.POLL.HUP;
            if (want_write and revents & (posix.POLL.OUT | failed) != 0) self.writeInput();
            if (want_read and (revents & (posix.POLL.IN | failed) != 0 or fds[2].revents != 0)) self.readOutput(&buf);
        }
    }

    fn readOutput(self: *Host, buf: []u8) void {
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

        // processOutput takes the whole queue, so a notification is due when
        // the queue was empty, and at end of file.
        if (eof or (was_empty and len > 0)) self.notify(self.context);
    }

    fn writeInput(self: *Host) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const q = &self.queues;
        while (q.input_start < q.input.items.len) {
            const n = self.pty.write(q.input.items[q.input_start..]) catch |err| switch (err) {
                error.WouldBlock, error.SystemResources => break,
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
            const rest = q.input.items[q.input_start..];
            std.mem.copyForwards(u8, q.input.items[0..rest.len], rest);
            q.input.shrinkRetainingCapacity(rest.len);
            q.input_start = 0;
        }
    }

    fn close(self: *Host) void {
        self.mutex.lockUncancelable(self.io);
        self.queues.closed = true;
        self.mutex.unlock(self.io);
        self.notify(self.context);
        self.waitExited();
    }

    fn waitExited(self: *Host) void {
        self.pty.waitExited() catch |err| log.warn("wait failed: {t}", .{err});

        self.mutex.lockUncancelable(self.io);
        self.queues.exited = true;
        const stopping = self.queues.stopping;
        self.mutex.unlock(self.io);

        // While stopping, destroy is joining this thread and the owner takes
        // no notification.
        if (!stopping) self.notify(self.context);
    }
};

/// The window's pixel size from the cell size. winsize's pixel fields are u16,
/// and larger sizes saturate.
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

fn ignoreNotify(_: ?*anyopaque) void {}

fn now() i64 {
    return std.Io.Clock.awake.now(testing.io).toMilliseconds();
}

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

    var logged: std.ArrayList(u8) = .empty;
    defer logged.deinit(testing.allocator);
    var it = try host.primary.log.iterator(0);
    while (it.next()) |record| try logged.appendSlice(testing.allocator, record.payload.output);
    try testing.expectEqualStrings("hello \x1b[1mbold\x1b[m", logged.items);
}

test "primary answers queries through the pty" {
    var environ = try testEnviron();
    defer environ.deinit();
    const host = try spawnTest(&environ,
        \\stty -icanon -echo min 1
        \\printf 'ab\033[6n'
        \\reply=$(dd bs=1 count=6 2>/dev/null | od -An -tx1)
        \\printf '\r\nreply:%s\r\n' "$(echo $reply)"
    );
    defer host.destroy();

    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try finish(host));
    try testing.expect(screenContains(host, "reply:1b 5b 31 3b 33 52"));
}

test "with no client attached, the primary answers with the last client's colors" {
    var environ = try testEnviron();
    defer environ.deinit();
    const host = try spawnTest(&environ,
        \\stty -icanon -echo min 0 time 10
        \\sleep 0.2
        \\printf '\033]11;?\033\\\033]4;1;?\033\\\033[?996n'
        \\reply=$(dd bs=1 count=128 2>/dev/null | tr '\033' E)
        \\printf '\r\nreply:[%s]\r\n' "$reply"
    );
    defer host.destroy();
    host.setColors(.{ .background = 0x102030, .palette = &.{ 1, 0xaa, 0xbb, 0xcc }, .dark = true });

    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try finish(host));
    const text = try screenText(host);
    defer testing.allocator.free(text);
    for ([_][]const u8{ "11;rgb:1010/2020/3030", "4;1;rgb:aaaa/bbbb/cccc", "[?997;1n" }) |want| {
        if (std.mem.indexOf(u8, text, want) == null) {
            std.debug.print("screen: {s}\n", .{text});
            return error.TestUnexpectedResult;
        }
    }
}

test "primary stays silent while answer_queries is clear" {
    var environ = try testEnviron();
    defer environ.deinit();
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
    for ([_][]const u8{ "exec sleep 30", "exec </dev/null >/dev/null 2>&1; exec sleep 30" }) |script| {
        const host = try spawnTest(&environ, script);
        try testing.io.sleep(.fromMilliseconds(50), .awake);
        const start = now();
        host.destroy();
        try testing.expect(now() - start < 5000);
    }
}

//! A session host: a program on a pseudo-terminal and the primary terminal
//! its output feeds.
//!
//! Output read from the pty is logged and applied by the `Primary`. User
//! input and the primary's query replies go to the pty through one queue, in
//! the order they were produced.
//!
//! The caller runs the event loop. It polls `fd` for reading, and for
//! writing while `wantsWrite`, and calls `readOutput` and `flushInput`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const term = @import("term");
const pty_pkg = @import("pty.zig");

const Primary = term.Primary;
const Pty = pty_pkg.Pty;

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

    pub const TerminalOptions = struct {
        max_scrollback_bytes: ?usize = 10_000_000,
        max_scrollback_lines: ?usize = null,
        kitty_image_storage_limit: usize = 320 * 1000 * 1000,
        log_capacity: usize = 8 * 1024 * 1024,
        continuation_max_bytes: usize = 1024 * 1024,
    };
};

pub const ReadError = pty_pkg.ReadError || term.log.AppendError;

pub const Host = struct {
    gpa: Allocator,
    pty: Pty,
    primary: *Primary,
    /// User input and primary replies not yet written to the pty, from
    /// `input_start`. Unbounded: the transport's flow control must stop
    /// reading client input while the program isn't reading.
    input: std.ArrayList(u8) = .empty,
    input_start: usize = 0,

    /// Start the program. Heap-allocated because the primary's reply
    /// callback points to the host.
    pub fn create(gpa: Allocator, io: std.Io, options: Options) !*Host {
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
            .continuation_max_bytes = t.continuation_max_bytes,
        });
        errdefer primary.destroy();
        // The initial size isn't logged, so apply a cell size as a resize
        // to log it.
        if (options.size.cell_size_px != null) try primary.resize(options.size);

        self.* = .{
            .gpa = gpa,
            .pty = try .spawn(gpa, .{
                .argv = options.argv,
                .program = options.program,
                .environ = options.environ,
                .cwd = options.cwd,
                .size = ptySize(options.size),
                .diagnostic = options.diagnostic,
            }),
            .primary = primary,
        };
        primary.context = self;
        primary.handler().effects.write_pty = &writePty;
        return self;
    }

    /// Kill the program if it is still running and free the host. Call
    /// `pty.hangup` and `pty.wait` first for a clean exit.
    pub fn destroy(self: *Host) void {
        const gpa = self.gpa;
        self.pty.deinit();
        self.primary.destroy();
        self.input.deinit(gpa);
        gpa.destroy(self);
    }

    pub fn fd(self: *const Host) std.posix.fd_t {
        return self.pty.master;
    }

    /// Read up to `buf.len` bytes of output and feed them to the primary.
    /// Returns the number read, 0 at end of file. Queues any replies; call
    /// `flushInput` afterwards.
    pub fn readOutput(self: *Host, buf: []u8) ReadError!usize {
        const n = try self.pty.read(buf);
        if (n > 0) try self.primary.output(buf[0..n]);
        return n;
    }

    /// Queue input and write as much as the pty accepts.
    pub fn sendInput(self: *Host, bytes: []const u8) Allocator.Error!void {
        try self.input.appendSlice(self.gpa, bytes);
        self.flushInput();
    }

    /// Whether queued input is waiting for the pty to become writable.
    pub fn wantsWrite(self: *const Host) bool {
        return self.input_start < self.input.items.len;
    }

    /// Write queued input until the pty would block.
    pub fn flushInput(self: *Host) void {
        while (self.wantsWrite()) {
            const n = self.pty.write(self.input.items[self.input_start..]) catch |err| switch (err) {
                // Out of kernel buffers. Retry when the pty is writable.
                error.WouldBlock, error.SystemResources => break,
                // Drop the input. The program's exit shows up as end of
                // file on the next read.
                error.BrokenPipe, error.Unexpected => {
                    self.input_start = self.input.items.len;
                    break;
                },
            };
            self.input_start += n;
        }
        if (self.input_start == self.input.items.len) {
            self.input.clearRetainingCapacity();
            self.input_start = 0;
        } else if (self.input_start > self.input.items.len / 2) {
            // Discard written bytes so the buffer doesn't grow without
            // bound behind a slow reader.
            const rest = self.input.items[self.input_start..];
            std.mem.copyForwards(u8, self.input.items[0..rest.len], rest);
            self.input.shrinkRetainingCapacity(rest.len);
            self.input_start = 0;
        }
    }

    /// Resize the terminal before the pty, so the program's redraw after
    /// SIGWINCH is logged after the resize.
    pub fn resize(self: *Host, size: term.log.Resize) !void {
        try self.primary.resize(size);
        try self.pty.resize(ptySize(size));
    }

    fn writePty(h: *term.primary.Handler, data: []const u8) void {
        const self: *Host = @ptrCast(@alignCast(Primary.fromHandler(h).context.?));
        // A reply that can't be queued is dropped. To the program this
        // looks like a terminal that didn't answer.
        self.input.appendSlice(self.gpa, data) catch return;
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
    });
}

/// Drive the host until `done` returns true or end of file, with a
/// deadline.
fn run(host: *Host, done: ?*const fn (*Host) bool) !void {
    const io = testing.io;
    const deadline = std.Io.Clock.awake.now(io).toMilliseconds() + test_timeout_ms;
    var buf: [4096]u8 = undefined;
    while (done == null or !done.?(host)) {
        const remaining = deadline - std.Io.Clock.awake.now(io).toMilliseconds();
        if (remaining <= 0) return error.Timeout;
        var events: i16 = std.posix.POLL.IN;
        if (host.wantsWrite()) events |= std.posix.POLL.OUT;
        var fds = [_]std.posix.pollfd{.{ .fd = host.fd(), .events = events, .revents = 0 }};
        _ = std.c.poll(&fds, fds.len, @intCast(remaining));
        if (host.wantsWrite()) host.flushInput();
        const n = host.readOutput(&buf) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => |e| return e,
        };
        if (n == 0) return;
        host.flushInput();
    }
}

fn waitTest(host: *Host) !pty_pkg.Term {
    const io = testing.io;
    const deadline = std.Io.Clock.awake.now(io).toMilliseconds() + test_timeout_ms;
    while (std.Io.Clock.awake.now(io).toMilliseconds() < deadline) {
        if (try host.pty.tryWait()) |t| return t;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    return error.Timeout;
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

    try run(host, null);
    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try waitTest(host));
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

    try run(host, null);
    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try waitTest(host));
    // ESC [ 1 ; 3 R
    try testing.expect(screenContains(host, "reply:1b 5b 31 3b 33 52"));
}

test "large input reaches the program intact" {
    var environ = try testEnviron();
    defer environ.deinit();
    // Larger than the tty's input queue, so most of it waits in the
    // host's queue.
    const len = 256 * 1024;
    const host = try spawnTest(&environ,
        \\stty raw -echo
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
    try run(host, null);
    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try waitTest(host));

    // POSIX cksum of the input.
    var crc: u32 = 0;
    var table: [256]u32 = undefined;
    for (&table, 0..) |*e, i| {
        var c: u32 = @as(u32, @intCast(i)) << 24;
        for (0..8) |_| c = if (c & 0x80000000 != 0) (c << 1) ^ 0x04c11db7 else c << 1;
        e.* = c;
    }
    for (input) |b| crc = (crc << 8) ^ table[(crc >> 24) ^ b];
    var n: usize = len;
    while (n != 0) : (n >>= 8) crc = (crc << 8) ^ table[(crc >> 24) ^ @as(u8, @truncate(n))];
    var want: [32]u8 = undefined;
    try testing.expect(screenContains(host, try std.fmt.bufPrint(&want, "{d} {d}", .{ ~crc, len })));
}

test "replica attached mid-session ends in the primary's state" {
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

    // Snapshot here, then apply the records logged after it.
    var snapshot: std.Io.Writer.Allocating = .init(testing.allocator);
    defer snapshot.deinit();
    const seq = try host.primary.snapshot(testing.allocator, &snapshot.writer);
    var reader: std.Io.Reader = .fixed(snapshot.written());
    const replica: *term.Replica = try .restore(testing.allocator, testing.io, &reader, seq, .{});
    defer replica.destroy();

    try host.resize(.{ .cols = 100, .rows = 30, .cell_size_px = .{ .width = 9, .height = 18 } });
    try host.sendInput("yes\r");
    try run(host, null);
    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try waitTest(host));
    try testing.expect(screenContains(host, "got yes, size 30 100"));
    try testing.expect(screenContains(host, "back on the primary screen"));

    var it = try host.primary.log.iterator(seq);
    while (it.next()) |record| try replica.apply(record);

    const want = try term.state.dumpAlloc(testing.allocator, &host.primary.terminal);
    defer testing.allocator.free(want);
    const got = try term.state.dumpAlloc(testing.allocator, &replica.terminal);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

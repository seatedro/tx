//! A session host: one program on a pseudo-terminal, and the authoritative
//! terminal fed everything it writes.
//!
//! The host is the only place the program's output enters tx. Each read
//! from the pty goes to the `Authority`, which logs it and applies it, so
//! mirrors attached at any point can catch up from a snapshot and the log.
//! It is also the only place the program's input leaves: the user's input
//! and the authority's replies to queries share one queue to the pty, in
//! the order they were produced.
//!
//! The host doesn't own an event loop. The caller polls `fd` for reading,
//! and for writing while `wantsWrite`, and calls `readOutput` and
//! `flushInput` when it is ready.
const std = @import("std");
const Allocator = std.mem.Allocator;
const term = @import("term");
const pty_pkg = @import("pty.zig");

const Authority = term.Authority;
const Pty = pty_pkg.Pty;

pub const Options = struct {
    /// See `pty.Options`.
    argv: []const []const u8,
    program: ?[]const u8 = null,
    environ: *const std.process.Environ.Map,
    cwd: std.process.Child.Cwd = .inherit,
    diagnostic: ?*pty_pkg.Diagnostic = null,

    size: term.log.Resize,
    /// Everything but the size, which comes from `size`.
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
    authority: *Authority,
    /// Bytes for the program that the pty hasn't taken yet: the user's
    /// input and the authority's replies. `input_start` is how much of
    /// `input` has been written. Nothing bounds it here; the transport's
    /// flow control has to stop reading input from a client while the
    /// program isn't reading it.
    input: std.ArrayList(u8) = .empty,
    input_start: usize = 0,

    /// Start the program. The host is heap-allocated because the
    /// authority's reply callback points back at it.
    pub fn create(gpa: Allocator, io: std.Io, options: Options) !*Host {
        const self = try gpa.create(Host);
        errdefer gpa.destroy(self);

        const t = options.terminal;
        const authority: *Authority = try .create(gpa, io, .{
            .cols = options.size.cols,
            .rows = options.size.rows,
            .max_scrollback_bytes = t.max_scrollback_bytes,
            .max_scrollback_lines = t.max_scrollback_lines,
            .kitty_image_storage_limit = t.kitty_image_storage_limit,
            .log_capacity = t.log_capacity,
            .continuation_max_bytes = t.continuation_max_bytes,
        });
        errdefer authority.destroy();
        // The size the terminal starts with isn't a record, so a cell size
        // has to be applied (and logged) like any later resize.
        if (options.size.cell_size_px != null) try authority.resize(options.size);

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
            .authority = authority,
        };
        authority.context = self;
        authority.handler().effects.write_pty = &writePty;
        return self;
    }

    /// Kill the program if it is still running, and free everything. Use
    /// `pty.hangup` and `pty.wait` first to let it exit cleanly.
    pub fn destroy(self: *Host) void {
        const gpa = self.gpa;
        self.pty.deinit();
        self.authority.destroy();
        self.input.deinit(gpa);
        gpa.destroy(self);
    }

    /// The pty master, to poll.
    pub fn fd(self: *const Host) std.posix.fd_t {
        return self.pty.master;
    }

    /// Read what the program wrote, at most `buf.len` bytes, and feed it
    /// to the authority. Returns the number of bytes read, 0 at end of
    /// file. Replies the output asked for are queued; flush them.
    pub fn readOutput(self: *Host, buf: []u8) ReadError!usize {
        const n = try self.pty.read(buf);
        if (n > 0) try self.authority.output(buf[0..n]);
        return n;
    }

    /// Queue input for the program and write as much as it takes now.
    pub fn sendInput(self: *Host, bytes: []const u8) Allocator.Error!void {
        try self.input.appendSlice(self.gpa, bytes);
        self.flushInput();
    }

    /// Whether queued input is waiting for the pty to become writable.
    pub fn wantsWrite(self: *const Host) bool {
        return self.input_start < self.input.items.len;
    }

    /// Write queued input until the pty stops taking it.
    pub fn flushInput(self: *Host) void {
        while (self.wantsWrite()) {
            const n = self.pty.write(self.input.items[self.input_start..]) catch |err| switch (err) {
                // Out of kernel buffers: like a full queue, try again
                // when the pty is writable.
                error.WouldBlock, error.SystemResources => break,
                // Nothing will read it any more. The program's exit shows
                // up as end of file on the next read.
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
            // Drop the written half so a slow reader doesn't keep the
            // whole history of its input alive.
            const rest = self.input.items[self.input_start..];
            std.mem.copyForwards(u8, self.input.items[0..rest.len], rest);
            self.input.shrinkRetainingCapacity(rest.len);
            self.input_start = 0;
        }
    }

    /// Resize the terminal, then the pty. In that order, the program's
    /// redraw after SIGWINCH is output the log records after the resize,
    /// so mirrors see it at the same size the authority did.
    pub fn resize(self: *Host, size: term.log.Resize) !void {
        try self.authority.resize(size);
        try self.pty.resize(ptySize(size));
    }

    fn writePty(h: *term.authority.Handler, data: []const u8) void {
        const self: *Host = @ptrCast(@alignCast(Authority.fromHandler(h).context.?));
        // A reply that can't be queued is lost, like one the program
        // never read. The program sees the same as from a slow terminal.
        self.input.appendSlice(self.gpa, data) catch return;
    }
};

/// The pty takes the pixel size of the whole grid; the terminal takes one
/// cell's.
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

/// Long enough for a loaded machine, short enough that a hung test fails.
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

/// Drive the host like an event loop would, until `done` or end of file.
/// Fails instead of hanging when neither comes.
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
    return host.authority.terminal.plainString(testing.allocator);
}

fn screenContains(host: *Host, needle: []const u8) bool {
    const text = screenText(host) catch return false;
    defer testing.allocator.free(text);
    return std.mem.indexOf(u8, text, needle) != null;
}

test "the program's output reaches the terminal and the log" {
    var environ = try testEnviron();
    defer environ.deinit();
    const host = try spawnTest(&environ, "printf 'hello \\033[1mbold\\033[m'");
    defer host.destroy();

    try run(host, null);
    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try waitTest(host));
    try testing.expect(screenContains(host, "hello bold"));

    // The log holds exactly what the terminal consumed.
    var logged: std.ArrayList(u8) = .empty;
    defer logged.deinit(testing.allocator);
    var it = try host.authority.log.iterator(0);
    while (it.next()) |record| try logged.appendSlice(testing.allocator, record.payload.output);
    try testing.expectEqualStrings("hello \x1b[1mbold\x1b[m", logged.items);
}

test "the authority answers the program's queries through the pty" {
    var environ = try testEnviron();
    defer environ.deinit();
    // Ask for the cursor position (DSR 6) and print the 6-byte reply in
    // hex. The terminal answers, not the test.
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

test "input reaches the program in order, however much it is" {
    var environ = try testEnviron();
    defer environ.deinit();
    // Far more than the tty's input queue holds, so most of it waits in
    // the host's queue while the program reads.
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

    // POSIX cksum of the same bytes, to compare with the program's.
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

test "a mirror attached partway through a session ends in the same state" {
    var environ = try testEnviron();
    defer environ.deinit();
    // Some history, the alternate screen, a pause for input, a resize the
    // program reports, and a return to the primary screen.
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

    // Attach: snapshot now, then apply everything logged after it.
    var snapshot: std.Io.Writer.Allocating = .init(testing.allocator);
    defer snapshot.deinit();
    const seq = try host.authority.snapshot(testing.allocator, &snapshot.writer);
    var reader: std.Io.Reader = .fixed(snapshot.written());
    const mirror: *term.Mirror = try .restore(testing.allocator, testing.io, &reader, seq, .{});
    defer mirror.destroy();

    try host.resize(.{ .cols = 100, .rows = 30, .cell_size_px = .{ .width = 9, .height = 18 } });
    try host.sendInput("yes\r");
    try run(host, null);
    try testing.expectEqual(pty_pkg.Term{ .exited = 0 }, try waitTest(host));
    try testing.expect(screenContains(host, "got yes, size 30 100"));
    try testing.expect(screenContains(host, "back on the primary screen"));

    var it = try host.authority.log.iterator(seq);
    while (it.next()) |record| try mirror.apply(record);

    const want = try term.state.dumpAlloc(testing.allocator, &host.authority.terminal);
    defer testing.allocator.free(want);
    const got = try term.state.dumpAlloc(testing.allocator, &mirror.terminal);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

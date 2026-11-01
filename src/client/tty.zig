const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const posix = std.posix;
const c = std.c;
const native_os = builtin.os.tag;
const Wake = @import("wake").Wake;

pub const Size = struct {
    cols: u16,
    rows: u16,
    width_px: u16 = 0,
    height_px: u16 = 0,
};

pub const TerminalError = error{ NotATerminal, Unexpected };

pub fn getSize(fd: posix.fd_t) TerminalError!Size {
    var ws: posix.winsize = undefined;
    if (ioctl(fd, tiocgwinsz, @intFromPtr(&ws)) == -1) return terminalError(posix.errno(-1));
    return .{ .cols = ws.col, .rows = ws.row, .width_px = ws.xpixel, .height_px = ws.ypixel };
}

pub const RawMode = struct {
    fd: posix.fd_t,
    saved: posix.termios,

    pub fn enter(fd: posix.fd_t) TerminalError!RawMode {
        const raw: RawMode = try .save(fd);
        try raw.apply();
        return raw;
    }

    pub fn save(fd: posix.fd_t) TerminalError!RawMode {
        var raw: RawMode = .{ .fd = fd, .saved = undefined };
        try getAttrs(fd, &raw.saved);
        return raw;
    }

    pub fn apply(raw: *const RawMode) TerminalError!void {
        const attrs = makeRaw(raw.saved);
        switch (setAttrs(raw.fd, &attrs)) {
            .SUCCESS => {},
            else => |err| return terminalError(err),
        }
    }

    pub fn restore(raw: *const RawMode) void {
        _ = setAttrs(raw.fd, &raw.saved);
    }
};

pub fn makeRaw(attrs: posix.termios) posix.termios {
    var raw = attrs;

    raw.iflag.IGNPAR = true;
    raw.iflag.ISTRIP = false;
    raw.iflag.INLCR = false;
    raw.iflag.IGNCR = false;
    raw.iflag.ICRNL = false;
    raw.iflag.IXON = false;
    raw.iflag.IXANY = false;
    raw.iflag.IXOFF = false;
    if (@hasField(@TypeOf(raw.iflag), "IUCLC")) raw.iflag.IUCLC = false;

    raw.lflag.ISIG = false;
    raw.lflag.ICANON = false;
    raw.lflag.ECHO = false;
    raw.lflag.ECHOE = false;
    raw.lflag.ECHOK = false;
    raw.lflag.ECHONL = false;
    raw.lflag.IEXTEN = false;

    raw.oflag.OPOST = false;

    raw.cc[@backingInt(posix.V.MIN)] = 1;
    raw.cc[@backingInt(posix.V.TIME)] = 0;

    return raw;
}

pub const handled_signals = [_]posix.SIG{ .WINCH, .HUP, .TERM, .QUIT };

pub fn blockSignals() posix.sigset_t {
    const set = signalSet();
    var old: posix.sigset_t = undefined;
    _ = c.pthread_sigmask(posix.SIG.BLOCK, &set, &old);
    return old;
}

fn signalSet() posix.sigset_t {
    var set = posix.sigemptyset();
    for (handled_signals) |sig| posix.sigaddset(&set, sig);
    return set;
}

fn signalsBlocked() bool {
    const empty = posix.sigemptyset();
    var mask: posix.sigset_t = undefined;
    _ = c.pthread_sigmask(posix.SIG.BLOCK, &empty, &mask);
    for (handled_signals) |sig| {
        if (c.sigismember(&mask, sig) != 1) return false;
    }
    return true;
}

pub const Signals = struct {
    options: Options,
    thread: std.Thread,
    stopping: std.atomic.Value(bool),
    old_winch: posix.Sigaction,

    pub const Event = union(enum) {
        resize: Size,
        terminate: posix.SIG,
    };

    pub const Options = struct {
        fd: posix.fd_t,
        raw_mode: ?*const RawMode = null,
        context: ?*anyopaque = null,
        callback: *const fn (context: ?*anyopaque, event: Event) void,
    };

    pub fn start(s: *Signals, options: Options) std.Thread.SpawnError!void {
        assert(signalsBlocked());
        s.* = .{ .options = options, .thread = undefined, .stopping = .init(false), .old_winch = undefined };

        const action: posix.Sigaction = .{ .handler = .{ .handler = ignore }, .mask = posix.sigemptyset(), .flags = 0 };
        _ = c.sigaction(.WINCH, &action, &s.old_winch);
        errdefer _ = c.sigaction(.WINCH, &s.old_winch, null);

        s.thread = try std.Thread.spawn(.{}, run, .{s});
    }

    pub fn stop(s: *Signals) void {
        s.stopping.store(true, .release);
        _ = c.pthread_kill(s.thread.getHandle(), .WINCH);
        s.thread.join();
        _ = c.sigaction(.WINCH, &s.old_winch, null);
        s.* = undefined;
    }

    fn ignore(_: posix.SIG) callconv(.c) void {}

    fn run(s: *Signals) void {
        var set = signalSet();
        var terminating = false;
        while (true) {
            var signo: c_int = undefined;
            const rc = c.sigwait(&set, &signo);
            assert(rc == 0);

            if (s.stopping.load(.acquire)) return;

            const sig = std.enums.fromInt(posix.SIG, signo).?;
            switch (sig) {
                .WINCH => {
                    const size = getSize(s.options.fd) catch continue;
                    s.options.callback(s.options.context, .{ .resize = size });
                },
                else => {
                    if (s.options.raw_mode) |raw| raw.restore();

                    if (terminating) defaultAction(sig);
                    terminating = true;

                    s.options.callback(s.options.context, .{ .terminate = sig });
                },
            }
        }
    }

    fn defaultAction(sig: posix.SIG) void {
        var action: posix.Sigaction = .{ .handler = .{ .handler = posix.SIG.DFL }, .mask = posix.sigemptyset(), .flags = 0 };
        _ = c.sigaction(sig, &action, null);

        _ = c.raise(sig);
        var set = posix.sigemptyset();
        posix.sigaddset(&set, sig);
        var old: posix.sigset_t = undefined;
        _ = c.pthread_sigmask(posix.SIG.UNBLOCK, &set, &old);
    }
};

pub const StartError = std.Thread.SpawnError || error{
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
};

pub const Reader = struct {
    options: Options,
    wake: Wake,
    thread: std.Thread,
    buf: [16 * 1024]u8,

    pub const Event = union(enum) {
        data: []const u8,
        end_of_file,
        failed: ReadError,
    };

    pub const ReadError = error{ InputOutput, SystemResources, Unexpected };

    pub const Options = struct {
        fd: posix.fd_t,
        context: ?*anyopaque = null,
        callback: *const fn (context: ?*anyopaque, event: Event) void,
    };

    pub fn start(r: *Reader, options: Options) StartError!void {
        r.* = .{ .options = options, .wake = try .init(), .thread = undefined, .buf = undefined };
        errdefer r.wake.deinit();
        r.thread = try std.Thread.spawn(.{}, run, .{r});
    }

    pub fn stop(r: *Reader) void {
        r.wake.notify();
        r.thread.join();
        r.wake.deinit();
        r.* = undefined;
    }

    fn run(r: *Reader) void {
        const fd = r.options.fd;

        var poll_fd = true;

        while (true) {
            if (poll_fd) switch (waitFor(fd, posix.POLL.IN, r.wake.read_fd)) {
                .ready => {},
                .woken => return,
                .unsupported => poll_fd = false,
            };

            const rc = c.read(fd, &r.buf, r.buf.len);
            const err: ReadError = switch (posix.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return r.options.callback(r.options.context, .end_of_file);
                    r.options.callback(r.options.context, .{ .data = r.buf[0..@intCast(rc)] });
                    continue;
                },
                .INTR, .AGAIN => continue,
                .IO => error.InputOutput,
                .NOMEM, .NOBUFS => error.SystemResources,
                else => |e| posix.unexpectedErrno(e),
            };
            return r.options.callback(r.options.context, .{ .failed = err });
        }
    }
};

pub const Writer = struct {
    gpa: Allocator,
    io: Io,
    options: Options,
    wake: Wake,
    thread: std.Thread,

    mutex: Io.Mutex,
    buf: []u8,
    head: usize,
    len: usize,
    above_high_water: bool,
    failed: bool,
    stopping: ?StopMode,

    pub const Event = union(enum) {
        above_high_water,
        below_low_water,
        failed: WriteError,
    };

    pub const WriteError = error{
        InputOutput,
        BrokenPipe,
        NoSpaceLeft,
        Unexpected,
    };

    pub const Options = struct {
        fd: posix.fd_t,
        capacity: usize = 8 * 1024 * 1024,
        high_water: usize = 1024 * 1024,
        low_water: usize = 256 * 1024,
        context: ?*anyopaque = null,
        callback: *const fn (context: ?*anyopaque, event: Event) void,
    };

    pub const StopMode = enum {
        drain,
        discard,
    };

    const max_write = 16 * 1024;

    pub fn start(w: *Writer, gpa: Allocator, io: Io, options: Options) (StartError || Allocator.Error)!void {
        assert(options.low_water <= options.high_water);
        assert(options.high_water < options.capacity);

        const buf = try gpa.alloc(u8, options.capacity);
        errdefer gpa.free(buf);
        w.* = .{
            .gpa = gpa,
            .io = io,
            .options = options,
            .wake = try .init(),
            .thread = undefined,
            .mutex = .init,
            .buf = buf,
            .head = 0,
            .len = 0,
            .above_high_water = false,
            .failed = false,
            .stopping = null,
        };
        errdefer w.wake.deinit();
        w.thread = try std.Thread.spawn(.{}, run, .{w});
    }

    pub fn stop(w: *Writer, mode: StopMode) void {
        w.mutex.lockUncancelable(w.io);
        w.stopping = mode;
        w.mutex.unlock(w.io);

        w.wake.notify();
        w.thread.join();
        w.wake.deinit();
        w.gpa.free(w.buf);
        w.* = undefined;
    }

    pub fn write(w: *Writer, bytes: []const u8) error{ QueueFull, Failed }!void {
        w.mutex.lockUncancelable(w.io);
        defer w.mutex.unlock(w.io);
        assert(w.stopping == null);
        if (w.failed) return error.Failed;
        if (bytes.len > w.buf.len - w.len) return error.QueueFull;
        if (bytes.len == 0) return;
        const was_empty = w.len == 0;

        const tail = (w.head + w.len) % w.buf.len;
        const first = @min(bytes.len, w.buf.len - tail);
        @memcpy(w.buf[tail..][0..first], bytes[0..first]);
        @memcpy(w.buf[0 .. bytes.len - first], bytes[first..]);
        w.len += bytes.len;

        if (!w.above_high_water and w.len > w.options.high_water) {
            w.above_high_water = true;
            w.options.callback(w.options.context, .above_high_water);
        }

        if (was_empty) w.wake.notify();
    }

    pub fn aboveHighWater(w: *Writer) bool {
        w.mutex.lockUncancelable(w.io);
        defer w.mutex.unlock(w.io);
        return w.above_high_water;
    }

    fn run(w: *Writer) void {
        const fd = w.options.fd;

        var poll_fd = true;

        while (true) {
            w.mutex.lockUncancelable(w.io);
            const stopping = w.stopping;
            const chunk = w.buf[w.head..][0..@min(w.len, w.buf.len - w.head, max_write)];
            w.mutex.unlock(w.io);
            if (stopping == .discard or (stopping == .drain and chunk.len == 0)) return;

            if (chunk.len == 0) {
                waitForWake(w.wake.read_fd);
                w.wake.drain();
                continue;
            }

            if (poll_fd) switch (waitFor(fd, posix.POLL.OUT, w.wake.read_fd)) {
                .ready => {},
                .woken => {
                    w.wake.drain();
                    continue;
                },
                .unsupported => poll_fd = false,
            };

            const rc = c.write(fd, chunk.ptr, chunk.len);
            const err: WriteError = switch (posix.errno(rc)) {
                .SUCCESS => {
                    w.consume(@intCast(rc));
                    continue;
                },
                .INTR, .AGAIN => continue,
                .IO => error.InputOutput,
                .PIPE => error.BrokenPipe,
                .NOSPC, .DQUOT => error.NoSpaceLeft,
                else => |e| posix.unexpectedErrno(e),
            };
            return w.fail(err);
        }
    }

    fn consume(w: *Writer, n: usize) void {
        w.mutex.lockUncancelable(w.io);
        defer w.mutex.unlock(w.io);
        w.head = (w.head + n) % w.buf.len;
        w.len -= n;
        if (w.len == 0) w.head = 0;
        if (w.above_high_water and w.len <= w.options.low_water) {
            w.above_high_water = false;
            w.options.callback(w.options.context, .below_low_water);
        }
    }

    fn fail(w: *Writer, err: WriteError) void {
        w.mutex.lockUncancelable(w.io);
        defer w.mutex.unlock(w.io);
        w.failed = true;

        w.head = 0;
        w.len = 0;
        w.options.callback(w.options.context, .{ .failed = err });
    }
};

const Ready = enum {
    ready,
    woken,
    unsupported,
};

fn waitFor(fd: posix.fd_t, events: i16, wake_fd: posix.fd_t) Ready {
    var fds = [_]posix.pollfd{
        .{ .fd = wake_fd, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = fd, .events = events, .revents = 0 },
    };
    while (true) {
        if (c.poll(&fds, fds.len, -1) == -1) switch (posix.errno(-1)) {
            .INTR, .AGAIN => continue,
            else => return .ready,
        };

        if (fds[0].revents != 0) return .woken;
        if (fds[1].revents & posix.POLL.NVAL != 0) return .unsupported;
        if (fds[1].revents != 0) return .ready;
    }
}

fn waitForWake(wake_fd: posix.fd_t) void {
    var fds = [_]posix.pollfd{.{ .fd = wake_fd, .events = posix.POLL.IN, .revents = 0 }};
    while (c.poll(&fds, fds.len, -1) == -1) switch (posix.errno(-1)) {
        .INTR, .AGAIN => {},
        else => return,
    };
}

pub fn getAttrs(fd: posix.fd_t, attrs: *posix.termios) TerminalError!void {
    const rc = if (native_os == .linux)
        ioctl(fd, std.os.linux.T.CGETS, @intFromPtr(attrs))
    else
        c.tcgetattr(fd, attrs);
    if (rc != 0) return terminalError(posix.errno(-1));
}

pub fn setAttrs(fd: posix.fd_t, attrs: *const posix.termios) posix.E {
    while (true) {
        const rc = if (native_os == .linux)
            ioctl(fd, std.os.linux.T.CSETSW, @intFromPtr(attrs))
        else
            c.tcsetattr(fd, .DRAIN, attrs);
        switch (posix.errno(rc)) {
            .INTR => continue,
            else => |err| return err,
        }
    }
}

fn terminalError(err: posix.E) TerminalError {
    return switch (err) {
        .NOTTY => error.NotATerminal,
        else => posix.unexpectedErrno(err),
    };
}

fn closeFd(fd: posix.fd_t) void {
    _ = c.close(fd);
}

extern "c" fn ioctl(fd: posix.fd_t, request: c_ulong, ...) c_int;

const tiocgwinsz: c_ulong = c.T.IOCGWINSZ;
const tiocswinsz: c_ulong = if (native_os.isDarwin()) 0x80087467 else c.T.IOCSWINSZ;

const testing = std.testing;

const test_timeout_ms = 10_000;

const libc = struct {
    extern "c" fn posix_openpt(flags: posix.O) c_int;
    extern "c" fn grantpt(fd: posix.fd_t) c_int;
    extern "c" fn unlockpt(fd: posix.fd_t) c_int;
    extern "c" fn ptsname_r(fd: posix.fd_t, buf: [*]u8, len: usize) c_int;
};

const TestPty = struct {
    master: posix.fd_t,
    slave: posix.fd_t,

    fn open() !TestPty {
        const master = libc.posix_openpt(.{ .ACCMODE = .RDWR, .NOCTTY = true });
        if (master == -1) return error.OpenPtyFailed;
        errdefer closeFd(master);
        if (libc.grantpt(master) != 0 or libc.unlockpt(master) != 0) return error.OpenPtyFailed;
        var name: [128]u8 = undefined;
        if (libc.ptsname_r(master, &name, name.len) != 0) return error.OpenPtyFailed;
        const len = std.mem.indexOfScalar(u8, &name, 0).?;
        const slave = c.open(name[0..len :0], .{ .ACCMODE = .RDWR, .NOCTTY = true });
        if (slave == -1) return error.OpenPtyFailed;
        return .{ .master = master, .slave = slave };
    }

    fn close(pty: *TestPty) void {
        if (pty.master != -1) closeFd(pty.master);
        closeFd(pty.slave);
    }

    fn closeMaster(pty: *TestPty) void {
        closeFd(pty.master);
        pty.master = -1;
    }

    fn writeMaster(pty: *TestPty, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0) {
            const rc = c.write(pty.master, rest.ptr, rest.len);
            if (rc == -1) return posix.unexpectedErrno(posix.errno(-1));
            rest = rest[@intCast(rc)..];
        }
    }

    fn readMaster(pty: *TestPty, buf: []u8, end_ms: i64) !usize {
        const io = testing.io;
        while (true) {
            const remaining = end_ms - Io.Clock.awake.now(io).toMilliseconds();
            if (remaining <= 0) return error.Timeout;
            var fds = [_]posix.pollfd{.{ .fd = pty.master, .events = posix.POLL.IN, .revents = 0 }};
            if (c.poll(&fds, fds.len, @intCast(remaining)) != 1) continue;
            const rc = c.read(pty.master, buf.ptr, buf.len);
            if (rc == -1) return posix.unexpectedErrno(posix.errno(-1));
            return @intCast(rc);
        }
    }
};

fn deadline() i64 {
    return Io.Clock.awake.now(testing.io).toMilliseconds() + test_timeout_ms;
}

fn waitUntil(context: anytype, comptime done: fn (@TypeOf(context)) bool) !void {
    const io = testing.io;
    const end = deadline();
    while (!done(context)) {
        if (Io.Clock.awake.now(io).toMilliseconds() >= end) return error.Timeout;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
}

test "raw mode sets OpenSSH's flags and restore brings back the saved attributes" {
    var pty: TestPty = try .open();
    defer pty.close();
    var before: posix.termios = undefined;
    try getAttrs(pty.slave, &before);
    try testing.expect(before.lflag.ICANON and before.lflag.ECHO and before.oflag.OPOST);

    const raw: RawMode = try .enter(pty.slave);
    try testing.expectEqual(before, raw.saved);
    var attrs: posix.termios = undefined;
    try getAttrs(pty.slave, &attrs);
    try testing.expect(!attrs.lflag.ISIG and !attrs.lflag.ICANON and !attrs.lflag.ECHO and !attrs.lflag.IEXTEN);
    try testing.expect(!attrs.iflag.IXON and !attrs.iflag.ICRNL and !attrs.iflag.ISTRIP and attrs.iflag.IGNPAR);
    try testing.expect(!attrs.oflag.OPOST);
    try testing.expectEqual(1, attrs.cc[@backingInt(posix.V.MIN)]);
    try testing.expectEqual(0, attrs.cc[@backingInt(posix.V.TIME)]);

    raw.restore();
    try getAttrs(pty.slave, &attrs);
    try expectRestored(before, attrs);
}

fn expectRestored(saved: posix.termios, attrs: posix.termios) !void {
    var got = attrs;
    got.lflag.PENDIN = saved.lflag.PENDIN;
    try testing.expectEqual(saved, got);
}

test "a pipe is not a terminal" {
    var fds: [2]posix.fd_t = undefined;
    try testing.expectEqual(0, c.pipe(&fds));
    defer for (fds) |fd| closeFd(fd);
    try testing.expectError(error.NotATerminal, RawMode.enter(fds[0]));
    try testing.expectError(error.NotATerminal, getSize(fds[0]));
}

test "getSize reads the window size" {
    var pty: TestPty = try .open();
    defer pty.close();
    var ws: posix.winsize = .{ .row = 40, .col = 120, .xpixel = 1200, .ypixel = 800 };
    try testing.expectEqual(0, ioctl(pty.master, tiocswinsz, @intFromPtr(&ws)));
    try testing.expectEqual(Size{ .cols = 120, .rows = 40, .width_px = 1200, .height_px = 800 }, try getSize(pty.slave));
}

const ReaderLog = struct {
    mutex: Io.Mutex = .init,
    buf: [256]u8 = undefined,
    len: usize = 0,
    ended: bool = false,
    failure: ?Reader.ReadError = null,

    fn callback(context: ?*anyopaque, event: Reader.Event) void {
        const log: *ReaderLog = @ptrCast(@alignCast(context.?));
        log.mutex.lockUncancelable(testing.io);
        defer log.mutex.unlock(testing.io);
        switch (event) {
            .data => |data| {
                @memcpy(log.buf[log.len..][0..data.len], data);
                log.len += data.len;
            },
            .end_of_file => log.ended = true,
            .failed => |err| log.failure = err,
        }
    }

    fn hasLen(comptime len: usize) fn (*ReaderLog) bool {
        return struct {
            fn done(log: *ReaderLog) bool {
                log.mutex.lockUncancelable(testing.io);
                defer log.mutex.unlock(testing.io);
                return log.len >= len;
            }
        }.done;
    }

    fn hasEnded(log: *ReaderLog) bool {
        log.mutex.lockUncancelable(testing.io);
        defer log.mutex.unlock(testing.io);
        return log.ended or log.failure != null;
    }
};

test "reader passes raw input through unchanged" {
    var pty: TestPty = try .open();
    defer pty.close();
    const raw: RawMode = try .enter(pty.slave);
    defer raw.restore();

    var log: ReaderLog = .{};
    var reader: Reader = undefined;
    try reader.start(.{ .fd = pty.slave, .context = &log, .callback = ReaderLog.callback });
    const input = "a\r\x03\x1a\x11\x7f\xff\xc3(~";
    try pty.writeMaster(input);
    try waitUntil(&log, ReaderLog.hasLen(input.len));
    reader.stop();
    try testing.expectEqualStrings(input, log.buf[0..log.len]);
    try testing.expect(!log.ended and log.failure == null);
}

test "reader reports the end of input when the terminal hangs up" {
    var pty: TestPty = try .open();
    defer pty.close();
    var log: ReaderLog = .{};
    var reader: Reader = undefined;
    try reader.start(.{ .fd = pty.slave, .context = &log, .callback = ReaderLog.callback });
    defer reader.stop();
    pty.closeMaster();
    try waitUntil(&log, ReaderLog.hasEnded);
    if (log.failure) |err| try testing.expectEqual(error.InputOutput, err);
}

const WriterLog = struct {
    mutex: Io.Mutex = .init,
    above: u32 = 0,
    below: u32 = 0,
    failure: ?Writer.WriteError = null,

    fn callback(context: ?*anyopaque, event: Writer.Event) void {
        const log: *WriterLog = @ptrCast(@alignCast(context.?));
        log.mutex.lockUncancelable(testing.io);
        defer log.mutex.unlock(testing.io);
        switch (event) {
            .above_high_water => log.above += 1,
            .below_low_water => log.below += 1,
            .failed => |err| log.failure = err,
        }
    }

    fn get(log: *WriterLog) WriterLog {
        log.mutex.lockUncancelable(testing.io);
        defer log.mutex.unlock(testing.io);
        return log.*;
    }

    fn isBelow(log: *WriterLog) bool {
        return log.get().below > 0;
    }

    fn hasFailed(log: *WriterLog) bool {
        return log.get().failure != null;
    }
};

fn patternByte(i: usize) u8 {
    return @intCast(i % 251);
}

test "writer writes in order and signals the high-water mark" {
    var pty: TestPty = try .open();
    defer pty.close();
    const raw: RawMode = try .enter(pty.slave);
    defer raw.restore();

    var log: WriterLog = .{};
    var writer: Writer = undefined;
    try writer.start(testing.allocator, testing.io, .{
        .fd = pty.slave,
        .capacity = 4 * 1024 * 1024,
        .high_water = 512 * 1024,
        .low_water = 64 * 1024,
        .context = &log,
        .callback = WriterLog.callback,
    });
    defer writer.stop(.discard);

    const total = 2 * 1024 * 1024;
    var chunk: [1000]u8 = undefined;
    var written: usize = 0;
    while (written < total) {
        const n = @min(chunk.len, total - written);
        for (chunk[0..n], written..) |*byte, i| byte.* = patternByte(i);
        try writer.write(chunk[0..n]);
        written += n;
    }
    try testing.expectEqual(1, log.get().above);
    try testing.expectEqual(0, log.get().below);
    try testing.expect(writer.aboveHighWater());

    const end = deadline();
    var buf: [64 * 1024]u8 = undefined;
    var read: usize = 0;
    while (read < total) {
        const n = try pty.readMaster(&buf, end);
        try testing.expect(n > 0);
        for (buf[0..n], read..) |byte, i| {
            if (byte != patternByte(i)) {
                std.debug.print("byte {d} is {d}, expected {d}\n", .{ i, byte, patternByte(i) });
                return error.TestUnexpectedResult;
            }
        }
        read += n;
    }
    try testing.expectEqual(total, read);
    try waitUntil(&log, WriterLog.isBelow);
    try testing.expectEqual(1, log.get().above);
    try testing.expectEqual(1, log.get().below);
    try testing.expect(!writer.aboveHighWater());
    try testing.expectEqual(null, log.get().failure);
}

test "writer reports an error when the terminal hangs up" {
    var pty: TestPty = try .open();
    defer pty.close();
    var log: WriterLog = .{};
    var writer: Writer = undefined;
    try writer.start(testing.allocator, testing.io, .{
        .fd = pty.slave,
        .context = &log,
        .callback = WriterLog.callback,
    });
    defer writer.stop(.drain);
    pty.closeMaster();
    try writer.write("hello");
    try waitUntil(&log, WriterLog.hasFailed);
    try testing.expectEqual(error.InputOutput, log.get().failure.?);
    try testing.expectError(error.Failed, writer.write("hello"));
}

test "writer rejects bytes beyond its capacity" {
    var pty: TestPty = try .open();
    defer pty.close();
    var log: WriterLog = .{};
    var writer: Writer = undefined;
    try writer.start(testing.allocator, testing.io, .{
        .fd = pty.slave,
        .capacity = 16,
        .high_water = 8,
        .low_water = 4,
        .context = &log,
        .callback = WriterLog.callback,
    });
    defer writer.stop(.discard);
    try testing.expectError(error.QueueFull, writer.write(&@as([17]u8, @splat('a'))));
}

fn setSignalMask(mask: posix.sigset_t) void {
    var old: posix.sigset_t = undefined;
    _ = c.pthread_sigmask(posix.SIG.SETMASK, &mask, &old);
}

const SignalLog = struct {
    mutex: Io.Mutex = .init,
    size: ?Size = null,
    terminate: ?posix.SIG = null,
    attrs: ?posix.termios = null,
    fd: posix.fd_t,

    fn callback(context: ?*anyopaque, event: Signals.Event) void {
        const log: *SignalLog = @ptrCast(@alignCast(context.?));
        log.mutex.lockUncancelable(testing.io);
        defer log.mutex.unlock(testing.io);
        switch (event) {
            .resize => |size| log.size = size,
            .terminate => |sig| {
                var attrs: posix.termios = undefined;
                getAttrs(log.fd, &attrs) catch {};
                log.attrs = attrs;
                log.terminate = sig;
            },
        }
    }

    fn hasSize(log: *SignalLog) bool {
        log.mutex.lockUncancelable(testing.io);
        defer log.mutex.unlock(testing.io);
        return log.size != null;
    }

    fn hasTerminate(log: *SignalLog) bool {
        log.mutex.lockUncancelable(testing.io);
        defer log.mutex.unlock(testing.io);
        return log.terminate != null;
    }
};

test "SIGWINCH reports the new size" {
    const old_mask = blockSignals();
    defer setSignalMask(old_mask);
    var pty: TestPty = try .open();
    defer pty.close();

    var log: SignalLog = .{ .fd = pty.slave };
    var signals: Signals = undefined;
    try signals.start(.{ .fd = pty.slave, .context = &log, .callback = SignalLog.callback });
    defer signals.stop();

    var ws: posix.winsize = .{ .row = 30, .col = 100, .xpixel = 1000, .ypixel = 600 };
    try testing.expectEqual(0, ioctl(pty.master, tiocswinsz, @intFromPtr(&ws)));
    try testing.expectEqual(0, c.pthread_kill(signals.thread.getHandle(), .WINCH));
    try waitUntil(&log, SignalLog.hasSize);
    try testing.expectEqual(Size{ .cols = 100, .rows = 30, .width_px = 1000, .height_px = 600 }, log.size.?);
}

test "SIGTERM restores the terminal before the callback runs" {
    const old_mask = blockSignals();
    defer setSignalMask(old_mask);
    var pty: TestPty = try .open();
    defer pty.close();
    const raw: RawMode = try .enter(pty.slave);
    defer raw.restore();

    var log: SignalLog = .{ .fd = pty.slave };
    var signals: Signals = undefined;
    try signals.start(.{ .fd = pty.slave, .raw_mode = &raw, .context = &log, .callback = SignalLog.callback });
    defer signals.stop();

    try testing.expectEqual(0, c.pthread_kill(signals.thread.getHandle(), .TERM));
    try waitUntil(&log, SignalLog.hasTerminate);
    try testing.expectEqual(posix.SIG.TERM, log.terminate.?);
    try expectRestored(raw.saved, log.attrs.?);
}

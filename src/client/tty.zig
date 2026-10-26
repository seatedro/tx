//! The user's terminal: raw mode, the window size, and threads that read
//! stdin, write stdout and receive signals.
//!
//! stdin and stdout stay blocking. Their file descriptions are shared with
//! the user's shell, and O_NONBLOCK set on them would stay set after the
//! client exits. Each thread polls its fd together with a wake pipe, so
//! `stop` can end it.
//!
//! Call `blockSignals` before the process starts any thread. Stop the
//! threads before `RawMode.restore`.
//!
//! Uses libc only; supports Linux (glibc and musl) and macOS.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const posix = std.posix;
const c = std.c;
const native_os = builtin.os.tag;
const Wake = @import("wake").Wake;

/// A terminal size in cells. `width_px` and `height_px` are the size of the
/// grid in pixels; 0 means unknown.
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

/// A terminal in raw mode and the attributes it had before.
pub const RawMode = struct {
    fd: posix.fd_t,
    saved: posix.termios,

    /// Applies `makeRaw` after the terminal's pending output is written.
    pub fn enter(fd: posix.fd_t) TerminalError!RawMode {
        var saved: posix.termios = undefined;
        try getAttrs(fd, &saved);

        const raw = makeRaw(saved);
        switch (setAttrs(fd, &raw)) {
            .SUCCESS => {},
            else => |err| return terminalError(err),
        }
        return .{ .fd = fd, .saved = saved };
    }

    /// Thread-safe and async-signal-safe, for use from a panic or crash
    /// handler. Errors are ignored; after a hangup the terminal is gone.
    pub fn restore(raw: *const RawMode) void {
        _ = setAttrs(raw.fd, &raw.saved);
    }
};

/// The changes OpenSSH's client makes in `enter_raw_mode` (sshtty.c): no
/// signal characters, line editing, echo, flow control, input or output
/// translation, and reads return after one byte.
pub fn makeRaw(attrs: posix.termios) posix.termios {
    var raw = attrs;

    // Input: bytes pass through unchanged, and ^S and ^Q are not flow
    // control. IGNPAR drops bytes with parity errors.
    raw.iflag.IGNPAR = true;
    raw.iflag.ISTRIP = false;
    raw.iflag.INLCR = false;
    raw.iflag.IGNCR = false;
    raw.iflag.ICRNL = false;
    raw.iflag.IXON = false;
    raw.iflag.IXANY = false;
    raw.iflag.IXOFF = false;
    // Linux only.
    if (@hasField(@TypeOf(raw.iflag), "IUCLC")) raw.iflag.IUCLC = false;

    // Local: no ^C or ^Z signals, no line editing, no echo. The remote
    // terminal does these.
    raw.lflag.ISIG = false;
    raw.lflag.ICANON = false;
    raw.lflag.ECHO = false;
    raw.lflag.ECHOE = false;
    raw.lflag.ECHOK = false;
    raw.lflag.ECHONL = false;
    raw.lflag.IEXTEN = false;

    // Output: no \n to \r\n translation. The server's output already has
    // what the remote terminal produced.
    raw.oflag.OPOST = false;

    // A read returns as soon as one byte is available.
    raw.cc[@backingInt(posix.V.MIN)] = 1;
    raw.cc[@backingInt(posix.V.TIME)] = 0;

    return raw;
}

/// The signals `Signals` receives.
pub const handled_signals = [_]posix.SIG{ .WINCH, .HUP, .TERM, .QUIT };

/// Blocks `handled_signals` in the calling thread and returns the previous
/// mask. Threads inherit the mask, and a process-directed signal goes to
/// any thread that doesn't block it, so the main thread calls this before
/// starting any thread.
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
    // Blocking an empty set changes nothing and returns the current mask.
    const empty = posix.sigemptyset();
    var mask: posix.sigset_t = undefined;
    _ = c.pthread_sigmask(posix.SIG.BLOCK, &empty, &mask);
    for (handled_signals) |sig| {
        if (c.sigismember(&mask, sig) != 1) return false;
    }
    return true;
}

/// A thread that receives `handled_signals` with sigwait.
pub const Signals = struct {
    options: Options,
    thread: std.Thread,
    stopping: std.atomic.Value(bool),
    /// SIGWINCH's action before `start`, restored by `stop`.
    old_winch: posix.Sigaction,

    pub const Event = union(enum) {
        /// The size after a SIGWINCH. Not sent if TIOCGWINSZ fails.
        resize: Size,
        /// SIGHUP, SIGTERM or SIGQUIT. `raw_mode` is restored before the
        /// callback runs. A second one gets the signal's default action,
        /// which ends the process.
        terminate: posix.SIG,
    };

    pub const Options = struct {
        /// The terminal whose size `resize` reports.
        fd: posix.fd_t,
        raw_mode: ?*const RawMode = null,
        context: ?*anyopaque = null,
        /// Runs on the signal thread.
        callback: *const fn (context: ?*anyopaque, event: Event) void,
    };

    /// Asserts that the calling thread blocks `handled_signals`.
    pub fn start(s: *Signals, options: Options) std.Thread.SpawnError!void {
        assert(signalsBlocked());
        s.* = .{ .options = options, .thread = undefined, .stopping = .init(false), .old_winch = undefined };

        // SIGWINCH's default action is to ignore it, and macOS discards an
        // ignored signal when it is sent, blocked or not. With a handler it
        // stays pending until sigwait takes it. Every thread blocks it, so
        // the handler never runs.
        const action: posix.Sigaction = .{ .handler = .{ .handler = ignore }, .mask = posix.sigemptyset(), .flags = 0 };
        _ = c.sigaction(.WINCH, &action, &s.old_winch);
        errdefer _ = c.sigaction(.WINCH, &s.old_winch, null);

        s.thread = try std.Thread.spawn(.{}, run, .{s});
    }

    pub fn stop(s: *Signals) void {
        s.stopping.store(true, .release);
        // Pending on the signal thread, since it blocks SIGWINCH.
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
            // Every thread blocks these signals. sigwait receives them.
            var signo: c_int = undefined;
            const rc = c.sigwait(&set, &signo);
            assert(rc == 0);

            // `stop` wakes the thread with a SIGWINCH.
            if (s.stopping.load(.acquire)) return;

            const sig = std.enums.fromInt(posix.SIG, signo).?;
            switch (sig) {
                .WINCH => {
                    const size = getSize(s.options.fd) catch continue;
                    s.options.callback(s.options.context, .{ .resize = size });
                },
                else => {
                    // The terminal is restored first, in case the process
                    // dies before the main thread gets to it.
                    if (s.options.raw_mode) |raw| raw.restore();

                    // The second terminating signal ends the process at once.
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

        // raise makes the signal pending on this thread, and unblocking it
        // delivers it before pthread_sigmask returns.
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

/// A thread that reads a terminal and passes what it reads to a callback.
pub const Reader = struct {
    options: Options,
    wake: Wake,
    thread: std.Thread,
    buf: [16 * 1024]u8,

    pub const Event = union(enum) {
        /// Valid until the callback returns.
        data: []const u8,
        end_of_file,
        failed: ReadError,
    };

    pub const ReadError = error{ InputOutput, SystemResources, Unexpected };

    pub const Options = struct {
        fd: posix.fd_t,
        context: ?*anyopaque = null,
        /// Runs on the reader thread. No events follow `end_of_file` or
        /// `failed`.
        callback: *const fn (context: ?*anyopaque, event: Event) void,
    };

    pub fn start(r: *Reader, options: Options) StartError!void {
        r.* = .{ .options = options, .wake = try .init(), .thread = undefined, .buf = undefined };
        errdefer r.wake.deinit();
        r.thread = try std.Thread.spawn(.{}, run, .{r});
    }

    /// Joins the reader thread. A callback in progress finishes first.
    pub fn stop(r: *Reader) void {
        r.wake.notify();
        r.thread.join();
        r.wake.deinit();
        r.* = undefined;
    }

    fn run(r: *Reader) void {
        const fd = r.options.fd;

        // Cleared if the fd turns out not to support poll. Reads then block
        // and `stop` waits for the next byte.
        var poll_fd = true;

        while (true) {
            // Wait for input or for `stop`.
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
                // EAGAIN if another process set O_NONBLOCK on the file
                // description.
                .INTR, .AGAIN => continue,
                .IO => error.InputOutput,
                .NOMEM, .NOBUFS => error.SystemResources,
                else => |e| posix.unexpectedErrno(e),
            };
            return r.options.callback(r.options.context, .{ .failed = err });
        }
    }
};

/// A thread that writes queued bytes to a terminal, in order and in full.
///
/// The queue's high-water mark tells the producer to stop acknowledging
/// output, which slows the server down.
pub const Writer = struct {
    gpa: Allocator,
    io: Io,
    options: Options,
    wake: Wake,
    thread: std.Thread,

    /// Guards the fields below, which `write` and the thread share.
    mutex: Io.Mutex,
    /// A ring buffer. The queued bytes start at `head` and wrap.
    buf: []u8,
    head: usize,
    len: usize,
    /// `above_high_water` was sent and `below_low_water` wasn't yet.
    above_high_water: bool,
    failed: bool,
    stopping: ?StopMode,

    pub const Event = union(enum) {
        /// The queue holds more than `high_water` bytes. Sent from `write`.
        above_high_water,
        /// After `above_high_water`, the queue holds `low_water` bytes or
        /// fewer. Sent from the writer thread.
        below_low_water,
        /// Sent from the writer thread. Queued bytes are dropped, and
        /// `write` fails from then on.
        failed: WriteError,
    };

    pub const WriteError = error{
        /// The terminal was hung up.
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
        /// Runs with the queue locked, which keeps events in order. It must
        /// not call the Writer.
        callback: *const fn (context: ?*anyopaque, event: Event) void,
    };

    pub const StopMode = enum {
        /// Write the queued bytes first. Blocks while the terminal isn't
        /// reading.
        drain,
        discard,
    };

    /// Writes are at most this long, so that `stop` waits for at most one
    /// write to a terminal that isn't reading.
    const max_write = 16 * 1024;

    /// Asserts `low_water <= high_water < capacity`.
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

    /// Joins the writer thread and frees the queue.
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

    /// Queues a copy of `bytes`. Thread-safe.
    pub fn write(w: *Writer, bytes: []const u8) error{ QueueFull, Failed }!void {
        w.mutex.lockUncancelable(w.io);
        defer w.mutex.unlock(w.io);
        assert(w.stopping == null);
        if (w.failed) return error.Failed;
        if (bytes.len > w.buf.len - w.len) return error.QueueFull;
        if (bytes.len == 0) return;
        const was_empty = w.len == 0;

        // Copy to the end of the ring buffer, then wrap to its start.
        const tail = (w.head + w.len) % w.buf.len;
        const first = @min(bytes.len, w.buf.len - tail);
        @memcpy(w.buf[tail..][0..first], bytes[0..first]);
        @memcpy(w.buf[0 .. bytes.len - first], bytes[first..]);
        w.len += bytes.len;

        if (!w.above_high_water and w.len > w.options.high_water) {
            w.above_high_water = true;
            w.options.callback(w.options.context, .above_high_water);
        }

        // A thread with an empty queue is waiting for the wake pipe.
        if (was_empty) w.wake.notify();
    }

    /// Set from `above_high_water` until `below_low_water`. Thread-safe.
    pub fn aboveHighWater(w: *Writer) bool {
        w.mutex.lockUncancelable(w.io);
        defer w.mutex.unlock(w.io);
        return w.above_high_water;
    }

    fn run(w: *Writer) void {
        const fd = w.options.fd;

        // Cleared if the fd turns out not to support poll.
        var poll_fd = true;

        while (true) {
            // The next chunk stops at the end of the ring buffer. `write`
            // appends after the queued bytes, so the chunk can be written
            // without the lock.
            w.mutex.lockUncancelable(w.io);
            const stopping = w.stopping;
            const chunk = w.buf[w.head..][0..@min(w.len, w.buf.len - w.head, max_write)];
            w.mutex.unlock(w.io);
            if (stopping == .discard or (stopping == .drain and chunk.len == 0)) return;

            // Nothing queued: wait for `write` or `stop`.
            if (chunk.len == 0) {
                waitForWake(w.wake.read_fd);
                w.wake.drain();
                continue;
            }

            // Wait until the terminal takes more. A wakeup goes back to the
            // top to check `stopping`.
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
                // EAGAIN if another process set O_NONBLOCK on the file
                // description.
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

        // The terminal is gone. The queued bytes are dropped.
        w.head = 0;
        w.len = 0;
        w.options.callback(w.options.context, .{ .failed = err });
    }
};

const Ready = enum {
    ready,
    woken,
    /// The fd doesn't support poll. macOS's poll rejects some devices with
    /// POLLNVAL.
    unsupported,
};

/// Waits until `fd` has one of `events`, an error or a hangup, or
/// `wake_fd` is readable. A failed poll returns `ready`, for the read or
/// write that follows to report the error.
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

        // A wakeup is checked first. `stop` isn't delayed by a busy fd.
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

// Don't use tcgetattr on Linux: glibc's struct termios is 16 bytes larger
// than the kernel's, which std.c's termios matches, and tcgetattr would
// write past its end. TCGETS and TCSETSW use the kernel's layout. macOS's
// tcgetattr matches std.c's termios.
fn getAttrs(fd: posix.fd_t, attrs: *posix.termios) TerminalError!void {
    const rc = if (native_os == .linux)
        ioctl(fd, std.os.linux.T.CGETS, @intFromPtr(attrs))
    else
        c.tcgetattr(fd, attrs);
    if (rc != 0) return terminalError(posix.errno(-1));
}

/// Applies `attrs` after pending output is written, as OpenSSH does with
/// TCSADRAIN. Async-signal-safe.
fn setAttrs(fd: posix.fd_t, attrs: *const posix.termios) posix.E {
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
    // Don't retry on EINTR: the fd may already be closed and reused by
    // another thread.
    _ = c.close(fd);
}

// glibc and macOS declare the request as unsigned long, musl as int.
// std.c uses c_int, which can't hold macOS's TIOCSWINSZ. musl reads only
// the low 32 bits of the unsigned long.
extern "c" fn ioctl(fd: posix.fd_t, request: c_ulong, ...) c_int;

const tiocgwinsz: c_ulong = c.T.IOCGWINSZ;
const tiocswinsz: c_ulong = if (native_os.isDarwin()) 0x80087467 else c.T.IOCSWINSZ;

const testing = std.testing;

const test_timeout_ms = 10_000;

// Missing from std.c. All are in libc on glibc, musl and macOS.
const libc = struct {
    extern "c" fn posix_openpt(flags: posix.O) c_int;
    extern "c" fn grantpt(fd: posix.fd_t) c_int;
    extern "c" fn unlockpt(fd: posix.fd_t) c_int;
    extern "c" fn ptsname_r(fd: posix.fd_t, buf: [*]u8, len: usize) c_int;
};

/// A pseudo-terminal pair. The slave stands in for the user's terminal and
/// the test drives the master.
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

/// Polls `done(context)` with a deadline.
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

/// Fails unless `attrs` are `saved`. BSD kernels, macOS's among them, set
/// PENDIN when ICANON is turned back on, to reprint pending input, so
/// PENDIN isn't compared.
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
    // No newline at the end: without ICANON, input arrives without one.
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
    // Linux reads 0 bytes from a hung-up terminal. macOS may return EIO.
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

    // The pty buffers far less than total - high_water while the master
    // isn't read.
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
    /// The terminal's attributes when `terminate` was received.
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
    // The kernel signals the terminal's foreground process group, and the
    // slave isn't the test's controlling terminal.
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

    // Sent to the thread: a process-directed SIGTERM would kill the test
    // runner if another thread doesn't block it.
    try testing.expectEqual(0, c.pthread_kill(signals.thread.getHandle(), .TERM));
    try waitUntil(&log, SignalLog.hasTerminate);
    try testing.expectEqual(posix.SIG.TERM, log.terminate.?);
    try expectRestored(raw.saved, log.attrs.?);
}

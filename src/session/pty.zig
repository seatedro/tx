//! A program running on a pseudo-terminal. The session host spawns the
//! user's shell or command here, feeds what it writes into a terminal
//! emulator, and writes the user's input back.
//!
//! A Pty does no event handling. The master is non-blocking and public so
//! the host can multiplex it with the network in its own event loop, and
//! the host decides when to reap the child (see `Pty.wait`). Only libc is
//! used: it works the same on Linux (glibc and musl) and macOS.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const posix = std.posix;
const c = std.c;
const native_os = builtin.os.tag;

/// How the child ended, as `std.process.Child.wait` reports it.
pub const Term = std.process.Child.Term;

/// A terminal size in cells, plus the pixel size of the whole grid for
/// programs that size images by it (sixel, kitty graphics). 0 pixels means
/// unknown.
pub const Size = struct {
    cols: u16,
    rows: u16,
    width_px: u16 = 0,
    height_px: u16 = 0,

    fn winsize(size: Size) posix.winsize {
        return .{ .row = size.rows, .col = size.cols, .xpixel = size.width_px, .ypixel = size.height_px };
    }
};

pub const Options = struct {
    /// argv[0] is what the program sees as its name and, unless `program`
    /// is set, the program to run.
    argv: []const []const u8,
    /// The program to run when it differs from argv[0], as for a login
    /// shell ("/bin/zsh" with argv[0] "-zsh"). A name without a slash is
    /// looked up in the PATH of `environ`, which is the environment the
    /// program will run in, not the host's.
    ///
    /// It must be a binary or a script with a `#!` line: unlike execvp,
    /// there is no retry with /bin/sh on ENOEXEC. Users' commands go
    /// through their shell, which does that itself.
    program: ?[]const u8 = null,
    /// The program's whole environment. Nothing is inherited, since the
    /// host's own environment (a daemon's) is rarely what a user's session
    /// should see.
    environ: *const std.process.Environ.Map,
    cwd: std.process.Child.Cwd = .inherit,
    /// Set before the program starts, so it never sees a 0x0 terminal.
    size: Size,
    /// Filled in when the child fails before or in exec, with the raw
    /// errno behind the returned error.
    diagnostic: ?*Diagnostic = null,
};

/// Why the child failed to start, beyond what the error says. A chdir and
/// an exec can both fail with ENOENT, for example.
pub const Diagnostic = struct {
    step: Step,
    errno: posix.E,

    pub const Step = enum(u8) {
        chdir,
        setsid,
        controlling_terminal,
        stdio,
        exec,
    };
};

pub const SpawnError = error{
    OutOfMemory,
    /// Out of processes, ptys or kernel memory.
    SystemResources,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    /// The program does not exist, or is not on PATH.
    FileNotFound,
    /// The program, or `cwd`, is not accessible.
    AccessDenied,
    /// The program is not in a format the kernel can execute.
    InvalidExe,
    NameTooLong,
    /// `cwd` does not exist or is not a directory.
    WorkingDirectoryNotFound,
    Unexpected,
};

pub const ReadError = error{
    /// Nothing to read yet; wait for the master to become readable.
    WouldBlock,
    SystemResources,
    Unexpected,
};

pub const WriteError = error{
    /// The terminal's input queue is full because the program is not
    /// reading; wait for the master to become writable.
    WouldBlock,
    /// Every process has closed the terminal.
    BrokenPipe,
    SystemResources,
    Unexpected,
};

pub const WaitError = error{
    /// Something other than this Pty reaped the child: SIGCHLD set to
    /// SIG_IGN, or a `waitpid(-1)` elsewhere in the host. Its status is
    /// lost.
    ProcessNotFound,
    Unexpected,
};

pub const KillError = posix.KillError;

pub const ResizeError = error{Unexpected};

/// The master side of a pseudo-terminal and the child process running on
/// its slave side.
///
/// The Pty owns the child until it is reaped. The host must reap it with
/// `wait` or `tryWait` and nothing else, because once a pid is reaped the
/// kernel may hand it to an unrelated process, and `kill` would signal
/// that one instead.
pub const Pty = struct {
    /// Non-blocking, so the host's event loop never stalls on one
    /// direction while the other backs up: a program blocked writing
    /// output stops reading input, and a blocking write of a large paste
    /// would then never return. Close-on-exec, so other children the host
    /// spawns don't hold the terminal open. -1 after `hangup`.
    master: posix.fd_t,
    /// The child until it is reaped.
    pid: ?posix.pid_t,
    /// How the child ended, once reaped.
    term: ?Term,
    tty_name_buf: [128]u8,
    tty_name_len: u8,

    /// Opens a pty and starts a program on it.
    ///
    /// Everything the child needs is prepared before fork, so the child
    /// only makes async-signal-safe calls and never allocates (a malloc
    /// lock held by another thread at fork would deadlock it). When this
    /// returns, the program has been exec'd; if the child fails before
    /// that, it is reaped and its errno is returned as an error here.
    pub fn spawn(gpa: Allocator, options: Options) SpawnError!Pty {
        assert(options.argv.len > 0);
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const argv = try arena.allocSentinel(?[*:0]const u8, options.argv.len, null);
        for (options.argv, argv) |arg, *ptr| ptr.* = (try arena.dupeSentinel(u8, arg, 0)).ptr;
        const envp = try options.environ.createPosixBlock(arena, .{});
        const program = try arena.dupeSentinel(u8, options.program orelse options.argv[0], 0);

        var self: Pty = .{
            .master = try openMaster(),
            .pid = null,
            .term = null,
            .tty_name_buf = undefined,
            .tty_name_len = undefined,
        };
        errdefer closeFd(self.master);

        if (libc.grantpt(self.master) != 0) return openError(posix.errno(-1));
        if (libc.unlockpt(self.master) != 0) return openError(posix.errno(-1));
        // ptsname_r rather than ptsname, whose static buffer races with
        // other threads. glibc and musl return the error number, and macOS
        // returns -1 and sets errno.
        switch (libc.ptsname_r(self.master, &self.tty_name_buf, self.tty_name_buf.len)) {
            0 => {},
            -1 => return openError(posix.errno(-1)),
            else => |err| return openError(@fromBackingInt(@intCast(err))),
        }
        self.tty_name_len = @intCast(std.mem.indexOfScalar(u8, &self.tty_name_buf, 0).?);

        // O_NOCTTY: a daemonized host has no controlling terminal, and
        // opening a tty without it would make this one the host's.
        const slave = try aboveStdio(try openFd(self.tty_name_buf[0..self.tty_name_len :0], .{
            .ACCMODE = .RDWR,
            .NOCTTY = true,
            .CLOEXEC = true,
        }));
        // Only the child keeps the slave open, so that reading the master
        // reports end of file once the child side is gone.
        defer closeFd(slave);

        // Linux's canonical mode erases whole UTF-8 characters only with
        // IUTF8, and macOS doesn't set it by default either.
        var attrs: posix.termios = undefined;
        try getAttrs(slave, &attrs);
        attrs.iflag.IUTF8 = true;
        try setAttrs(slave, &attrs);
        try self.resize(options.size);

        const flags = c.fcntl(self.master, posix.F.GETFL);
        if (flags == -1) return posix.unexpectedErrno(posix.errno(-1));
        const nonblock: c_int = @bitCast(posix.O{ .NONBLOCK = true });
        if (c.fcntl(self.master, posix.F.SETFL, flags | nonblock) == -1)
            return posix.unexpectedErrno(posix.errno(-1));

        var child: Child = .{
            .argv = argv.ptr,
            .envp = envp.slice.ptr,
            .program = program,
            .search_path = if (std.mem.indexOfScalar(u8, program, '/') == null)
                options.environ.get("PATH") orelse default_path
            else
                null,
            .cwd = switch (options.cwd) {
                .inherit => .inherit,
                .dir => |dir| .{ .fd = dir.handle },
                .path => |path| .{ .path = try arena.dupeSentinel(u8, path, 0) },
            },
            .slave = slave,
            .report = undefined,
            .max_fd = maxFd(),
            .default_action = .{ .handler = .{ .handler = posix.SIG.DFL }, .mask = undefined, .flags = 0 },
            .empty_mask = undefined,
        };
        _ = c.sigemptyset(&child.default_action.mask);
        _ = c.sigemptyset(&child.empty_mask);

        // The child writes a Report here if it fails before exec. The
        // pipe is close-on-exec, so a successful exec closes it unwritten.
        const report_pipe = try pipe();
        child.report = report_pipe[1];

        // Block every signal across fork so the child can't run one of the
        // host's handlers before it has reset them all to the default.
        var all_signals: posix.sigset_t = undefined;
        _ = c.sigfillset(&all_signals);
        var old_mask: posix.sigset_t = undefined;
        _ = c.pthread_sigmask(posix.SIG.SETMASK, &all_signals, &old_mask);
        const pid = c.fork();
        if (pid == 0) child.run();
        _ = c.pthread_sigmask(posix.SIG.SETMASK, &old_mask, &all_signals);

        closeFd(report_pipe[1]);
        defer closeFd(report_pipe[0]);
        if (pid == -1) return switch (posix.errno(-1)) {
            .AGAIN, .NOMEM => error.SystemResources,
            else => |err| posix.unexpectedErrno(err),
        };
        const failure = readReport(report_pipe[0]) orelse {
            self.pid = pid;
            return self;
        };
        // Normally the child has already exited, but if reading the pipe
        // itself failed it may have exec'd a shell that won't.
        _ = c.kill(pid, .KILL);
        _ = reap(pid, 0) catch {};
        if (options.diagnostic) |diagnostic| diagnostic.* = .{ .step = failure.step, .errno = failure.errno };
        return failure.toError();
    }

    /// Reads what the program wrote. Returns 0 at end of file, once every
    /// process has closed the terminal, which may be later than the child
    /// exiting if it left background jobs behind. Use `wait` for the exit.
    pub fn read(self: *Pty, buf: []u8) ReadError!usize {
        while (true) {
            const rc = c.read(self.master, buf.ptr, buf.len);
            switch (posix.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                // Linux fails reads with EIO once the slave side has no
                // open fds, where macOS returns 0.
                .IO => return 0,
                .NOMEM, .NOBUFS => return error.SystemResources,
                else => |err| return posix.unexpectedErrno(err),
            }
        }
    }

    /// Writes as much of `bytes` as the terminal's input queue takes.
    pub fn write(self: *Pty, bytes: []const u8) WriteError!usize {
        while (true) {
            const rc = c.write(self.master, bytes.ptr, bytes.len);
            switch (posix.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .IO => return error.BrokenPipe,
                .NOMEM, .NOBUFS => return error.SystemResources,
                else => |err| return posix.unexpectedErrno(err),
            }
        }
    }

    /// Writes all of `bytes`, waiting for the program to read when the
    /// input queue is full. It blocks for as long as the program doesn't
    /// read, so an event loop should use `write` and wait for POLLOUT
    /// itself.
    pub fn writeAll(self: *Pty, bytes: []const u8) error{ BrokenPipe, SystemResources, Unexpected }!void {
        var rest = bytes;
        while (rest.len > 0) {
            const n = self.write(rest) catch |err| switch (err) {
                error.WouldBlock => {
                    var fds = [_]posix.pollfd{.{ .fd = self.master, .events = posix.POLL.OUT, .revents = 0 }};
                    if (c.poll(&fds, fds.len, -1) == -1) switch (posix.errno(-1)) {
                        .INTR => {},
                        .NOMEM => return error.SystemResources,
                        else => |e| return posix.unexpectedErrno(e),
                    };
                    continue;
                },
                else => |e| return e,
            };
            rest = rest[n..];
        }
    }

    /// Sets the terminal size. The kernel sends SIGWINCH to the
    /// terminal's foreground process group when it changes.
    pub fn resize(self: *Pty, size: Size) ResizeError!void {
        var ws = size.winsize();
        if (ioctl(self.master, tiocswinsz, @intFromPtr(&ws)) == -1) return posix.unexpectedErrno(posix.errno(-1));
    }

    /// The slave's path, as `tty` prints it in the child.
    pub fn ttyName(self: *const Pty) [:0]const u8 {
        return self.tty_name_buf[0..self.tty_name_len :0];
    }

    /// Sends `sig` to the child only. Jobs it started in other process
    /// groups don't get it; `hangup` reaches the terminal's foreground job
    /// as well. Fails with ProcessNotFound once the child is reaped rather
    /// than signal whatever process has its pid now.
    pub fn kill(self: *Pty, sig: posix.SIG) KillError!void {
        return posix.kill(self.pid orelse return error.ProcessNotFound, sig);
    }

    /// Blocks until the child exits, and reaps it. Once reaped, returns
    /// the same Term again without blocking.
    pub fn wait(self: *Pty) WaitError!Term {
        return (try self.reapChild(0)).?;
    }

    /// Reaps the child if it has exited, without blocking: call this when
    /// SIGCHLD arrives, or the master reaches end of file. Both usually
    /// happen, so once the child is reaped this returns its Term again
    /// rather than wait for a pid that may now be another process's.
    pub fn tryWait(self: *Pty) WaitError!?Term {
        return self.reapChild(posix.W.NOHANG);
    }

    fn reapChild(self: *Pty, flags: c_int) WaitError!?Term {
        const pid = self.pid orelse return self.term orelse error.ProcessNotFound;
        const term = reap(pid, flags) catch |err| {
            if (err == error.ProcessNotFound) self.pid = null;
            return err;
        };
        if (term != null) {
            self.pid = null;
            self.term = term;
        }
        return term;
    }

    /// Closes the master, which hangs up the terminal as if the user's
    /// connection dropped: the kernel sends SIGHUP to the child (the
    /// session leader) and to the foreground job, and shells pass it on to
    /// their other jobs. Programs save state on SIGHUP (shell history, vim
    /// swap files), so this is the graceful way to end a session; `wait`
    /// for the child afterwards.
    pub fn hangup(self: *Pty) void {
        if (self.master == -1) return;
        closeFd(self.master);
        self.master = -1;
    }

    /// Hangs up, then kills and reaps the child if it is still unreaped,
    /// so no zombie is left behind. That gives the program no chance to
    /// shut down cleanly; use `hangup` and `wait` first for that.
    pub fn deinit(self: *Pty) void {
        self.hangup();
        if (self.pid) |pid| {
            _ = c.kill(pid, .KILL);
            _ = reap(pid, 0) catch {};
        }
        self.* = undefined;
    }
};

/// What execvp uses when PATH is unset.
const default_path = "/usr/bin:/bin";

/// The fd limit for closing inherited fds one by one, when close_range is
/// unavailable (macOS, Linux before 5.9) and RLIMIT_NOFILE is huge. An
/// inheritable fd above it, or above a soft limit lowered after it was
/// opened, leaks into the child there; without listing fds (which
/// allocates) the child can't find it.
const max_fd_limit = 1 << 16;

// glibc and macOS declare the request as unsigned long and musl as int;
// std.c uses c_int, which can't hold macOS's TIOCSWINSZ. Passing an
// unsigned long is right for the first two and harmless for musl, which
// reads only the low 32 bits.
extern "c" fn ioctl(fd: posix.fd_t, request: c_ulong, ...) c_int;

const tiocsctty: c_ulong = if (native_os.isDarwin()) 0x20007461 else c.T.IOCSCTTY;
const tiocswinsz: c_ulong = if (native_os.isDarwin()) 0x80087467 else c.T.IOCSWINSZ;

/// What the child does between fork and exec, with everything it needs.
const Child = struct {
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    program: [:0]const u8,
    /// PATH to search for `program`, or null if it contains a slash.
    search_path: ?[]const u8,
    cwd: union(enum) {
        inherit,
        fd: posix.fd_t,
        path: [*:0]const u8,
    },
    /// Both above stdio, so that installing stdio clobbers neither.
    slave: posix.fd_t,
    report: posix.fd_t,
    max_fd: posix.fd_t,
    default_action: posix.Sigaction,
    empty_mask: posix.sigset_t,

    fn run(child: *const Child) noreturn {
        switch (child.cwd) {
            .inherit => {},
            .fd => |fd| if (c.fchdir(fd) != 0) fail(child.report, .chdir, posix.errno(-1)),
            .path => |path| if (c.chdir(path) != 0) fail(child.report, .chdir, posix.errno(-1)),
        }

        // A new session has no controlling terminal, so the slave can
        // become this one's. That also makes the child the foreground
        // process group, which gets ^C and SIGWINCH.
        if (c.setsid() == -1) fail(child.report, .setsid, posix.errno(-1));
        if (ioctl(child.slave, tiocsctty, @as(c_ulong, 0)) == -1)
            fail(child.report, .controlling_terminal, posix.errno(-1));

        for ([_]posix.fd_t{ 0, 1, 2 }) |fd| {
            if (c.dup2(child.slave, fd) == -1) fail(child.report, .stdio, posix.errno(-1));
        }
        // Close everything else the host had open without close-on-exec,
        // keeping only the report pipe, moved to 3.
        const report: posix.fd_t = 3;
        if (c.dup2(child.report, report) == -1) fail(child.report, .stdio, posix.errno(-1));
        if (c.fcntl(report, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) == -1)
            fail(report, .stdio, posix.errno(-1));
        closeFrom(report + 1, child.max_fd);

        // exec keeps ignored signals ignored and keeps the mask, and the
        // host likely ignores SIGPIPE at least. Errors are for signals
        // that can't be changed (KILL, STOP, libc's internal ones).
        var sig: u32 = 1;
        while (sig < posix.NSIG) : (sig += 1) {
            _ = c.sigaction(@fromBackingInt(sig), &child.default_action, null);
        }
        _ = c.sigprocmask(posix.SIG.SETMASK, &child.empty_mask, null);

        fail(report, .exec, child.exec());
    }

    /// Returns only if exec fails, with why.
    fn exec(child: *const Child) posix.E {
        const search_path = child.search_path orelse {
            _ = c.execve(child.program, child.argv, child.envp);
            return posix.errno(-1);
        };
        // As execvp: try each PATH entry in turn, and report EACCES if
        // some entry had the program but couldn't run it.
        var path_buf: [posix.PATH_MAX]u8 = undefined;
        var denied = false;
        var dirs = std.mem.splitScalar(u8, search_path, ':');
        while (dirs.next()) |entry| {
            const dir = if (entry.len == 0) "." else entry;
            if (dir.len + 1 + child.program.len >= path_buf.len) continue;
            @memcpy(path_buf[0..dir.len], dir);
            path_buf[dir.len] = '/';
            @memcpy(path_buf[dir.len + 1 ..][0..child.program.len], child.program);
            path_buf[dir.len + 1 + child.program.len] = 0;
            _ = c.execve(path_buf[0 .. dir.len + 1 + child.program.len :0], child.argv, child.envp);
            switch (posix.errno(-1)) {
                .ACCES => denied = true,
                .NOENT, .NOTDIR, .NAMETOOLONG, .LOOP => {},
                else => |err| return err,
            }
        }
        return if (denied) .ACCES else .NOENT;
    }

    fn fail(fd: posix.fd_t, step: Diagnostic.Step, err: posix.E) noreturn {
        const report: Report = .{ .step = @backingInt(step), .errno = @intCast(@backingInt(err)) };
        const bytes = std.mem.asBytes(&report);
        // Smaller than PIPE_BUF, so one write delivers all of it or none.
        while (posix.errno(c.write(fd, bytes, bytes.len)) == .INTR) {}
        // _exit, not exit: atexit handlers belong to the host.
        c._exit(127);
    }
};

/// What a failed child sends the parent.
const Report = extern struct {
    step: u32,
    errno: u32,

    const Failure = struct {
        step: Diagnostic.Step,
        errno: posix.E,

        fn toError(failure: Failure) SpawnError {
            return switch (failure.step) {
                .chdir => switch (failure.errno) {
                    .NOENT, .NOTDIR => error.WorkingDirectoryNotFound,
                    .ACCES => error.AccessDenied,
                    .NAMETOOLONG => error.NameTooLong,
                    else => |err| posix.unexpectedErrno(err),
                },
                .exec => switch (failure.errno) {
                    .NOENT, .NOTDIR, .LOOP => error.FileNotFound,
                    .ACCES, .PERM => error.AccessDenied,
                    .NOEXEC => error.InvalidExe,
                    .NAMETOOLONG => error.NameTooLong,
                    .@"2BIG", .NOMEM, .AGAIN, .TXTBSY => error.SystemResources,
                    .MFILE => error.ProcessFdQuotaExceeded,
                    .NFILE => error.SystemFdQuotaExceeded,
                    else => |err| posix.unexpectedErrno(err),
                },
                .setsid, .controlling_terminal, .stdio => posix.unexpectedErrno(failure.errno),
            };
        }
    };
};

/// Returns null if the child exec'd, which closed the pipe unwritten.
fn readReport(fd: posix.fd_t) ?Report.Failure {
    var report: Report = undefined;
    const bytes = std.mem.asBytes(&report);
    const n = while (true) {
        const rc = c.read(fd, bytes, bytes.len);
        switch (posix.errno(rc)) {
            .SUCCESS => break @as(usize, @intCast(rc)),
            .INTR => continue,
            else => |err| return .{ .step = .exec, .errno = err },
        }
    };
    if (n == 0) return null;
    if (n != bytes.len) return .{ .step = .exec, .errno = .IO };
    return .{
        .step = std.enums.fromInt(Diagnostic.Step, report.step) orelse .exec,
        .errno = @fromBackingInt(@intCast(report.errno)),
    };
}

fn reap(pid: posix.pid_t, flags: c_int) WaitError!?Term {
    var status: c_int = undefined;
    while (true) {
        const rc = c.waitpid(pid, &status, flags);
        switch (posix.errno(rc)) {
            .SUCCESS => return if (rc == 0) null else statusToTerm(@bitCast(status)),
            .INTR => continue,
            .CHILD => return error.ProcessNotFound,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn statusToTerm(status: u32) Term {
    return if (posix.W.IFEXITED(status))
        .{ .exited = posix.W.EXITSTATUS(status) }
    else if (posix.W.IFSIGNALED(status))
        .{ .signal = posix.W.TERMSIG(status) }
    else if (posix.W.IFSTOPPED(status))
        .{ .stopped = posix.W.STOPSIG(status) }
    else
        .{ .unknown = status };
}

fn openMaster() SpawnError!posix.fd_t {
    // glibc and musl pass the flags to open(2), so Linux gets the master
    // close-on-exec atomically. macOS rejects any flag but these two, so
    // there another thread spawning between posix_openpt and fcntl can
    // leak the master into its child, which then holds the terminal open
    // until it exits or execs.
    var flags: posix.O = .{ .ACCMODE = .RDWR, .NOCTTY = true };
    if (native_os == .linux) flags.CLOEXEC = true;
    const fd = libc.posix_openpt(flags);
    if (fd == -1) return openError(posix.errno(-1));
    if (native_os != .linux) {
        if (c.fcntl(fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) == -1) {
            closeFd(fd);
            return posix.unexpectedErrno(posix.errno(-1));
        }
    }
    return fd;
}

// On Linux, std.c's termios is the kernel's layout, but glibc's
// tcgetattr writes its own, 16 bytes larger, struct termios: past the end
// of ours. TCGETS and TCSETS use the kernel's layout, which ours holds.
// macOS's tcgetattr matches std.c's termios.
fn getAttrs(fd: posix.fd_t, attrs: *posix.termios) SpawnError!void {
    const rc = if (native_os == .linux)
        ioctl(fd, std.os.linux.T.CGETS, @intFromPtr(attrs))
    else
        c.tcgetattr(fd, attrs);
    if (rc != 0) return posix.unexpectedErrno(posix.errno(-1));
}

fn setAttrs(fd: posix.fd_t, attrs: *const posix.termios) SpawnError!void {
    const rc = if (native_os == .linux)
        ioctl(fd, std.os.linux.T.CSETS, @intFromPtr(attrs))
    else
        c.tcsetattr(fd, .NOW, attrs);
    if (rc != 0) return posix.unexpectedErrno(posix.errno(-1));
}

fn openFd(path: [*:0]const u8, flags: posix.O) SpawnError!posix.fd_t {
    while (true) {
        const fd = c.open(path, flags);
        switch (posix.errno(fd)) {
            .SUCCESS => return fd,
            .INTR => continue,
            else => |err| return openError(err),
        }
    }
}

fn openError(err: posix.E) SpawnError {
    return switch (err) {
        // ENOSPC is Linux out of ptys (kernel.pty.max), EAGAIN macOS.
        .AGAIN, .NOSPC, .NOMEM => error.SystemResources,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .ACCES, .PERM => error.AccessDenied,
        else => posix.unexpectedErrno(err),
    };
}

/// A close-on-exec pipe with both ends above stdio. macOS has no pipe2,
/// so another thread forking between pipe and fcntl can inherit it there.
fn pipe() SpawnError![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    if (@TypeOf(c.pipe2) != void) {
        if (c.pipe2(&fds, .{ .CLOEXEC = true }) == -1) return openError(posix.errno(-1));
    } else {
        if (c.pipe(&fds) == -1) return openError(posix.errno(-1));
        for (fds) |fd| {
            if (c.fcntl(fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) == -1) {
                closeFd(fds[0]);
                closeFd(fds[1]);
                return posix.unexpectedErrno(posix.errno(-1));
            }
        }
    }
    errdefer closeFd(fds[1]);
    fds[0] = try aboveStdio(fds[0]);
    errdefer closeFd(fds[0]);
    fds[1] = try aboveStdio(fds[1]);
    return fds;
}

/// Moves a close-on-exec fd above 2, where the child's dup2 onto stdio
/// can't clobber it. A daemonized host may have closed its stdio, making
/// fresh fds land there.
fn aboveStdio(fd: posix.fd_t) SpawnError!posix.fd_t {
    if (fd > 2) return fd;
    defer closeFd(fd);
    const new = c.fcntl(fd, posix.F.DUPFD_CLOEXEC, @as(c_int, 3));
    if (new == -1) return openError(posix.errno(-1));
    return new;
}

/// One past the highest fd the child may have inherited, for closeFrom's
/// fallback.
fn maxFd() posix.fd_t {
    var limit: posix.rlimit = undefined;
    if (c.getrlimit(.NOFILE, &limit) != 0) return max_fd_limit;
    return @intCast(@min(limit.cur, max_fd_limit));
}

/// Async-signal-safe: no /proc or /dev/fd listing, which allocates.
fn closeFrom(first: posix.fd_t, max_fd: posix.fd_t) void {
    if (native_os == .linux) {
        const linux = std.os.linux;
        if (linux.errno(linux.close_range(first, std.math.maxInt(posix.fd_t), .{ .UNSHARE = false, .CLOEXEC = false })) == .SUCCESS) return;
    }
    var fd = first;
    while (fd < max_fd) : (fd += 1) _ = c.close(fd);
}

fn closeFd(fd: posix.fd_t) void {
    // Retrying close on EINTR may close an fd another thread just got.
    _ = c.close(fd);
}

// Declared here because std.c lacks them. All of libc proper on glibc
// (unlike openpty, in libutil before 2.34), musl and macOS.
const libc = struct {
    extern "c" fn posix_openpt(flags: posix.O) c_int;
    extern "c" fn grantpt(fd: posix.fd_t) c_int;
    extern "c" fn unlockpt(fd: posix.fd_t) c_int;
    extern "c" fn ptsname_r(fd: posix.fd_t, buf: [*]u8, len: usize) c_int;
    extern "c" fn getsid(pid: posix.pid_t) posix.pid_t;
    extern "c" fn tcgetsid(fd: posix.fd_t) posix.pid_t;
};

const testing = std.testing;

const test_size: Size = .{ .cols = 80, .rows = 24 };

/// Long enough for a loaded machine, short enough that a hung test fails.
const test_timeout_ms = 10_000;

fn testEnviron() !std.process.Environ.Map {
    var map: std.process.Environ.Map = .init(testing.allocator);
    errdefer map.deinit();
    try map.put("PATH", testing.environ.getPosix("PATH") orelse default_path);
    return map;
}

fn spawnTest(environ: *const std.process.Environ.Map, argv: []const []const u8) !Pty {
    return Pty.spawn(testing.allocator, .{ .argv = argv, .environ = environ, .size = test_size });
}

/// `Pty.wait` with a deadline, for children a broken Pty might leave
/// running (`deinit` kills them).
fn waitTest(pty: *Pty) !Term {
    const io = testing.io;
    const deadline = std.Io.Clock.awake.now(io).toMilliseconds() + test_timeout_ms;
    while (std.Io.Clock.awake.now(io).toMilliseconds() < deadline) {
        if (try pty.tryWait()) |term| return term;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    std.debug.print("timed out waiting for the child\n", .{});
    return error.Timeout;
}

/// What a test's program wrote, read with a deadline so a test that
/// waits for output that never comes fails instead of hanging.
const Output = struct {
    buf: [16 * 1024]u8 = undefined,
    len: usize = 0,
    eof: bool = false,

    fn bytes(out: *const Output) []const u8 {
        return out.buf[0..out.len];
    }

    fn readUntil(out: *Output, pty: *Pty, needle: []const u8) !void {
        while (std.mem.indexOf(u8, out.bytes(), needle) == null) {
            if (out.eof) {
                std.debug.print("expected \"{f}\" in \"{f}\"\n", .{ std.zig.fmtString(needle), std.zig.fmtString(out.bytes()) });
                return error.EndOfStream;
            }
            try out.readSome(pty);
        }
    }

    fn readToEnd(out: *Output, pty: *Pty) !void {
        while (!out.eof) try out.readSome(pty);
    }

    fn readSome(out: *Output, pty: *Pty) !void {
        const io = testing.io;
        const deadline = std.Io.Clock.awake.now(io).toMilliseconds() + test_timeout_ms;
        while (true) {
            const remaining = deadline - std.Io.Clock.awake.now(io).toMilliseconds();
            if (remaining <= 0) {
                std.debug.print("timed out with output \"{f}\"\n", .{std.zig.fmtString(out.bytes())});
                return error.Timeout;
            }
            var fds = [_]posix.pollfd{.{ .fd = pty.master, .events = posix.POLL.IN, .revents = 0 }};
            _ = c.poll(&fds, fds.len, @intCast(remaining));
            if (out.len == out.buf.len) return error.NoSpaceLeft;
            const n = pty.read(out.buf[out.len..]) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
            if (n == 0) out.eof = true;
            out.len += n;
            return;
        }
    }
};

test "a program's output arrives and its exit status is reported" {
    var environ = try testEnviron();
    defer environ.deinit();
    for ([_]struct { []const u8, u8 }{ .{ "printf hello", 0 }, .{ "printf hello; exit 3", 3 } }) |case| {
        const script, const status = case;
        var pty = try spawnTest(&environ, &.{ "/bin/sh", "-c", script });
        defer pty.deinit();
        var out: Output = .{};
        try out.readToEnd(&pty);
        try testing.expectEqualStrings("hello", out.bytes());
        try testing.expectEqual(Term{ .exited = status }, try waitTest(&pty));
        // Reaped once; asking again gets the same answer, not a waitpid.
        try testing.expectEqual(Term{ .exited = status }, try pty.tryWait());
        try testing.expectEqual(Term{ .exited = status }, try pty.wait());
    }
}

test "the program sees the initial size and later resizes" {
    var environ = try testEnviron();
    defer environ.deinit();
    {
        var pty = try spawnTest(&environ, &.{ "stty", "size" });
        defer pty.deinit();
        var out: Output = .{};
        try out.readToEnd(&pty);
        try testing.expectEqualStrings("24 80\r\n", out.bytes());
        try testing.expectEqual(Term{ .exited = 0 }, try waitTest(&pty));
    }

    var pty = try spawnTest(&environ, &.{
        "/bin/sh", "-c",
        \\trap 'stty size' WINCH
        \\echo ready
        \\while :; do sleep 0.05; done
    });
    defer pty.deinit();
    var out: Output = .{};
    try out.readUntil(&pty, "ready\r\n");
    try pty.resize(.{ .cols = 100, .rows = 30, .width_px = 1000, .height_px = 600 });
    try out.readUntil(&pty, "30 100\r\n");

    var ws: posix.winsize = undefined;
    try testing.expect(ioctl(pty.master, c.T.IOCGWINSZ, @intFromPtr(&ws)) == 0);
    try testing.expectEqual(posix.winsize{ .row = 30, .col = 100, .xpixel = 1000, .ypixel = 600 }, ws);

    pty.hangup();
    try testing.expectEqual(Term{ .signal = .HUP }, try waitTest(&pty));
}

test "input goes through the line discipline" {
    var environ = try testEnviron();
    defer environ.deinit();
    {
        var pty = try spawnTest(&environ, &.{ "head", "-n1" });
        defer pty.deinit();
        try pty.writeAll("hi there\n");
        var out: Output = .{};
        try out.readToEnd(&pty);
        // The tty's echo, then head's copy, both with ONLCR's \r.
        try testing.expectEqualStrings("hi there\r\nhi there\r\n", out.bytes());
        try testing.expectEqual(Term{ .exited = 0 }, try waitTest(&pty));
    }
    {
        // ^C reaches the foreground process group as SIGINT.
        var pty = try spawnTest(&environ, &.{"cat"});
        defer pty.deinit();
        try pty.writeAll("\x03");
        try testing.expectEqual(Term{ .signal = .INT }, try waitTest(&pty));
    }
}

test "the program starts with default signal dispositions and an empty mask" {
    var environ = try testEnviron();
    defer environ.deinit();
    // A host that ignores SIGINT and blocks SIGTERM must pass on neither.
    var ignore: posix.Sigaction = .{ .handler = .{ .handler = posix.SIG.IGN }, .mask = undefined, .flags = 0 };
    _ = c.sigemptyset(&ignore.mask);
    var old_action: posix.Sigaction = undefined;
    _ = c.sigaction(.INT, &ignore, &old_action);
    defer _ = c.sigaction(.INT, &old_action, null);
    var block: posix.sigset_t = undefined;
    _ = c.sigemptyset(&block);
    _ = c.sigaddset(&block, .TERM);
    var old_mask: posix.sigset_t = undefined;
    _ = c.pthread_sigmask(posix.SIG.BLOCK, &block, &old_mask);
    defer _ = c.pthread_sigmask(posix.SIG.SETMASK, &old_mask, &block);

    {
        var pty = try spawnTest(&environ, &.{"cat"});
        defer pty.deinit();
        try pty.writeAll("\x03");
        try testing.expectEqual(Term{ .signal = .INT }, try waitTest(&pty));
    }
    {
        var pty = try spawnTest(&environ, &.{ "sleep", "30" });
        defer pty.deinit();
        try pty.kill(.TERM);
        try testing.expectEqual(Term{ .signal = .TERM }, try waitTest(&pty));
    }

    // spawn restored the host's own mask.
    var mask: posix.sigset_t = undefined;
    _ = c.sigemptyset(&block);
    _ = c.pthread_sigmask(posix.SIG.BLOCK, &block, &mask);
    try testing.expectEqual(1, c.sigismember(&mask, .TERM));
    try testing.expectEqual(0, c.sigismember(&mask, .INT));
}

test "termios reads stay inside std's termios and see IUTF8" {
    var environ = try testEnviron();
    defer environ.deinit();
    var pty = try spawnTest(&environ, &.{"cat"});
    defer pty.deinit();
    const slave = try openFd(pty.ttyName(), .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true });
    defer closeFd(slave);

    // glibc's tcgetattr would overwrite the start of the canary.
    var guarded: extern struct { attrs: posix.termios, canary: [64]u8 } = .{ .attrs = undefined, .canary = @splat(0xaa) };
    try getAttrs(slave, &guarded.attrs);
    try testing.expectEqualSlices(u8, &@as([64]u8, @splat(0xaa)), &guarded.canary);
    try testing.expect(guarded.attrs.iflag.IUTF8);
}

test "the program leads a session with the pty as its controlling terminal" {
    var environ = try testEnviron();
    defer environ.deinit();
    var pty = try spawnTest(&environ, &.{
        "/bin/sh", "-c",
        \\tty
        \\echo ok >/dev/tty
        \\read line
    });
    defer pty.deinit();
    var out: Output = .{};
    try out.readUntil(&pty, "ok\r\n");
    try testing.expectEqualStrings(pty.ttyName(), std.mem.sliceTo(out.bytes(), '\r'));

    const pid = pty.pid.?;
    try testing.expectEqual(pid, libc.getsid(pid));
    try testing.expectEqual(pid, libc.tcgetsid(pty.master));

    try pty.writeAll("\n");
    try testing.expectEqual(Term{ .exited = 0 }, try waitTest(&pty));
}

test "spawn failures report the child's errno" {
    var environ = try testEnviron();
    defer environ.deinit();
    const cases = [_]struct { Options, SpawnError, Diagnostic }{
        .{
            .{ .argv = &.{"/nonexistent/tx-test"}, .environ = &environ, .size = test_size },
            error.FileNotFound,
            .{ .step = .exec, .errno = .NOENT },
        },
        .{
            .{ .argv = &.{"tx-no-such-program"}, .environ = &environ, .size = test_size },
            error.FileNotFound,
            .{ .step = .exec, .errno = .NOENT },
        },
        .{
            .{ .argv = &.{"/etc/passwd"}, .environ = &environ, .size = test_size },
            error.AccessDenied,
            .{ .step = .exec, .errno = .ACCES },
        },
        .{
            .{ .argv = &.{"/bin/sh"}, .environ = &environ, .cwd = .{ .path = "/nonexistent" }, .size = test_size },
            error.WorkingDirectoryNotFound,
            .{ .step = .chdir, .errno = .NOENT },
        },
    };
    for (cases) |case| {
        var options, const expected_error, const expected_diagnostic = case;
        var diagnostic: Diagnostic = undefined;
        options.diagnostic = &diagnostic;
        try testing.expectError(expected_error, Pty.spawn(testing.allocator, options));
        try testing.expectEqual(expected_diagnostic, diagnostic);
    }
    // The failed children were reaped.
    try testing.expectEqual(-1, c.waitpid(-1, null, posix.W.NOHANG));
    try testing.expectEqual(posix.E.CHILD, posix.errno(-1));
}

test "the program gets exactly the environment and cwd passed" {
    var environ = try testEnviron();
    defer environ.deinit();
    try environ.put("TX_TEST", "a b");
    var pty = try Pty.spawn(testing.allocator, .{
        .argv = &.{ "/bin/sh", "-c", "printf '%s|%s|%s' \"$TX_TEST\" \"${HOME-unset}\" \"$(pwd)\"" },
        .environ = &environ,
        .cwd = .{ .path = "/" },
        .size = test_size,
    });
    defer pty.deinit();
    var out: Output = .{};
    try out.readToEnd(&pty);
    try testing.expectEqualStrings("a b|unset|/", out.bytes());
    try testing.expectEqual(Term{ .exited = 0 }, try waitTest(&pty));
}

test "a program killed by a signal is reported as such" {
    var environ = try testEnviron();
    defer environ.deinit();
    var pty = try spawnTest(&environ, &.{ "sleep", "30" });
    defer pty.deinit();
    try pty.kill(.KILL);
    // SIGKILL can't be caught, so the blocking wait can't hang.
    try testing.expectEqual(Term{ .signal = .KILL }, try pty.wait());
    try testing.expectError(error.ProcessNotFound, pty.kill(.TERM));
}

test "no fds leak into the program" {
    var environ = try testEnviron();
    defer environ.deinit();
    // Inheritable fds the host might have: a low one and a high one.
    const null_fd = try openFd("/dev/null", .{ .ACCMODE = .RDWR });
    defer closeFd(null_fd);
    try testing.expectEqual(100, c.dup2(null_fd, 100));
    defer closeFd(100);

    const fd_dir = if (native_os == .linux) "/proc/self/fd" else "/dev/fd";
    var pty = try spawnTest(&environ, &.{ "ls", "-1", fd_dir });
    defer pty.deinit();
    var out: Output = .{};
    try out.readToEnd(&pty);
    try testing.expectEqual(Term{ .exited = 0 }, try waitTest(&pty));
    // stdio, and the fd ls reads the directory with.
    try testing.expectEqualStrings("0\r\n1\r\n2\r\n3\r\n", out.bytes());
}

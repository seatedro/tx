//! Starts a program on a new pty (Pty) or on three socketpairs (Pipes), and
//! waits for it. host.zig runs a Pty from its thread; server/exec.zig runs
//! commands without a terminal on Pipes. Between fork and exec the child makes
//! async-signal-safe calls on data startChild prepared, and reports the step
//! that failed and its errno over a close-on-exec pipe.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const posix = std.posix;
const c = std.c;
const native_os = builtin.os.tag;

pub const Term = std.process.Child.Term;

/// The pty's window size. width_px and height_px are 0 when unknown.
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
    argv: []const []const u8,
    /// The file to run when it differs from argv[0]. A name without a slash
    /// is searched for in environ's PATH, or in default_path when it has none.
    program: ?[]const u8 = null,
    environ: *const std.process.Environ.Map,
    cwd: std.process.Child.Cwd = .inherit,
    size: Size,
    /// Receives the step and errno of a failure in the child.
    diagnostic: ?*Diagnostic = null,
};

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
    SystemResources,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    FileNotFound,
    AccessDenied,
    InvalidExe,
    NameTooLong,
    WorkingDirectoryNotFound,
    Unexpected,
};

pub const ReadError = error{
    WouldBlock,
    SystemResources,
    Unexpected,
};

pub const WriteError = error{
    WouldBlock,
    BrokenPipe,
    SystemResources,
    Unexpected,
};

pub const WaitError = error{
    ProcessNotFound,
    Unexpected,
};

pub const KillError = posix.KillError;

pub const ResizeError = error{Unexpected};

/// A program running on a pty. Pty owns the master side.
pub const Pty = struct {
    /// Nonblocking. -1 after hangup.
    master: posix.fd_t,
    /// null once the program has been reaped, or waitpid has found it gone.
    /// term holds the status of a reaped program.
    pid: ?posix.pid_t,
    term: ?Term,
    tty_name_buf: [128]u8,
    tty_name_len: u8,
    /// On Darwin the parent keeps the slave open until the program has
    /// exited and the master is drained. Output still unread when the last
    /// slave fd closes is lost there.
    held_slave: posix.fd_t = -1,
    /// On Darwin, a kqueue that turns readable when the program exits; -1
    /// elsewhere.
    exit_fd: posix.fd_t = -1,

    /// Opens a pty and starts the program as a session leader with the pty as
    /// its controlling terminal. The program gets default signal dispositions,
    /// an empty signal mask, and no fds other than 0, 1 and 2.
    pub fn spawn(gpa: Allocator, options: Options) SpawnError!Pty {
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

        // ptsname_r fails with -1 and errno on some systems, and returns the
        // error number on others.
        switch (libc.ptsname_r(self.master, &self.tty_name_buf, self.tty_name_buf.len)) {
            0 => {},
            -1 => return openError(posix.errno(-1)),
            else => |err| return openError(@fromBackingInt(@intCast(err))),
        }
        self.tty_name_len = @intCast(std.mem.indexOfScalar(u8, &self.tty_name_buf, 0).?);

        const slave = try aboveStdio(try openFd(self.tty_name_buf[0..self.tty_name_len :0], .{
            .ACCMODE = .RDWR,
            .NOCTTY = true,
            .CLOEXEC = true,
        }));
        const hold = native_os.isDarwin();
        defer if (!hold) closeFd(slave);
        errdefer if (hold) closeFd(slave);

        // IUTF8 makes the line discipline erase whole UTF-8 characters.
        var attrs: posix.termios = undefined;
        try getAttrs(slave, &attrs);
        attrs.iflag.IUTF8 = true;
        try setAttrs(slave, &attrs);
        try self.resize(options.size);

        try setNonblocking(self.master);

        self.pid = try startChild(gpa, .{
            .argv = options.argv,
            .program = options.program,
            .environ = options.environ,
            .cwd = options.cwd,
            .diagnostic = options.diagnostic,
        }, .{ .pty = slave });
        if (hold) {
            self.held_slave = slave;
            self.exit_fd = watchExit(self.pid.?) catch |err| {
                closeFd(slave);
                self.held_slave = -1;
                return err;
            };
        }
        return self;
    }

    /// Returns 0 once every slave fd is closed and the output is drained.
    pub fn read(self: *Pty, buf: []u8) ReadError!usize {
        while (true) {
            const rc = c.read(self.master, buf.ptr, buf.len);
            switch (posix.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .INTR => continue,
                .AGAIN => {
                    // The program has exited and the master is drained.
                    // Closing the held slave lets the master reach end of file.
                    if (self.held_slave != -1 and childExited(self.exit_fd)) {
                        self.releaseSlave();
                        continue;
                    }
                    return error.WouldBlock;
                },
                // The master reports EIO once every slave fd is closed.
                .IO => return 0,
                .NOMEM, .NOBUFS => return error.SystemResources,
                else => |err| return posix.unexpectedErrno(err),
            }
        }
    }

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

    /// Blocks in poll while the pty's input queue is full.
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

    /// The kernel sends SIGWINCH to the pty's foreground process group when
    /// the size changes.
    pub fn resize(self: *Pty, size: Size) ResizeError!void {
        var ws = size.winsize();
        if (ioctl(self.master, tiocswinsz, @intFromPtr(&ws)) == -1) return posix.unexpectedErrno(posix.errno(-1));
    }

    pub fn ttyName(self: *const Pty) [:0]const u8 {
        return self.tty_name_buf[0..self.tty_name_len :0];
    }

    /// Fails with error.ProcessNotFound once the program has been reaped.
    pub fn kill(self: *Pty, sig: posix.SIG) KillError!void {
        return posix.kill(self.pid orelse return error.ProcessNotFound, sig);
    }

    /// Signals the process group the program leads.
    pub fn killGroup(self: *Pty, sig: posix.SIG) KillError!void {
        return posix.kill(-(self.pid orelse return error.ProcessNotFound), sig);
    }

    /// Blocks until the program exits, and reaps it.
    pub fn wait(self: *Pty) WaitError!Term {
        return (try self.reapChild(0)).?;
    }

    /// Reaps the program if it has exited. After that it returns the saved
    /// status.
    pub fn tryWait(self: *Pty) WaitError!?Term {
        return self.reapChild(posix.W.NOHANG);
    }

    /// Blocks until the program exits, and leaves it unreaped. Its pid stays
    /// valid for kill until wait or tryWait reaps it.
    pub fn waitExited(self: *const Pty) WaitError!void {
        return waitExitedPid(self.pid orelse return);
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

    /// Closes the master, which hangs up the pty. The program, as the pty's
    /// controlling process, gets SIGHUP.
    pub fn hangup(self: *Pty) void {
        if (self.master == -1) return;
        closeFd(self.master);
        self.master = -1;
        self.releaseSlave();
    }

    fn releaseSlave(self: *Pty) void {
        if (self.held_slave == -1) return;
        closeFd(self.held_slave);
        closeFd(self.exit_fd);
        self.held_slave = -1;
        self.exit_fd = -1;
    }

    /// Hangs up, and kills and reaps the program if it hasn't been reaped.
    pub fn deinit(self: *Pty) void {
        self.hangup();
        if (self.pid) |pid| {
            _ = c.kill(pid, .KILL);
            _ = reap(pid, 0) catch {};
        }
        self.* = undefined;
    }
};

pub const PipesOptions = struct {
    argv: []const []const u8,
    program: ?[]const u8 = null,
    environ: *const std.process.Environ.Map,
    cwd: std.process.Child.Cwd = .inherit,
    diagnostic: ?*Diagnostic = null,
};

/// A program whose stdin, stdout and stderr are unix socketpairs. They are
/// sockets so that xev.TCP, which reads and writes with recv and send, can
/// drive the parent's ends. The parent's ends are nonblocking.
pub const Pipes = struct {
    /// The parent's ends. -1 once closed.
    stdin: posix.fd_t,
    stdout: posix.fd_t,
    stderr: posix.fd_t,
    /// null once the program has been reaped, or waitpid has found it gone.
    /// term holds the status of a reaped program.
    pid: ?posix.pid_t,
    term: ?Term = null,

    /// Starts the program with default signal dispositions, an empty signal
    /// mask, and no fds other than 0, 1 and 2.
    pub fn spawn(gpa: Allocator, options: PipesOptions) SpawnError!Pipes {
        const stdin = try socketPair();
        defer closeFd(stdin[0]);
        errdefer closeFd(stdin[1]);
        const stdout = try socketPair();
        defer closeFd(stdout[1]);
        errdefer closeFd(stdout[0]);
        const stderr = try socketPair();
        defer closeFd(stderr[1]);
        errdefer closeFd(stderr[0]);
        for ([_]posix.fd_t{ stdin[1], stdout[0], stderr[0] }) |fd| try setNonblocking(fd);

        const pid = try startChild(gpa, .{
            .argv = options.argv,
            .program = options.program,
            .environ = options.environ,
            .cwd = options.cwd,
            .diagnostic = options.diagnostic,
        }, .{ .pipes = .{ stdin[0], stdout[1], stderr[1] } });
        return .{ .stdin = stdin[1], .stdout = stdout[0], .stderr = stderr[0], .pid = pid };
    }

    /// Closes one of stdin, stdout and stderr, and sets it to -1.
    pub fn close(self: *Pipes, fd: *posix.fd_t) void {
        _ = self;
        if (fd.* == -1) return;
        closeFd(fd.*);
        fd.* = -1;
    }

    pub fn kill(self: *Pipes, sig: posix.SIG) KillError!void {
        return posix.kill(self.pid orelse return error.ProcessNotFound, sig);
    }

    /// Blocks until the program exits, and leaves it unreaped for tryWait.
    pub fn waitExited(self: *const Pipes) WaitError!void {
        return waitExitedPid(self.pid orelse return);
    }

    /// Reaps the program if it has exited. After that it returns the saved
    /// status.
    pub fn tryWait(self: *Pipes) WaitError!?Term {
        const pid = self.pid orelse return self.term orelse error.ProcessNotFound;
        const term = reap(pid, posix.W.NOHANG) catch |err| {
            if (err == error.ProcessNotFound) self.pid = null;
            return err;
        };
        if (term != null) {
            self.pid = null;
            self.term = term;
        }
        return term;
    }

    /// Closes the parent's ends, and kills and reaps the program if it hasn't
    /// been reaped.
    pub fn deinit(self: *Pipes) void {
        self.close(&self.stdin);
        self.close(&self.stdout);
        self.close(&self.stderr);
        if (self.pid) |pid| {
            _ = c.kill(pid, .KILL);
            _ = reap(pid, 0) catch {};
        }
        self.* = undefined;
    }
};

const Program = struct {
    argv: []const []const u8,
    program: ?[]const u8,
    environ: *const std.process.Environ.Map,
    cwd: std.process.Child.Cwd,
    diagnostic: ?*Diagnostic,
};

fn startChild(gpa: Allocator, program: Program, stdio: Child.Stdio) SpawnError!posix.pid_t {
    assert(program.argv.len > 0);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = try arena.allocSentinel(?[*:0]const u8, program.argv.len, null);
    for (program.argv, argv) |arg, *ptr| ptr.* = (try arena.dupeSentinel(u8, arg, 0)).ptr;
    const envp = try program.environ.createPosixBlock(arena, .{});
    const path = try arena.dupeSentinel(u8, program.program orelse program.argv[0], 0);

    var child: Child = .{
        .argv = argv.ptr,
        .envp = envp.slice.ptr,
        .program = path,
        .search_path = if (std.mem.indexOfScalar(u8, path, '/') == null)
            program.environ.get("PATH") orelse default_path
        else
            null,
        .cwd = switch (program.cwd) {
            .inherit => .inherit,
            .dir => |dir| .{ .fd = dir.handle },
            .path => |p| .{ .path = try arena.dupeSentinel(u8, p, 0) },
        },
        .stdio = stdio,
        .err_fd = undefined,
        .max_fd = maxFd(),
        .default_action = .{ .handler = .{ .handler = posix.SIG.DFL }, .mask = undefined, .flags = 0 },
        .empty_mask = undefined,
    };
    _ = c.sigemptyset(&child.default_action.mask);
    _ = c.sigemptyset(&child.empty_mask);

    // The child writes a ChildError to the pipe when a step fails. The write
    // end is close-on-exec, so after a successful exec the parent reads end of
    // file.
    const err_pipe = try pipe();
    child.err_fd = err_pipe[1];

    // Signals stay blocked from fork until the child has reset their
    // dispositions, so no handler of this process runs in the child.
    var all_signals: posix.sigset_t = undefined;
    _ = c.sigfillset(&all_signals);
    var old_mask: posix.sigset_t = undefined;
    _ = c.pthread_sigmask(posix.SIG.SETMASK, &all_signals, &old_mask);
    const pid = c.fork();
    if (pid == 0) child.run();
    _ = c.pthread_sigmask(posix.SIG.SETMASK, &old_mask, &all_signals);

    closeFd(err_pipe[1]);
    defer closeFd(err_pipe[0]);
    if (pid == -1) return switch (posix.errno(-1)) {
        .AGAIN, .NOMEM => error.SystemResources,
        else => |err| posix.unexpectedErrno(err),
    };
    if (readChildError(err_pipe[0])) |failure| {
        _ = c.kill(pid, .KILL);
        _ = reap(pid, 0) catch {};
        if (program.diagnostic) |diagnostic| diagnostic.* = .{ .step = failure.step, .errno = failure.errno };
        return failure.toError();
    }
    return pid;
}

const default_path = "/usr/bin:/bin";

const max_fd_limit = 1 << 16;

extern "c" fn ioctl(fd: posix.fd_t, request: c_ulong, ...) c_int;

// std.c.T has no Darwin values for these.
const tiocsctty: c_ulong = if (native_os.isDarwin()) 0x20007461 else c.T.IOCSCTTY;
const tiocswinsz: c_ulong = if (native_os.isDarwin()) 0x80087467 else c.T.IOCSWINSZ;

/// What the child needs after fork, prepared by startChild. A child of a
/// multithreaded process may make async-signal-safe calls only, until it
/// execs, so run allocates nothing.
const Child = struct {
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    program: [:0]const u8,
    search_path: ?[]const u8,
    cwd: union(enum) {
        inherit,
        fd: posix.fd_t,
        path: [*:0]const u8,
    },
    stdio: Stdio,
    err_fd: posix.fd_t,
    max_fd: posix.fd_t,
    default_action: posix.Sigaction,
    empty_mask: posix.sigset_t,

    const Stdio = union(enum) {
        pty: posix.fd_t,
        pipes: [3]posix.fd_t,
    };

    fn run(child: *const Child) noreturn {
        switch (child.cwd) {
            .inherit => {},
            .fd => |fd| if (c.fchdir(fd) != 0) fail(child.err_fd, .chdir, posix.errno(-1)),
            .path => |path| if (c.chdir(path) != 0) fail(child.err_fd, .chdir, posix.errno(-1)),
        }

        if (c.setsid() == -1) fail(child.err_fd, .setsid, posix.errno(-1));
        switch (child.stdio) {
            .pty => |slave| {
                if (ioctl(slave, tiocsctty, @as(c_ulong, 0)) == -1)
                    fail(child.err_fd, .controlling_terminal, posix.errno(-1));
                for ([_]posix.fd_t{ 0, 1, 2 }) |fd| {
                    if (c.dup2(slave, fd) == -1) fail(child.err_fd, .stdio, posix.errno(-1));
                }
            },
            .pipes => |fds| for (fds, 0..) |from, to| {
                if (c.dup2(from, @intCast(to)) == -1) fail(child.err_fd, .stdio, posix.errno(-1));
            },
        }

        // The error pipe moves to fd 3 so that closeFrom can close every fd
        // above it. dup2 clears close-on-exec, and fcntl sets it again for
        // exec to close the pipe.
        const err_fd: posix.fd_t = 3;
        if (c.dup2(child.err_fd, err_fd) == -1) fail(child.err_fd, .stdio, posix.errno(-1));
        if (c.fcntl(err_fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) == -1)
            fail(err_fd, .stdio, posix.errno(-1));
        closeFrom(err_fd + 1, child.max_fd);

        // Ignored signals and the signal mask survive exec.
        var sig: u32 = 1;
        while (sig < posix.NSIG) : (sig += 1) {
            _ = c.sigaction(@fromBackingInt(sig), &child.default_action, null);
        }
        _ = c.sigprocmask(posix.SIG.SETMASK, &child.empty_mask, null);

        fail(err_fd, .exec, child.exec());
    }

    /// Returns the errno to report. As with execvp, EACCES from one directory
    /// of search_path wins over ENOENT from the others.
    fn exec(child: *const Child) posix.E {
        const search_path = child.search_path orelse {
            _ = c.execve(child.program, child.argv, child.envp);
            return posix.errno(-1);
        };
        var path_buf: [posix.PATH_MAX]u8 = undefined;
        var denied = false;
        var dirs = std.mem.splitScalar(u8, search_path, ':');
        while (dirs.next()) |entry| {
            // An empty PATH entry is the current directory.
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
        const child_err: ChildError = .{ .step = @backingInt(step), .errno = @intCast(@backingInt(err)) };
        const bytes = std.mem.asBytes(&child_err);
        while (posix.errno(c.write(fd, bytes, bytes.len)) == .INTR) {}
        c._exit(127);
    }
};

/// What the child writes to the error pipe when a step fails.
const ChildError = extern struct {
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

/// Returns null at end of file, which means exec succeeded.
fn readChildError(fd: posix.fd_t) ?ChildError.Failure {
    var child_err: ChildError = undefined;
    const bytes = std.mem.asBytes(&child_err);
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
        .step = std.enums.fromInt(Diagnostic.Step, child_err.step) orelse .exec,
        .errno = @fromBackingInt(@intCast(child_err.errno)),
    };
}

/// Returns a kqueue that reports the exit of pid. For a child that exited
/// before it could be watched, it holds a user event that is already
/// triggered.
fn watchExit(pid: posix.pid_t) SpawnError!posix.fd_t {
    if (comptime !native_os.isDarwin()) unreachable;
    const kq = c.kqueue();
    if (kq == -1) return openError(posix.errno(-1));
    errdefer closeFd(kq);
    if (c.fcntl(kq, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) == -1) return posix.unexpectedErrno(posix.errno(-1));

    const exit: c.Kevent = .{ .ident = @intCast(pid), .filter = c.EVFILT.PROC, .flags = c.EV.ADD, .fflags = c.NOTE.EXIT, .data = 0, .udata = 0 };
    if (c.kevent(kq, (&exit)[0..1], 1, (&exit)[0..0], 0, null) == 0) return kq;
    if (posix.errno(-1) != .SRCH) return posix.unexpectedErrno(posix.errno(-1));

    const exited: c.Kevent = .{ .ident = 0, .filter = c.EVFILT.USER, .flags = c.EV.ADD, .fflags = c.NOTE.TRIGGER, .data = 0, .udata = 0 };
    if (c.kevent(kq, (&exited)[0..1], 1, (&exited)[0..0], 0, null) == -1) return posix.unexpectedErrno(posix.errno(-1));
    return kq;
}

fn childExited(kq: posix.fd_t) bool {
    if (comptime !native_os.isDarwin()) return false;
    var event: c.Kevent = undefined;
    const zero: c.timespec = .{ .sec = 0, .nsec = 0 };
    return c.kevent(kq, (&event)[0..0], 0, (&event)[0..1], 1, &zero) > 0;
}

fn waitExitedPid(pid: posix.pid_t) WaitError!void {
    // Space for the siginfo_t waitid fills in. It isn't read.
    var info: [128]u8 align(8) = undefined;

    while (libc.waitid(p_pid, @intCast(pid), &info, w_exited | w_nowait) == -1) switch (posix.errno(-1)) {
        .INTR => {},
        .CHILD => return error.ProcessNotFound,
        else => |err| return posix.unexpectedErrno(err),
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
    // Linux's posix_openpt takes O_CLOEXEC. Elsewhere it is set after.
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

// posix.termios on Linux has the kernel's layout. glibc's tcgetattr and
// tcsetattr take a larger struct, so Linux uses the TCGETS and TCSETS ioctls.
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
        .AGAIN, .NOSPC, .NOMEM => error.SystemResources,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .ACCES, .PERM => error.AccessDenied,
        else => posix.unexpectedErrno(err),
    };
}

fn setNonblocking(fd: posix.fd_t) SpawnError!void {
    const flags = c.fcntl(fd, posix.F.GETFL);
    if (flags == -1) return posix.unexpectedErrno(posix.errno(-1));
    const nonblock: c_int = @bitCast(posix.O{ .NONBLOCK = true });
    if (c.fcntl(fd, posix.F.SETFL, flags | nonblock) == -1) return posix.unexpectedErrno(posix.errno(-1));
}

fn socketPair() SpawnError![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    const cloexec: u32 = if (native_os == .linux) posix.SOCK.CLOEXEC else 0;
    if (c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | cloexec, 0, &fds) != 0) return openError(posix.errno(-1));
    if (native_os != .linux) for (fds) |fd| {
        if (c.fcntl(fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) == -1) {
            closeFd(fds[0]);
            closeFd(fds[1]);
            return posix.unexpectedErrno(posix.errno(-1));
        }
    };
    errdefer closeFd(fds[1]);
    fds[0] = try aboveStdio(fds[0]);
    errdefer closeFd(fds[0]);
    fds[1] = try aboveStdio(fds[1]);
    return fds;
}

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

/// Moves fd above 2. The child dup2s its stdio fds onto 0, 1 and 2. A source
/// already at one of those could be overwritten by an earlier dup2, or keep
/// close-on-exec when dup2 copies it onto itself.
fn aboveStdio(fd: posix.fd_t) SpawnError!posix.fd_t {
    if (fd > 2) return fd;
    defer closeFd(fd);
    const new = c.fcntl(fd, posix.F.DUPFD_CLOEXEC, @as(c_int, 3));
    if (new == -1) return openError(posix.errno(-1));
    return new;
}

/// The soft RLIMIT_NOFILE, capped at max_fd_limit, for closeFrom.
pub fn maxFd() posix.fd_t {
    var limit: posix.rlimit = undefined;
    if (c.getrlimit(.NOFILE, &limit) != 0) return max_fd_limit;
    return @intCast(@min(limit.cur, max_fd_limit));
}

/// Closes every fd from first up. Without close_range it closes those below
/// max_fd. Forked children call it before exec, so it makes async-signal-safe
/// calls only.
pub fn closeFrom(first: posix.fd_t, max_fd: posix.fd_t) void {
    if (native_os == .linux) {
        const linux = std.os.linux;
        if (linux.errno(linux.close_range(first, std.math.maxInt(posix.fd_t), .{ .UNSHARE = false, .CLOEXEC = false })) == .SUCCESS) return;
    }
    var fd = first;
    while (fd < max_fd) : (fd += 1) _ = c.close(fd);
}

fn closeFd(fd: posix.fd_t) void {
    _ = c.close(fd);
}

const libc = struct {
    extern "c" fn posix_openpt(flags: posix.O) c_int;
    extern "c" fn grantpt(fd: posix.fd_t) c_int;
    extern "c" fn unlockpt(fd: posix.fd_t) c_int;
    extern "c" fn ptsname_r(fd: posix.fd_t, buf: [*]u8, len: usize) c_int;
    extern "c" fn getsid(pid: posix.pid_t) posix.pid_t;
    extern "c" fn tcgetsid(fd: posix.fd_t) posix.pid_t;
    extern "c" fn waitid(idtype: c_int, id: c_uint, info: *anyopaque, options: c_int) c_int;
};

// waitid's P_PID, WEXITED and WNOWAIT. std.c.W has no Darwin values for the
// flags.
const p_pid = 1;
const w_exited: c_int = if (native_os.isDarwin()) 0x4 else c.W.EXITED;
const w_nowait: c_int = if (native_os.isDarwin()) 0x20 else c.W.NOWAIT;

const testing = std.testing;

const test_size: Size = .{ .cols = 80, .rows = 24 };

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

fn waitTest(pty: *Pty) !Term {
    const io = testing.io;
    const deadline = std.Io.Clock.awake.now(io).toMilliseconds() + test_timeout_ms;
    while (std.Io.Clock.awake.now(io).toMilliseconds() < deadline) {
        if (try pty.tryWait()) |term| return term;

        var buf: [1024]u8 = undefined;
        if (pty.master != -1) while (c.read(pty.master, &buf, buf.len) > 0) {};
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    std.debug.print("timed out waiting for the child\n", .{});
    return error.Timeout;
}

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
            var fds = [_]posix.pollfd{
                .{ .fd = pty.master, .events = posix.POLL.IN, .revents = 0 },
                .{ .fd = pty.exit_fd, .events = posix.POLL.IN, .revents = 0 },
            };
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

test "output and exit status are reported" {
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
        try testing.expectEqual(Term{ .exited = status }, try pty.tryWait());
        try testing.expectEqual(Term{ .exited = status }, try pty.wait());
    }
}

test "output of a program that exits at once is read in full" {
    var environ = try testEnviron();
    defer environ.deinit();
    for (0..200) |_| {
        var pty = try spawnTest(&environ, &.{ "echo", "bye" });
        defer pty.deinit();
        var out: Output = .{};
        try out.readToEnd(&pty);
        try testing.expectEqualStrings("bye\r\n", out.bytes());
        try testing.expectEqual(Term{ .exited = 0 }, try waitTest(&pty));
    }
}

test "program sees the initial size and resizes" {
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
        try testing.expectEqualStrings("hi there\r\nhi there\r\n", out.bytes());
        try testing.expectEqual(Term{ .exited = 0 }, try waitTest(&pty));
    }
    {
        var pty = try spawnTest(&environ, &.{"cat"});
        defer pty.deinit();
        try pty.writeAll("\x03");
        try testing.expectEqual(Term{ .signal = .INT }, try waitTest(&pty));
    }
}

test "program starts with default signal dispositions and an empty mask" {
    var environ = try testEnviron();
    defer environ.deinit();
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

    var mask: posix.sigset_t = undefined;
    _ = c.sigemptyset(&block);
    _ = c.pthread_sigmask(posix.SIG.BLOCK, &block, &mask);
    try testing.expectEqual(1, c.sigismember(&mask, .TERM));
    try testing.expectEqual(0, c.sigismember(&mask, .INT));
}

test "getAttrs doesn't overrun termios and IUTF8 is set" {
    var environ = try testEnviron();
    defer environ.deinit();
    var pty = try spawnTest(&environ, &.{"cat"});
    defer pty.deinit();
    const slave = try openFd(pty.ttyName(), .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true });
    defer closeFd(slave);

    var guarded: extern struct { attrs: posix.termios, canary: [64]u8 } = .{ .attrs = undefined, .canary = @splat(0xaa) };
    try getAttrs(slave, &guarded.attrs);
    try testing.expectEqualSlices(u8, &@as([64]u8, @splat(0xaa)), &guarded.canary);
    try testing.expect(guarded.attrs.iflag.IUTF8);
}

test "program is a session leader with the pty as controlling terminal" {
    var environ = try testEnviron();
    defer environ.deinit();
    var pty = try spawnTest(&environ, &.{
        "/bin/sh", "-c",
        \\printf '%s\n' "$(tty)"
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
    try testing.expectEqual(-1, c.waitpid(-1, null, posix.W.NOHANG));
    try testing.expectEqual(posix.E.CHILD, posix.errno(-1));
}

test "program gets the given environment and cwd" {
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

test "killed program reports the signal" {
    var environ = try testEnviron();
    defer environ.deinit();
    var pty = try spawnTest(&environ, &.{ "sleep", "30" });
    defer pty.deinit();
    try pty.kill(.KILL);
    try testing.expectEqual(Term{ .signal = .KILL }, try pty.wait());
    try testing.expectError(error.ProcessNotFound, pty.kill(.TERM));
}

test "no fds leak into the program" {
    var environ = try testEnviron();
    defer environ.deinit();
    const null_fd = try openFd("/dev/null", .{ .ACCMODE = .RDWR });
    defer closeFd(null_fd);
    try testing.expectEqual(100, c.dup2(null_fd, 100));
    defer closeFd(100);

    var pty = try spawnTest(&environ, &.{ "/bin/sh", "-c", "for fd in 3 4 5 6 7 8 9 100; do if (: <&$fd) 2>/dev/null; then echo $fd; fi; done; echo end" });
    defer pty.deinit();
    var out: Output = .{};
    try out.readToEnd(&pty);
    try testing.expectEqual(Term{ .exited = 0 }, try waitTest(&pty));
    try testing.expectEqualStrings("end\r\n", out.bytes());
}

fn readPipeToEnd(fd: posix.fd_t, out: *std.ArrayList(u8)) !void {
    var buf: [1024]u8 = undefined;
    while (true) {
        var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
        if (c.poll(&fds, fds.len, test_timeout_ms) == 0) return error.Timeout;
        const rc = c.read(fd, &buf, buf.len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return;
                try out.appendSlice(testing.allocator, buf[0..@intCast(rc)]);
            },
            .INTR, .AGAIN => {},
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

test "a program on pipes reads its stdin, and writes stdout and stderr apart" {
    var environ = try testEnviron();
    defer environ.deinit();
    var pipes: Pipes = try .spawn(testing.allocator, .{
        .argv = &.{ "/bin/sh", "-c", "read line; echo \"got $line\"; echo oops >&2; exit 4" },
        .environ = &environ,
    });
    defer pipes.deinit();

    try testing.expectEqual(5, c.write(pipes.stdin, "data\n", 5));
    pipes.close(&pipes.stdin);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    var err: std.ArrayList(u8) = .empty;
    defer err.deinit(testing.allocator);
    try readPipeToEnd(pipes.stdout, &out);
    try readPipeToEnd(pipes.stderr, &err);

    try pipes.waitExited();
    try testing.expectEqual(Term{ .exited = 4 }, (try pipes.tryWait()).?);
    try testing.expectEqualStrings("got data\n", out.items);
    try testing.expectEqualStrings("oops\n", err.items);
}

test "a program on pipes gets SIGPIPE once its stdout is closed" {
    const ignore: posix.Sigaction = .{ .handler = .{ .handler = posix.SIG.IGN }, .mask = posix.sigemptyset(), .flags = 0 };
    var old: posix.Sigaction = undefined;
    _ = c.sigaction(.PIPE, &ignore, &old);
    defer _ = c.sigaction(.PIPE, &old, null);

    var environ = try testEnviron();
    defer environ.deinit();
    var pipes: Pipes = try .spawn(testing.allocator, .{
        .argv = &.{ "/bin/sh", "-c", "while :; do echo y; done" },
        .environ = &environ,
    });
    defer pipes.deinit();
    pipes.close(&pipes.stdout);

    try pipes.waitExited();
    try testing.expectEqual(Term{ .signal = .PIPE }, (try pipes.tryWait()).?);
}

//! Starts a session process (see `process`), detached from txd.
//!
//! The process runs in a session of its own, and isn't txd's child: an
//! intermediate child starts it and exits. It outlives txd, and a service
//! manager stopping txd leaves it running. Its stdin and stdout are
//! /dev/null, and its stderr is txd's unless the caller gives another, so
//! that its log goes where txd's does. Its environment is empty; `Start`
//! carries the program's.
const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const c = std.c;
const pty = @import("pty.zig");

/// The fd the session process gets its socket on.
pub const socket_fd = 3;

pub const Error = error{
    OutOfMemory,
    /// Out of processes or fds.
    SystemResources,
    /// The executable is missing, or can't run.
    FileNotFound,
    AccessDenied,
    Unexpected,
};

/// Runs `exe --session --fd 3` with `socket` as fd 3, and returns once it
/// has exec'd. `exe` is txd. `socket` and `stderr` stay open in the caller.
pub fn spawn(gpa: Allocator, exe: []const u8, socket: posix.fd_t, stderr: ?posix.fd_t) Error!void {
    const exe_z = try gpa.dupeSentinel(u8, exe, 0);
    defer gpa.free(exe_z);
    const argv = [_:null]?[*:0]const u8{ "txd", "--session", "--fd", "3" };
    const envp = [_:null]?[*:0]const u8{};

    // Both above 4, so that the dup2s onto 3 and 4 don't clobber them.
    const link = try dupAbove(socket, 5);
    defer _ = c.close(link);
    const log_fd = if (stderr) |fd| try dupAbove(fd, 5) else null;
    defer if (log_fd) |fd| {
        _ = c.close(fd);
    };
    const err_pipe = try pipe();
    defer _ = c.close(err_pipe[0]);
    const err_fd = dupAbove(err_pipe[1], 5) catch |err| {
        _ = c.close(err_pipe[1]);
        return err;
    };
    _ = c.close(err_pipe[1]);

    var child: Child = .{
        .exe = exe_z,
        .argv = &argv,
        .envp = &envp,
        .link = link,
        .log_fd = log_fd,
        .err_fd = err_fd,
        .max_fd = pty.maxFd(),
        .default_action = .{ .handler = .{ .handler = posix.SIG.DFL }, .mask = undefined, .flags = 0 },
        .empty_mask = undefined,
    };
    _ = c.sigemptyset(&child.default_action.mask);
    _ = c.sigemptyset(&child.empty_mask);

    // As in `pty.Pty.spawn`: no handler of txd's runs in the child.
    var all_signals: posix.sigset_t = undefined;
    _ = c.sigfillset(&all_signals);
    var old_mask: posix.sigset_t = undefined;
    _ = c.pthread_sigmask(posix.SIG.SETMASK, &all_signals, &old_mask);
    const pid = c.fork();
    if (pid == 0) child.run();
    _ = c.pthread_sigmask(posix.SIG.SETMASK, &old_mask, &all_signals);
    _ = c.close(err_fd);
    if (pid == -1) return spawnError(posix.errno(-1));

    // The intermediate child exits as soon as it has forked.
    var status: c_int = 0;
    while (c.waitpid(pid, &status, 0) == -1) switch (posix.errno(-1)) {
        .INTR => {},
        else => |err| return posix.unexpectedErrno(err),
    };
    if (posix.W.EXITSTATUS(@bitCast(status)) != 0) return error.SystemResources;

    // The session process closes the pipe when it execs, or writes the
    // errno of what failed.
    var errno: u32 = undefined;
    const n = while (true) {
        const rc = c.read(err_pipe[0], std.mem.asBytes(&errno), @sizeOf(u32));
        if (rc >= 0) break @as(usize, @intCast(rc));
        if (posix.errno(rc) != .INTR) return posix.unexpectedErrno(posix.errno(rc));
    };
    if (n == 0) return;
    return spawnError(@fromBackingInt(@intCast(errno)));
}

/// Runs in the children, between fork and exec. Only async-signal-safe
/// calls, as in `pty`.
const Child = struct {
    exe: [*:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    link: posix.fd_t,
    log_fd: ?posix.fd_t,
    err_fd: posix.fd_t,
    max_fd: posix.fd_t,
    default_action: posix.Sigaction,
    empty_mask: posix.sigset_t,

    fn run(child: *const Child) noreturn {
        // A session of its own: no terminal's hangup or job control signal
        // reaches it.
        if (c.setsid() == -1) child.fail();

        // The grandchild is the session process. Its parent exits, and it
        // is reparented to init.
        switch (c.fork()) {
            0 => {},
            -1 => c._exit(1),
            else => c._exit(0),
        }

        // Out of any directory that might be unmounted.
        _ = c.chdir("/");

        const null_fd = c.open("/dev/null", .{ .ACCMODE = .RDWR });
        if (null_fd == -1) child.fail();
        for ([_]posix.fd_t{ 0, 1 }) |fd| if (c.dup2(null_fd, fd) == -1) child.fail();
        if (child.log_fd) |fd| if (c.dup2(fd, 2) == -1) child.fail();
        if (c.dup2(child.link, socket_fd) == -1) child.fail();
        // The error pipe moves to 4 and closes on exec.
        const err_fd: posix.fd_t = socket_fd + 1;
        if (c.dup2(child.err_fd, err_fd) == -1) child.fail();
        if (c.fcntl(err_fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) == -1) child.fail();
        pty.closeFrom(err_fd + 1, child.max_fd);

        // txd ignores SIGPIPE and blocks signals; neither should carry over.
        var sig: u32 = 1;
        while (sig < posix.NSIG) : (sig += 1) {
            _ = c.sigaction(@fromBackingInt(sig), &child.default_action, null);
        }
        _ = c.sigprocmask(posix.SIG.SETMASK, &child.empty_mask, null);

        _ = c.execve(child.exe, child.argv, child.envp);
        failTo(err_fd);
    }

    fn fail(child: *const Child) noreturn {
        failTo(child.err_fd);
    }

    fn failTo(fd: posix.fd_t) noreturn {
        const errno: u32 = @intCast(@backingInt(posix.errno(-1)));
        // Smaller than PIPE_BUF, so the write is atomic.
        while (posix.errno(c.write(fd, std.mem.asBytes(&errno), @sizeOf(u32))) == .INTR) {}
        c._exit(127);
    }
};

/// A close-on-exec pipe. macOS has no pipe2; there, a thread that forks
/// between pipe and fcntl inherits the pipe.
fn pipe() Error![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    if (@TypeOf(c.pipe2) != void) {
        if (c.pipe2(&fds, .{ .CLOEXEC = true }) == -1) return spawnError(posix.errno(-1));
        return fds;
    }
    if (c.pipe(&fds) == -1) return spawnError(posix.errno(-1));
    for (fds) |fd| _ = c.fcntl(fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC));
    return fds;
}

/// A close-on-exec copy of `fd` at `min` or above.
fn dupAbove(fd: posix.fd_t, min: posix.fd_t) Error!posix.fd_t {
    const new = c.fcntl(fd, posix.F.DUPFD_CLOEXEC, @as(c_int, min));
    if (new == -1) return spawnError(posix.errno(-1));
    return new;
}

fn spawnError(err: posix.E) Error {
    return switch (err) {
        .AGAIN, .NOMEM, .MFILE, .NFILE => error.SystemResources,
        .NOENT, .NOTDIR, .NOEXEC => error.FileNotFound,
        .ACCES, .PERM => error.AccessDenied,
        else => posix.unexpectedErrno(err),
    };
}

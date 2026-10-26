//! Uses libc only; supports Linux (glibc and musl) and macOS.
const std = @import("std");
const posix = std.posix;
const c = std.c;

/// A non-blocking, close-on-exec pipe that wakes a thread from poll.
pub const Wake = struct {
    read_fd: posix.fd_t,
    write_fd: posix.fd_t,

    pub fn init() error{ ProcessFdQuotaExceeded, SystemFdQuotaExceeded, Unexpected }!Wake {
        var fds: [2]posix.fd_t = undefined;
        const rc = if (@TypeOf(c.pipe2) != void)
            c.pipe2(&fds, .{ .CLOEXEC = true, .NONBLOCK = true })
        else
            c.pipe(&fds);
        if (rc == -1) return switch (posix.errno(-1)) {
            .MFILE => error.ProcessFdQuotaExceeded,
            .NFILE => error.SystemFdQuotaExceeded,
            else => |err| posix.unexpectedErrno(err),
        };
        // macOS has no pipe2.
        if (@TypeOf(c.pipe2) == void) {
            const nonblock: c_int = @bitCast(posix.O{ .NONBLOCK = true });
            for (fds) |fd| {
                if (c.fcntl(fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) == -1 or
                    c.fcntl(fd, posix.F.SETFL, nonblock) == -1)
                {
                    const err = posix.errno(-1);
                    closeFd(fds[0]);
                    closeFd(fds[1]);
                    return posix.unexpectedErrno(err);
                }
            }
        }
        return .{ .read_fd = fds[0], .write_fd = fds[1] };
    }

    pub fn deinit(wake: *Wake) void {
        closeFd(wake.read_fd);
        closeFd(wake.write_fd);
        wake.* = undefined;
    }

    /// A full pipe already wakes the reader, so EAGAIN is ignored.
    pub fn notify(wake: *Wake) void {
        const byte = [1]u8{0};
        while (posix.errno(c.write(wake.write_fd, &byte, 1)) == .INTR) {}
    }

    pub fn drain(wake: *Wake) void {
        var buf: [64]u8 = undefined;
        while (true) {
            const rc = c.read(wake.read_fd, &buf, buf.len);
            switch (posix.errno(rc)) {
                .SUCCESS => if (rc < buf.len) return,
                .INTR => {},
                else => return,
            }
        }
    }
};

fn closeFd(fd: posix.fd_t) void {
    // Don't retry on EINTR: the fd may already be closed and reused by
    // another thread.
    _ = c.close(fd);
}

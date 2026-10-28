//! Unix stream sockets between txd and its session processes, set up for
//! the loop: close-on-exec, blocking on io_uring and non-blocking on other
//! backends, as libxev's own sockets are.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const c = std.c;
const xev = @import("xev");
const native_os = builtin.os.tag;

/// Each socket's send and receive buffer. macOS gives Unix sockets 8 KiB.
const buffer_size = 256 << 10;

pub const Error = error{
    /// The path doesn't fit in `sockaddr.un`.
    NameTooLong,
    AddressInUse,
    /// No socket at the path.
    FileNotFound,
    /// Nothing listens on the socket: its process ended.
    ConnectionRefused,
    /// The listener's backlog is full: its process isn't accepting.
    WouldBlock,
    AccessDenied,
    SystemResources,
    Unexpected,
};

/// Ignores SIGPIPE. A write to a socket whose peer closed it fails with
/// EPIPE, and doesn't end the process.
pub fn ignoreSigpipe() void {
    var action: posix.Sigaction = .{ .handler = .{ .handler = posix.SIG.IGN }, .mask = undefined, .flags = 0 };
    _ = c.sigemptyset(&action.mask);
    _ = c.sigaction(.PIPE, &action, null);
}

/// A connected pair.
pub fn pair() Error![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    if (c.socketpair(posix.AF.UNIX, socketType(), 0, &fds) != 0) return socketError(posix.errno(-1));
    errdefer for (fds) |fd| close(fd);
    for (fds) |fd| try prepare(fd);
    return fds;
}

/// Listens on a new socket at `path`.
pub fn listen(path: []const u8) Error!posix.fd_t {
    const address = try unixAddress(path);
    const fd = try socket();
    errdefer close(fd);
    if (c.bind(fd, @ptrCast(&address), @sizeOf(c.sockaddr.un)) != 0) return socketError(posix.errno(-1));
    if (c.listen(fd, 16) != 0) return socketError(posix.errno(-1));
    return fd;
}

/// Connects to the socket at `path`. A local connect completes at once, or
/// fails.
pub fn connect(path: []const u8) Error!posix.fd_t {
    const address = try unixAddress(path);

    // Non-blocking, so that a full backlog fails instead of waiting.
    const fd = c.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    if (fd == -1) return socketError(posix.errno(-1));
    errdefer close(fd);
    try setNonblocking(fd, true);
    while (c.connect(fd, @ptrCast(&address), @sizeOf(c.sockaddr.un)) != 0) switch (posix.errno(-1)) {
        .INTR => {},
        .AGAIN, .INPROGRESS => return error.WouldBlock,
        else => |err| return socketError(err),
    };
    try prepare(fd);
    return fd;
}

/// Sets up a socket from elsewhere: one the loop accepted on a listener
/// from `listen`, or one the process inherited.
pub fn adopt(fd: posix.fd_t) Error!void {
    return prepare(fd);
}

/// The user ID of the process on the other end of a connected socket.
pub fn peerUid(fd: posix.fd_t) Error!posix.uid_t {
    if (native_os == .linux) {
        const Ucred = extern struct { pid: posix.pid_t, uid: posix.uid_t, gid: posix.gid_t };
        var cred: Ucred = undefined;
        var len: posix.socklen_t = @sizeOf(Ucred);
        if (c.getsockopt(fd, posix.SOL.SOCKET, posix.SO.PEERCRED, &cred, &len) != 0) return socketError(posix.errno(-1));
        return cred.uid;
    }
    var uid: posix.uid_t = undefined;
    var gid: posix.gid_t = undefined;
    if (getpeereid(fd, &uid, &gid) != 0) return socketError(posix.errno(-1));
    return uid;
}

extern "c" fn getpeereid(fd: posix.fd_t, uid: *posix.uid_t, gid: *posix.gid_t) c_int;

/// Only the user running txd may talk to its sessions.
pub fn acceptsPeer(peer: posix.uid_t, self: posix.uid_t) bool {
    return peer == self;
}

pub fn close(fd: posix.fd_t) void {
    _ = c.close(fd);
}

fn socket() Error!posix.fd_t {
    const fd = c.socket(posix.AF.UNIX, socketType(), 0);
    if (fd == -1) return socketError(posix.errno(-1));
    errdefer close(fd);
    try prepare(fd);
    return fd;
}

/// macOS takes no flags in the type. There, a thread that forks before
/// `prepare` inherits the socket.
fn socketType() c_uint {
    return if (native_os == .linux) posix.SOCK.STREAM | posix.SOCK.CLOEXEC else posix.SOCK.STREAM;
}

/// Close-on-exec, the loop's blocking mode, and larger buffers.
fn prepare(fd: posix.fd_t) Error!void {
    if (c.fcntl(fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) == -1) return socketError(posix.errno(-1));
    // io_uring waits for the socket itself. A non-blocking socket would
    // complete its reads with EAGAIN.
    try setNonblocking(fd, xev.backend != .io_uring);
    const size: c_int = buffer_size;
    for ([_]u32{ posix.SO.SNDBUF, posix.SO.RCVBUF }) |option| {
        _ = c.setsockopt(fd, posix.SOL.SOCKET, option, &size, @sizeOf(c_int));
    }
}

fn setNonblocking(fd: posix.fd_t, on: bool) Error!void {
    const flags = c.fcntl(fd, posix.F.GETFL);
    if (flags == -1) return socketError(posix.errno(-1));
    const nonblock: c_int = @bitCast(posix.O{ .NONBLOCK = true });
    const new = if (on) flags | nonblock else flags & ~nonblock;
    if (new != flags and c.fcntl(fd, posix.F.SETFL, new) == -1) return socketError(posix.errno(-1));
}

fn unixAddress(path: []const u8) Error!c.sockaddr.un {
    var address: c.sockaddr.un = .{ .family = posix.AF.UNIX, .path = @splat(0) };
    // The path is NUL-terminated within `path`.
    if (path.len >= address.path.len) return error.NameTooLong;
    @memcpy(address.path[0..path.len], path);
    return address;
}

fn socketError(err: posix.E) Error {
    return switch (err) {
        .ADDRINUSE => error.AddressInUse,
        .NOENT, .NOTDIR => error.FileNotFound,
        .CONNREFUSED => error.ConnectionRefused,
        .ACCES, .PERM => error.AccessDenied,
        .NAMETOOLONG => error.NameTooLong,
        .MFILE, .NFILE, .NOBUFS, .NOMEM => error.SystemResources,
        else => posix.unexpectedErrno(err),
    };
}

const testing = std.testing;

test "a connection reaches the listener, and the peer is this user" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = buf[0..try tmp.dir.realPath(testing.io, &buf)];
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/s.sock", .{dir});

    const listener = try listen(path);
    defer close(listener);
    try testing.expectError(error.AddressInUse, listen(path));

    const client = try connect(path);
    defer close(client);
    // The connection is waiting, so this doesn't block.
    const server = c.accept(listener, null, null);
    try testing.expect(server != -1);
    defer close(server);
    try adopt(server);
    try testing.expectEqual(c.getuid(), try peerUid(server));
    try testing.expect(acceptsPeer(try peerUid(client), c.getuid()));
    try testing.expect(!acceptsPeer(c.getuid() +% 1, c.getuid()));

    try testing.expectError(error.FileNotFound, connect(path[0 .. path.len - 1]));
}

test "a connection to a closed listener is refused" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = buf[0..try tmp.dir.realPath(testing.io, &buf)];
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/s.sock", .{dir});

    close(try listen(path));
    try testing.expectError(error.ConnectionRefused, connect(path));
    try testing.expectError(error.NameTooLong, connect(&@as([200]u8, @splat('a'))));
}

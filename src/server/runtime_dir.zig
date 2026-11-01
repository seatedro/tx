//! The runtime directory holds one unix socket per session, `{id}.sock`. A
//! session process listens on the path that Start.socket_path gives it and
//! unlinks it when it stops listening. txd finds sessions by listing the
//! names.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const posix = std.posix;
const c = std.c;

pub const Error = error{
    InsecureRuntimeDir,
    NameTooLong,
    Unexpected,
} || Io.Dir.CreateDirPathError;

/// Creates any missing parents, then the directory with mode 0700. Fails with
/// InsecureRuntimeDir unless it is a directory of this user's that group and
/// others can't reach.
pub fn prepare(io: Io, path: []const u8) Error!void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_z = try terminated(&buf, path);
    if (std.fs.path.dirname(path)) |parent| try Io.Dir.cwd().createDirPath(io, parent);
    if (c.mkdir(path_z, 0o700) != 0) switch (posix.errno(-1)) {
        .EXIST => {},
        else => |err| return posix.unexpectedErrno(err),
    };
    if (!(try secure(path_z))) return error.InsecureRuntimeDir;
}

fn secure(path: [*:0]const u8) Error!bool {
    // std.c has no Stat on Linux.
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var st: linux.Statx = undefined;
        const rc = linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true, .MODE = true, .UID = true }, &st);
        if (linux.errno(rc) != .SUCCESS) return posix.unexpectedErrno(linux.errno(rc));
        return checkMode(st.mode, st.uid, c.getuid());
    }
    var st: c.Stat = undefined;
    if (c.stat(path, &st) != 0) return posix.unexpectedErrno(posix.errno(-1));
    return checkMode(st.mode, st.uid, c.getuid());
}

pub fn checkMode(mode: posix.mode_t, owner: posix.uid_t, uid: posix.uid_t) bool {
    return posix.S.ISDIR(mode) and owner == uid and mode & 0o077 == 0;
}

/// The path session id's process listens on, written into buf.
pub fn socketPath(buf: []u8, dir: []const u8, id: u64) error{NameTooLong}![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{d}.sock", .{ dir, id }) catch error.NameTooLong;
}

/// The IDs of the sockets in the directory, in ascending order. The caller
/// frees the slice.
pub fn ids(gpa: Allocator, io: Io, path: []const u8) ![]u64 {
    var dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    var list: std.ArrayList(u64) = .empty;
    errdefer list.deinit(gpa);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (parseName(entry.name)) |id| try list.append(gpa, id);
    }
    std.mem.sortUnstable(u64, list.items, {}, std.sort.asc(u64));
    return list.toOwnedSlice(gpa);
}

pub fn parseName(name: []const u8) ?u64 {
    const digits = name[0 .. std.mem.indexOf(u8, name, ".sock") orelse return null];
    if (digits.len == 0 or digits.len + ".sock".len != name.len) return null;
    // IDs start at 1, and socketPath writes no leading zeros.
    if (digits[0] == '0') return null;
    return std.fmt.parseInt(u64, digits, 10) catch null;
}

/// Unlinks session id's socket, for a socket whose process is gone.
pub fn remove(dir: []const u8, id: u64) void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = socketPath(buf[0 .. buf.len - 1], dir, id) catch return;
    buf[path.len] = 0;
    _ = c.unlink(buf[0..path.len :0]);
}

fn terminated(buf: []u8, path: []const u8) error{NameTooLong}![:0]const u8 {
    if (path.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0];
}

const testing = std.testing;

test "a socket's name is its ID" {
    try testing.expectEqual(7, parseName("7.sock"));
    try testing.expectEqual(1234, parseName("1234.sock"));
    for ([_][]const u8{ ".sock", "07.sock", "7.sock.part", "x.sock", "7", "7.socks", "-1.sock" }) |name| {
        try testing.expectEqual(null, parseName(name));
    }
}

test "only a directory of the user's own, closed to others, is used" {
    const uid = c.getuid();
    try testing.expect(checkMode(posix.S.IFDIR | 0o700, uid, uid));
    try testing.expect(!checkMode(posix.S.IFDIR | 0o750, uid, uid));
    try testing.expect(!checkMode(posix.S.IFDIR | 0o701, uid, uid));
    try testing.expect(!checkMode(posix.S.IFDIR | 0o700, uid +% 1, uid));
    try testing.expect(!checkMode(posix.S.IFREG | 0o600, uid, uid));

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const base = buf[0..try tmp.dir.realPath(testing.io, &buf)];
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/a/run", .{base});

    try prepare(testing.io, path);
    try prepare(testing.io, path);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a/run/3.sock", .data = "" });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a/run/12.sock", .data = "" });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a/run/other", .data = "" });
    const found = try ids(testing.allocator, testing.io, path);
    defer testing.allocator.free(found);
    try testing.expectEqualSlices(u64, &.{ 3, 12 }, found);

    var z_buf: [std.fs.max_path_bytes]u8 = undefined;
    try testing.expectEqual(0, c.chmod(try terminated(&z_buf, path), 0o750));
    try testing.expectError(error.InsecureRuntimeDir, prepare(testing.io, path));
}

//! The host and user ssh would log in to, from `ssh -G`, which prints the
//! configuration ssh uses for a destination. tx connects to that
//! `HostName` as that `User`, so `tx HOST` reaches the host `ssh HOST`
//! does, with `Include`, `Match` and `%` tokens read as ssh reads them.
//!
//! ssh's port is sshd's, so tx doesn't take it.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Resolved = struct {
    hostname: ?[]const u8 = null,
    user: ?[]const u8 = null,
};

/// Runs `ssh OPTIONS -G [-l USER] -- HOST`. Empty when ssh can't run or
/// fails, so that tx falls back to the destination as given.
pub fn resolve(arena: Allocator, io: Io, ssh: []const u8, options: []const []const u8, user: ?[]const u8, host: []const u8) Resolved {
    var argv: std.ArrayList([]const u8) = .empty;
    argv.append(arena, ssh) catch return .{};
    argv.appendSlice(arena, options) catch return .{};
    argv.append(arena, "-G") catch return .{};
    if (user) |u| argv.appendSlice(arena, &.{ "-l", u }) catch return .{};
    argv.appendSlice(arena, &.{ "--", host }) catch return .{};

    const result = std.process.run(arena, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(64 << 10),
        .stderr_limit = .limited(4096),
    }) catch return .{};
    if (!result.term.success()) return .{};
    return parse(result.stdout);
}

/// The `hostname` and `user` lines of `ssh -G`'s output, which has a
/// `key value` line per option.
pub fn parse(output: []const u8) Resolved {
    var resolved: Resolved = .{};
    var lines = std.mem.tokenizeScalar(u8, output, '\n');
    while (lines.next()) |line| {
        const space = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
        const key = line[0..space];
        const value = std.mem.trim(u8, line[space + 1 ..], " \r");
        if (value.len == 0) continue;

        if (std.mem.eql(u8, key, "hostname")) {
            resolved.hostname = value;
        } else if (std.mem.eql(u8, key, "user")) {
            resolved.user = value;
        }
    }
    return resolved;
}

test parse {
    const resolved = parse(
        \\host pulsar
        \\user rohit
        \\hostname pulsar.tail87c919.ts.net
        \\port 22
        \\identityfile ~/.ssh/id_ed25519
        \\
    );
    try std.testing.expectEqualStrings("pulsar.tail87c919.ts.net", resolved.hostname.?);
    try std.testing.expectEqualStrings("rohit", resolved.user.?);

    const empty = parse("port 22\nuser \n");
    try std.testing.expectEqual(null, empty.hostname);
    try std.testing.expectEqual(null, empty.user);
}

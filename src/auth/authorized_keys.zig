//! `authorized_keys` files, in sshd's format (sshd(8), AUTHORIZED_KEYS FILE
//! FORMAT).
//!
//! Each line is `[options] keytype base64 [comment]`. Blank lines and lines
//! starting with `#` are ignored. No options are implemented yet, so a key
//! whose line has options is refused: accepting it would drop the
//! restriction the options describe.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const ssh = @import("ssh.zig");

pub const Match = enum {
    /// No line lists the key.
    absent,
    /// The first line listing the key has no options.
    allowed,
    /// The first line listing the key has options.
    restricted,
};

/// The largest file read.
const max_file_len = 1 << 20;

/// Looks `key` up in the first of `paths` that exists. sshd uses the first
/// line that lists a key, so later lines don't override it.
pub fn check(io: Io, gpa: Allocator, paths: []const []const u8, key: ssh.Key) !Match {
    for (paths) |path| {
        const contents = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_file_len)) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer gpa.free(contents);
        return find(contents, key);
    }
    return .absent;
}

pub fn find(contents: []const u8, key: ssh.Key) Match {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        // A line starting with a key type has no options.
        var rest = line;
        const has_options = !isKeyType(firstField(rest));
        if (has_options) rest = skipOptions(rest);

        const key_type = firstField(rest);
        rest = std.mem.trimStart(u8, rest[key_type.len..], " \t");
        const text = firstField(rest);

        // Lines that don't parse, or hold other key types, list no
        // Ed25519 key.
        const listed = ssh.parseKeyText(key_type, text) catch continue;
        if (!std.mem.eql(u8, &listed, &key)) continue;
        return if (has_options) .restricted else .allowed;
    }
    return .absent;
}

fn firstField(s: []const u8) []const u8 {
    const end = std.mem.indexOfAny(u8, s, " \t") orelse s.len;
    return s[0..end];
}

/// Returns what follows the options field. Option values are in double
/// quotes and can hold spaces and `\"`.
fn skipOptions(s: []const u8) []const u8 {
    var quoted = false;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        switch (s[i]) {
            '\\' => if (quoted) {
                i += 1;
            },
            '"' => quoted = !quoted,
            ' ', '\t' => if (!quoted) break,
            else => {},
        }
    }
    return std.mem.trimStart(u8, s[@min(i, s.len)..], " \t");
}

/// The key types sshd recognizes at the start of a line. An entry naming
/// one of them has no options field.
fn isKeyType(field: []const u8) bool {
    const types = [_][]const u8{
        "ssh-ed25519",
        "ssh-rsa",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    };
    for (types) |t| if (std.mem.eql(u8, field, t)) return true;

    // Certificate types, such as ssh-ed25519-cert-v01@openssh.com.
    return std.mem.endsWith(u8, field, "-cert-v01@openssh.com");
}

const testing = std.testing;

const key_text = "AAAAC3NzaC1lZDI1NTE5AAAAICwLzobQsiT0GtH1xeKcMJ3KbPb38YiHHQef9Jr2O9+G";

test "a listed key is allowed" {
    const key = try ssh.parseKeyText(ssh.ed25519, key_text);
    try testing.expectEqual(.allowed, find("ssh-ed25519 " ++ key_text ++ " me@laptop\n", key));
    try testing.expectEqual(.allowed, find("# keys\n\n  ssh-ed25519\t" ++ key_text ++ "\r\n", key));
    try testing.expectEqual(.allowed, find("ssh-ed25519 " ++ key_text, key));
}

test "an unlisted key is absent" {
    const key = try ssh.parseKeyText(ssh.ed25519, key_text);
    var other = key;
    other[0] ^= 1;
    try testing.expectEqual(.absent, find("ssh-ed25519 " ++ key_text ++ "\n", other));
    try testing.expectEqual(.absent, find("# ssh-ed25519 " ++ key_text ++ "\n", key));
    try testing.expectEqual(.absent, find("ssh-ed25519 garbage\nssh-rsa " ++ key_text ++ "\n", key));
}

test "a key whose first line has options is restricted" {
    const key = try ssh.parseKeyText(ssh.ed25519, key_text);
    try testing.expectEqual(.restricted, find("restrict ssh-ed25519 " ++ key_text ++ "\n", key));
    try testing.expectEqual(.restricted, find("from=\"10.0.0.0/8,!10.1.0.0/16\",no-pty ssh-ed25519 " ++ key_text ++ "\n", key));
    try testing.expectEqual(.restricted, find("command=\"echo \\\"a b\\\"\" ssh-ed25519 " ++ key_text ++ "\n", key));

    // A later line without options doesn't lift the restriction.
    try testing.expectEqual(.restricted, find("no-pty ssh-ed25519 " ++ key_text ++ "\nssh-ed25519 " ++ key_text ++ "\n", key));
}

test "the first existing file is used" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const key = try ssh.parseKeyText(ssh.ed25519, key_text);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "b", .data = "ssh-ed25519 " ++ key_text ++ "\n" });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "c", .data = "" });

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(testing.io, &buf);
    const dir = buf[0..n];
    const a = try std.fs.path.join(testing.allocator, &.{ dir, "a" });
    defer testing.allocator.free(a);
    const b = try std.fs.path.join(testing.allocator, &.{ dir, "b" });
    defer testing.allocator.free(b);
    const c = try std.fs.path.join(testing.allocator, &.{ dir, "c" });
    defer testing.allocator.free(c);

    try testing.expectEqual(.allowed, try check(testing.io, testing.allocator, &.{ a, b }, key));
    try testing.expectEqual(.absent, try check(testing.io, testing.allocator, &.{ c, b }, key));
    try testing.expectEqual(.absent, try check(testing.io, testing.allocator, &.{a}, key));
}

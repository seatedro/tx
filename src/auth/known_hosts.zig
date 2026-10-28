//! `known_hosts` files, in OpenSSH's format (sshd(8), SSH_KNOWN_HOSTS FILE
//! FORMAT).
//!
//! Each line is `[marker] hostnames keytype base64 [comment]`. `hostnames`
//! is a comma-separated list of patterns, where `*` and `?` are wildcards
//! and a leading `!` negates, or one hashed name, `|1|salt|hash`, whose hash
//! is HMAC-SHA1 of the host name keyed with the salt. A host on a port
//! other than the default is written `[host]:port`.
//!
//! The `@revoked` marker revokes a key for the hosts it matches. Lines
//! marked `@cert-authority` are skipped: tx has no host certificates yet.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const base64 = std.base64.standard;
const ssh = @import("ssh.zig");

/// The keys files list for one host.
pub const Known = struct {
    keys: std.ArrayList(ssh.Key) = .empty,
    revoked: std.ArrayList(ssh.Key) = .empty,

    pub fn deinit(k: *Known, gpa: Allocator) void {
        k.keys.deinit(gpa);
        k.revoked.deinit(gpa);
        k.* = undefined;
    }

    pub fn isRevoked(k: *const Known, key: ssh.Key) bool {
        for (k.revoked.items) |r| if (std.mem.eql(u8, &r, &key)) return true;
        return false;
    }

    /// The listed keys that aren't revoked.
    pub fn trusted(k: *const Known, gpa: Allocator) Allocator.Error![]ssh.Key {
        var out: std.ArrayList(ssh.Key) = .empty;
        errdefer out.deinit(gpa);
        for (k.keys.items) |key| if (!k.isRevoked(key)) try out.append(gpa, key);
        return out.toOwnedSlice(gpa);
    }
};

/// The name lookups use: `host`, or `[host]:port` off the default port.
pub fn hostName(buf: []u8, host: []const u8, port: u16, default_port: u16) error{NoSpaceLeft}![]const u8 {
    if (port == default_port) return std.fmt.bufPrint(buf, "{s}", .{host});
    return std.fmt.bufPrint(buf, "[{s}]:{d}", .{ host, port });
}

/// The largest file read.
const max_file_len = 16 << 20;

/// Adds the Ed25519 keys `path` lists for `host` to `known`. A missing file
/// lists none.
pub fn readFile(io: Io, gpa: Allocator, path: []const u8, host: []const u8, known: *Known) !void {
    const contents = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_file_len)) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer gpa.free(contents);
    try find(gpa, contents, host, known);
}

pub fn find(gpa: Allocator, contents: []const u8, host: []const u8, known: *Known) Allocator.Error!void {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw| {
        var fields: Fields = .{ .rest = std.mem.trim(u8, raw, " \t\r") };
        if (fields.rest.len == 0 or fields.rest[0] == '#') continue;

        var revoked = false;
        var names = fields.next();
        if (names.len > 0 and names[0] == '@') {
            if (!std.mem.eql(u8, names, "@revoked")) continue;
            revoked = true;
            names = fields.next();
        }
        const key_type = fields.next();
        const text = fields.next();

        if (!matchNames(names, host)) continue;
        // Other key types, and lines that don't parse.
        const key = ssh.parseKeyText(key_type, text) catch continue;

        if (revoked) try known.revoked.append(gpa, key) else try known.keys.append(gpa, key);
    }
}

/// Appends a line for `host` to `path`, creating the file and its
/// directory if needed.
pub fn append(io: Io, path: []const u8, host: []const u8, key: ssh.Key) !void {
    if (std.fs.path.dirname(path)) |dir| try Io.Dir.cwd().createDirPath(io, dir);

    const file = try Io.Dir.cwd().createFile(io, path, .{ .truncate = false, .read = true });
    defer file.close(io);

    // Starts on a new line if the file doesn't end with one.
    const size = try file.length(io);
    var last: [1]u8 = .{'\n'};
    if (size > 0) _ = try file.readPositionalAll(io, &last, size - 1);
    const sep: []const u8 = if (last[0] == '\n') "" else "\n";

    var buf: [1024]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "{s}{s} {s} {s}\n", .{ sep, host, ssh.ed25519, ssh.KeyText.init(key).slice() });
    try file.writePositionalAll(io, line, size);
}

/// Removes the lines `append` wrote for `host`: those whose hostnames are
/// exactly `host`. Lines with patterns, hashed names or markers stay. A
/// missing file has none.
pub fn remove(gpa: Allocator, io: Io, path: []const u8, host: []const u8) !void {
    const dir = Io.Dir.cwd();
    const old = dir.readFileAlloc(io, path, gpa, .limited(max_file_len)) catch |err| switch (err) {
        error.FileNotFound => return,
        else => |e| return e,
    };
    defer gpa.free(old);

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var lines = std.mem.splitScalar(u8, old, '\n');
    var removed = false;
    while (lines.next()) |line| {
        var fields: Fields = .{ .rest = std.mem.trim(u8, line, " \t\r") };
        if (std.mem.eql(u8, fields.next(), host)) {
            removed = true;
            continue;
        }
        // The split leaves an empty last line after the final newline.
        if (lines.peek() == null and line.len == 0) break;
        try out.writer.print("{s}\n", .{line});
    }
    if (!removed) return;

    // Written whole, then renamed, so the file never holds part of itself.
    var part_buf: [std.fs.max_path_bytes]u8 = undefined;
    const part = std.fmt.bufPrint(&part_buf, "{s}.part", .{path}) catch return error.NameTooLong;
    try dir.writeFile(io, .{ .sub_path = part, .data = out.written() });
    try dir.rename(part, dir, path, io);
}

const Fields = struct {
    rest: []const u8,

    fn next(f: *Fields) []const u8 {
        const end = std.mem.indexOfAny(u8, f.rest, " \t") orelse f.rest.len;
        const field = f.rest[0..end];
        f.rest = std.mem.trimStart(u8, f.rest[end..], " \t");
        return field;
    }
};

/// Whether the hostnames field of a line matches `host`.
fn matchNames(names: []const u8, host: []const u8) bool {
    if (std.mem.startsWith(u8, names, "|1|")) return matchHashed(names["|1|".len..], host);

    // A negated pattern that matches excludes the host, whatever else
    // matches.
    var matched = false;
    var patterns = std.mem.splitScalar(u8, names, ',');
    while (patterns.next()) |pattern| {
        if (pattern.len > 0 and pattern[0] == '!') {
            if (matchPattern(pattern[1..], host)) return false;
        } else if (matchPattern(pattern, host)) {
            matched = true;
        }
    }
    return matched;
}

/// `salt|hash`, both base64.
fn matchHashed(salt_and_hash: []const u8, host: []const u8) bool {
    const bar = std.mem.indexOfScalar(u8, salt_and_hash, '|') orelse return false;

    // OpenSSH's salt is the length of an HMAC-SHA1 output.
    var salt: [HmacSha1.mac_length]u8 = undefined;
    var hash: [HmacSha1.mac_length]u8 = undefined;
    if (!decodeExact(&salt, salt_and_hash[0..bar])) return false;
    if (!decodeExact(&hash, salt_and_hash[bar + 1 ..])) return false;

    // Names are hashed lowercased.
    var lower_buf: [256]u8 = undefined;
    if (host.len > lower_buf.len) return false;
    const lower = std.ascii.lowerString(&lower_buf, host);

    var mac: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&mac, lower, &salt);
    return std.mem.eql(u8, &mac, &hash);
}

fn decodeExact(out: []u8, text: []const u8) bool {
    const len = base64.Decoder.calcSizeForSlice(text) catch return false;
    if (len != out.len) return false;
    base64.Decoder.decode(out, text) catch return false;
    return true;
}

/// Case-insensitive glob match: `*` matches any run of bytes and `?` any
/// one byte.
fn matchPattern(pattern: []const u8, name: []const u8) bool {
    if (pattern.len == 0) return name.len == 0;

    switch (pattern[0]) {
        '*' => {
            // Try each suffix of `name` against the rest of the pattern.
            for (0..name.len + 1) |i| {
                if (matchPattern(pattern[1..], name[i..])) return true;
            }
            return false;
        },
        '?' => return name.len > 0 and matchPattern(pattern[1..], name[1..]),
        else => {
            if (name.len == 0 or std.ascii.toLower(pattern[0]) != std.ascii.toLower(name[0])) return false;
            return matchPattern(pattern[1..], name[1..]);
        },
    }
}

const testing = std.testing;

const key_text = "AAAAC3NzaC1lZDI1NTE5AAAAICwLzobQsiT0GtH1xeKcMJ3KbPb38YiHHQef9Jr2O9+G";

fn expectKeys(contents: []const u8, host: []const u8, keys: usize, revoked: usize) !void {
    var known: Known = .{};
    defer known.deinit(testing.allocator);
    try find(testing.allocator, contents, host, &known);
    try testing.expectEqual(keys, known.keys.items.len);
    try testing.expectEqual(revoked, known.revoked.items.len);
}

test remove {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const base = buf[0..try tmp.dir.realPath(testing.io, &buf)];
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/known_hosts", .{base});

    const line = " ssh-ed25519 " ++ key_text ++ "\n";
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "known_hosts",
        .data = "# kept\npulsar" ++ line ++ "[pulsar]:9000" ++ line ++ "pulsar,other" ++ line ++ "@revoked pulsar" ++ line ++ "pulsar" ++ line,
    });
    try remove(testing.allocator, testing.io, path, "pulsar");

    const text = try tmp.dir.readFileAlloc(testing.io, "known_hosts", testing.allocator, .limited(4096));
    defer testing.allocator.free(text);
    try testing.expectEqualStrings("# kept\n[pulsar]:9000" ++ line ++ "pulsar,other" ++ line ++ "@revoked pulsar" ++ line, text);

    // A missing file, and a host the file doesn't have.
    try remove(testing.allocator, testing.io, path, "absent");
    try remove(testing.allocator, testing.io, "/nonexistent/known_hosts", "pulsar");
}

test "host name patterns" {
    const line = " ssh-ed25519 " ++ key_text ++ "\n";
    try expectKeys("pulsar" ++ line, "pulsar", 1, 0);
    try expectKeys("PULSAR" ++ line, "pulsar", 1, 0);
    try expectKeys("other,pulsar,10.0.0.2" ++ line, "pulsar", 1, 0);
    try expectKeys("other" ++ line, "pulsar", 0, 0);
    try expectKeys("*.lan" ++ line, "pulsar.lan", 1, 0);
    try expectKeys("*.lan" ++ line, "pulsar.lan.example", 0, 0);
    try expectKeys("pulsa?" ++ line, "pulsar", 1, 0);
    try expectKeys("*,!pulsar" ++ line, "pulsar", 0, 0);
    try expectKeys("*,!pulsar" ++ line, "nova", 1, 0);
    try expectKeys("[pulsar]:2222" ++ line, "[pulsar]:2222", 1, 0);
    try expectKeys("[pulsar]:2222" ++ line, "pulsar", 0, 0);
}

test "hashed host names" {
    // From `ssh-keygen -H` on a file with a line for "pulsar".
    const line = "|1|GAcJdL9QNTot2bJpq2vb0aMJzvA=|TSp+OONctT2/7zKsRLLn89tH16U= ssh-ed25519 " ++ key_text ++ "\n";

    try expectKeys(line, "pulsar", 1, 0);
    try expectKeys(line, "PULSAR", 1, 0);
    try expectKeys(line, "nova", 0, 0);
}

test "markers, comments and other key types" {
    const key = " ssh-ed25519 " ++ key_text;
    try expectKeys("@revoked *" ++ key ++ "\n", "pulsar", 0, 1);
    try expectKeys("@cert-authority *" ++ key ++ "\n", "pulsar", 0, 0);
    try expectKeys("# pulsar" ++ key ++ "\n\n", "pulsar", 0, 0);
    try expectKeys("pulsar ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== c\n", "pulsar", 0, 0);
    try expectKeys("pulsar" ++ key ++ " a comment\r\npulsar" ++ key, "pulsar", 2, 0);
}

test "revoked keys aren't trusted" {
    var known: Known = .{};
    defer known.deinit(testing.allocator);
    try find(testing.allocator, "pulsar ssh-ed25519 " ++ key_text ++ "\n@revoked pulsar ssh-ed25519 " ++ key_text ++ "\n", "pulsar", &known);

    const trusted = try known.trusted(testing.allocator);
    defer testing.allocator.free(trusted);
    try testing.expectEqual(0, trusted.len);
    try testing.expect(known.isRevoked(known.keys.items[0]));
}

test "append adds a line that find reads back" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(testing.io, &buf);
    const path = try std.fs.path.join(testing.allocator, &.{ buf[0..n], "tx", "known_hosts" });
    defer testing.allocator.free(path);

    const key = try ssh.parseKeyText(ssh.ed25519, key_text);
    try append(testing.io, path, "pulsar", key);
    try append(testing.io, path, "[nova]:2222", key);

    var known: Known = .{};
    defer known.deinit(testing.allocator);
    try readFile(testing.io, testing.allocator, path, "[nova]:2222", &known);
    try testing.expectEqual(1, known.keys.items.len);
    try testing.expectEqual(key, known.keys.items[0]);

    const contents = try tmp.dir.readFileAlloc(testing.io, "tx/known_hosts", testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("pulsar ssh-ed25519 " ++ key_text ++ "\n[nova]:2222 ssh-ed25519 " ++ key_text ++ "\n", contents);
}

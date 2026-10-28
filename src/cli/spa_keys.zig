//! `~/.config/tx/spa_keys`: the SPA key of each host (see
//! `transport.spa`), one line each, `NAME KEY`. NAME is the host's name
//! in known_hosts, `host` or `[host]:port`, and KEY is base64. tx reads a
//! host's key over ssh, from `txd --print-spa-key`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const spa = @import("transport").spa;

const base64 = std.base64.standard;

/// The key recorded for `name`, if there is one.
pub fn find(gpa: Allocator, io: Io, path: []const u8, name: []const u8) !?spa.Key {
    const text = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    defer gpa.free(text);

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const entry = parseLine(line) orelse continue;
        if (std.mem.eql(u8, entry.name, name)) return entry.key;
    }
    return null;
}

/// Records `key` for `name`, in place of the line it had.
pub fn store(gpa: Allocator, io: Io, path: []const u8, name: []const u8, key: spa.Key) !void {
    const dir = Io.Dir.cwd();
    const old = dir.readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => try gpa.dupe(u8, ""),
        else => |e| return e,
    };
    defer gpa.free(old);

    // Every other line, then the host's.
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const w = &out.writer;
    var lines = std.mem.splitScalar(u8, old, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (parseLine(line)) |entry| if (std.mem.eql(u8, entry.name, name)) continue;
        try w.print("{s}\n", .{line});
    }
    var text: [base64.Encoder.calcSize(32)]u8 = undefined;
    try w.print("{s} {s}\n", .{ name, base64.Encoder.encode(&text, &key) });

    // Written whole, then renamed, so the file never holds part of one.
    // Mode 0600, as the key is a secret.
    if (std.fs.path.dirname(path)) |parent| try dir.createDirPath(io, parent);
    var part_buf: [std.fs.max_path_bytes]u8 = undefined;
    const part = std.fmt.bufPrint(&part_buf, "{s}.part", .{path}) catch return error.NameTooLong;
    const file = try dir.createFile(io, part, .{ .permissions = .fromMode(0o600) });
    {
        defer file.close(io);
        try file.writeStreamingAll(io, out.written());
    }
    try dir.rename(part, dir, path, io);
}

/// What `txd --print-spa-key` printed: its key, and its clock in Unix
/// seconds.
pub const Printed = struct {
    key: spa.Key,
    time: i64,
};

/// The `spa-key KEY TIME` line among txd's output.
pub fn parsePrinted(output: []const u8) ?Printed {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        if (!std.mem.eql(u8, fields.next() orelse continue, "spa-key")) continue;
        const key = decodeKey(fields.next() orelse return null) orelse return null;
        const time = std.fmt.parseInt(i64, fields.next() orelse return null, 10) catch return null;
        return .{ .key = key, .time = time };
    }
    return null;
}

const Entry = struct {
    name: []const u8,
    key: spa.Key,
};

fn parseLine(line: []const u8) ?Entry {
    var fields = std.mem.tokenizeAny(u8, line, " \t\r");
    const name = fields.next() orelse return null;
    const key = decodeKey(fields.next() orelse return null) orelse return null;
    return .{ .name = name, .key = key };
}

fn decodeKey(text: []const u8) ?spa.Key {
    var key: spa.Key = undefined;
    const len = base64.Decoder.calcSizeForSlice(text) catch return null;
    if (len != key.len) return null;
    base64.Decoder.decode(&key, text) catch return null;
    return key;
}

const testing = std.testing;

test "a host's key replaces its line, and the others stay" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const base = buf[0..try tmp.dir.realPath(testing.io, &buf)];
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/tx/spa_keys", .{base});

    try testing.expectEqual(null, try find(testing.allocator, testing.io, path, "a"));
    try store(testing.allocator, testing.io, path, "a", @splat(1));
    try store(testing.allocator, testing.io, path, "[b]:9000", @splat(2));
    try store(testing.allocator, testing.io, path, "a", @splat(3));

    try testing.expectEqual(@as(spa.Key, @splat(3)), (try find(testing.allocator, testing.io, path, "a")).?);
    try testing.expectEqual(@as(spa.Key, @splat(2)), (try find(testing.allocator, testing.io, path, "[b]:9000")).?);
    try testing.expectEqual(null, try find(testing.allocator, testing.io, path, "b"));
    const text = try tmp.dir.readFileAlloc(testing.io, "tx/spa_keys", testing.allocator, .limited(4096));
    defer testing.allocator.free(text);
    try testing.expectEqual(2, std.mem.count(u8, text, "\n"));
}

test "txd's SPA key line is found among its output" {
    const key: spa.Key = @splat(9);
    var text: [base64.Encoder.calcSize(32)]u8 = undefined;
    var out_buf: [256]u8 = undefined;
    const output = try std.fmt.bufPrint(&out_buf, "ssh-ed25519 AAAA\nspa-key {s} 1700000000\n", .{base64.Encoder.encode(&text, &key)});

    const printed = parsePrinted(output).?;
    try testing.expectEqual(key, printed.key);
    try testing.expectEqual(1700000000, printed.time);
    try testing.expectEqual(null, parsePrinted("ssh-ed25519 AAAA\n"));
    try testing.expectEqual(null, parsePrinted("spa-key short 1\n"));
}

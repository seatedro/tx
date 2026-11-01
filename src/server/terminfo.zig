//! Compiles the terminfo entry a client sends with its Attach, the output of
//! `infocmp -x $TERM`, so that programs in the session know the client's
//! TERM. Each entry gets a directory under terminfo_dir named by its hash,
//! and the session's TERMINFO points at it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// The largest entry accepted. tx caps what it sends at the same 64 KiB.
pub const max_source_len = 64 << 10;

pub fn install(gpa: Allocator, io: Io, base: []const u8, source: []const u8) ![]u8 {
    if (source.len > max_source_len) return error.TooLong;

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(source, &digest, .{});
    const name = std.fmt.bytesToHex(digest[0..16].*, .lower);
    const dir = try std.fs.path.join(gpa, &.{ base, &name });
    errdefer gpa.free(dir);
    const cwd = Io.Dir.cwd();
    if (cwd.access(io, dir, .{})) return dir else |_| {}

    // tic writes into a temporary directory, renamed into place once complete,
    // so the access check above finds complete directories.
    var suffix: [8]u8 = undefined;
    io.random(&suffix);
    const tmp = try std.fmt.allocPrint(gpa, "{s}.tmp-{x}", .{ dir, suffix });
    defer gpa.free(tmp);
    try cwd.createDirPath(io, tmp);
    defer cwd.deleteTree(io, tmp) catch {};

    const source_path = try std.fs.path.join(gpa, &.{ tmp, "source" });
    defer gpa.free(source_path);
    try cwd.writeFile(io, .{ .sub_path = source_path, .data = source });
    try compile(gpa, io, source_path, tmp);
    try cwd.deleteFile(io, source_path);

    if (!hasEntry(io, tmp, entryName(source) orelse return error.NoEntry)) return error.NoEntry;

    // When another install of the same entry renamed first, its directory is
    // used.
    cwd.rename(tmp, cwd, dir, io) catch |err| {
        if (cwd.access(io, dir, .{})) return dir else |_| return err;
    };
    return dir;
}

// infocmp indents capability lines. The first line that isn't indented or a
// comment starts with the entry's names, separated by '|'.
fn entryName(source: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#' or std.ascii.isWhitespace(line[0])) continue;
        const end = std.mem.indexOfAny(u8, line, "|,") orelse return null;
        return line[0..end];
    }
    return null;
}

// tic files an entry under its first character, or under that character's
// hex code where filenames are case-insensitive, as on macOS.
fn hasEntry(io: Io, dir: []const u8, name: []const u8) bool {
    // The name comes from the client and becomes part of a path.
    if (name.len == 0 or std.mem.indexOfScalar(u8, name, '/') != null) return false;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const by_letter = std.fmt.bufPrint(&buf, "{s}/{c}/{s}", .{ dir, name[0], name }) catch return false;
    if (Io.Dir.cwd().access(io, by_letter, .{})) return true else |_| {}
    const by_hex = std.fmt.bufPrint(&buf, "{s}/{x:0>2}/{s}", .{ dir, name[0], name }) catch return false;
    if (Io.Dir.cwd().access(io, by_hex, .{})) return true else |_| return false;
}

fn compile(gpa: Allocator, io: Io, source_path: []const u8, out_dir: []const u8) !void {
    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "tic", "-x", "-o", out_dir, source_path },
        .stdout_limit = .limited(64 << 10),
        .stderr_limit = .limited(64 << 10),
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    if (!result.term.success()) {
        std.log.scoped(.terminfo).warn("tic failed: {s}", .{std.mem.trim(u8, result.stderr, " \n")});
        return error.TicFailed;
    }
}

const testing = std.testing;

const test_source =
    \\tx-test-term|a terminal for tx's tests,
    \\    am, cols#80, lines#24,
    \\    clear=\E[H\E[2J, smxx=\E[9m,
    \\
;

test entryName {
    try testing.expectEqualStrings("xterm-ghostty", entryName("#\tReconstructed via infocmp\nxterm-ghostty|ghostty|Ghostty,\n\tam,\n").?);
    try testing.expectEqual(null, entryName("# nothing\n"));
}

test "an entry compiles once, into the directory its hash names" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const base = buf[0..try tmp.dir.realPath(testing.io, &buf)];

    const dir = install(testing.allocator, testing.io, base, test_source) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer testing.allocator.free(dir);

    try testing.expect(hasEntry(testing.io, dir, "tx-test-term"));

    const again = try install(testing.allocator, testing.io, base, test_source);
    defer testing.allocator.free(again);
    try testing.expectEqualStrings(dir, again);

    try testing.expectError(error.NoEntry, install(testing.allocator, testing.io, base, "not terminfo\n"));
}

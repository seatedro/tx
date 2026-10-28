//! Command-line options with POSIX getopt's rules, as ssh and most Unix
//! commands read them, plus long options.
//!
//! The spec lists the option letters, and a letter followed by `:` takes a
//! value. ssh's, for example, starts `1246ab:c:`: `-1` takes no value, and
//! `-b` takes one.
//!
//! - Letters group: `-tv` is `-t -v`.
//! - A value is the rest of its argument or, if there is none, the next
//!   argument: `-p22` and `-p 22` are the same.
//! - The first argument that isn't an option ends the options. So does
//!   `--`, which is skipped. A lone `-` isn't an option.
//! - `--name` is a long option. Its value, if it takes one, is the next
//!   argument (see `Parser.value`).
const std = @import("std");

pub const Item = union(enum) {
    /// `-x`, with its value if its letter takes one.
    short: Short,
    /// `--name`, without the dashes.
    long: []const u8,

    pub const Short = struct {
        letter: u8,
        value: ?[]const u8 = null,
    };
};

pub const Error = error{
    /// A letter the spec doesn't list. It is in `Parser.letter`.
    UnknownOption,
    /// An option that takes a value came last.
    MissingValue,
};

pub const Parser = struct {
    spec: []const u8,
    args: []const []const u8,
    /// The argument being read, or after the options, the first operand.
    index: usize = 0,
    /// In a group of letters, the next one's offset. 0 between arguments.
    offset: usize = 0,
    /// `--` ended the options.
    ended: bool = false,
    /// The letter of the last `error.UnknownOption` or
    /// `error.MissingValue`.
    letter: u8 = 0,

    /// The next option, or null at the end of the options.
    pub fn next(p: *Parser) Error!?Item {
        if (p.offset == 0) {
            if (p.index == p.args.len) return null;
            const arg = p.args[p.index];
            if (std.mem.eql(u8, arg, "--")) {
                p.index += 1;
                p.ended = true;
                return null;
            }
            if (arg.len < 2 or arg[0] != '-') return null;
            if (arg[1] == '-') {
                p.index += 1;
                return .{ .long = arg[2..] };
            }
            p.offset = 1;
        }

        const arg = p.args[p.index];
        const letter = arg[p.offset];
        p.offset += 1;
        p.letter = letter;
        const at = std.mem.indexOfScalar(u8, p.spec, letter);

        // `:` marks values, and isn't a letter.
        if (at == null or letter == ':') {
            p.endGroupIfDone();
            return error.UnknownOption;
        }
        const takes_value = at.? + 1 < p.spec.len and p.spec[at.? + 1] == ':';
        if (!takes_value) {
            p.endGroupIfDone();
            return .{ .short = .{ .letter = letter } };
        }

        // The rest of the group, or else the next argument.
        const joined = arg[p.offset..];
        p.offset = 0;
        p.index += 1;
        if (joined.len > 0) return .{ .short = .{ .letter = letter, .value = joined } };
        return .{ .short = .{ .letter = letter, .value = try p.value() } };
    }

    /// Takes the next argument as the value of the option just read, as a
    /// long option's.
    pub fn value(p: *Parser) Error![]const u8 {
        if (p.index == p.args.len) return error.MissingValue;
        defer p.index += 1;
        return p.args[p.index];
    }

    /// The arguments after the options.
    pub fn rest(p: *const Parser) []const []const u8 {
        return p.args[p.index..];
    }

    /// Moves to the next argument after the last letter of a group.
    fn endGroupIfDone(p: *Parser) void {
        if (p.offset < p.args[p.index].len) return;
        p.offset = 0;
        p.index += 1;
    }
};

const testing = std.testing;

/// The items `args` gives, as `-x`, `-x=value` and `--name`, then `| rest`.
fn expectItems(args: []const []const u8, want: []const u8) !void {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var p: Parser = .{ .spec = "ab:c", .args = args };
    while (try p.next()) |item| switch (item) {
        .short => |s| if (s.value) |v| try out.writer.print("-{c}={s} ", .{ s.letter, v }) else try out.writer.print("-{c} ", .{s.letter}),
        .long => |name| try out.writer.print("--{s} ", .{name}),
    };
    try out.writer.writeAll("|");
    for (p.rest()) |arg| try out.writer.print(" {s}", .{arg});
    try testing.expectEqualStrings(want, out.written());
}

test "letters group, and a value is joined or the next argument" {
    try expectItems(&.{ "-ac", "-bx", "-b", "y", "-cbz" }, "-a -c -b=x -b=y -c -b=z |");
}

test "the first operand, or --, ends the options" {
    try expectItems(&.{ "-a", "host", "-c" }, "-a | host -c");
    try expectItems(&.{ "-a", "--", "-c" }, "-a | -c");
    try expectItems(&.{ "-", "-a" }, "| - -a");
    try expectItems(&.{ "-b", "--", "x" }, "-b=-- | x");
}

test "long options" {
    var p: Parser = .{ .spec = "a", .args = &.{ "--list", "--attach", "3", "-a", "x" } };
    try testing.expectEqualStrings("list", (try p.next()).?.long);
    try testing.expectEqualStrings("attach", (try p.next()).?.long);
    try testing.expectEqualStrings("3", try p.value());
    try testing.expectEqual('a', (try p.next()).?.short.letter);
    try testing.expectEqual(null, try p.next());
    try testing.expectEqualStrings("x", p.rest()[0]);
}

test "an unknown letter, and a missing value, fail" {
    var unknown: Parser = .{ .spec = "ab:", .args = &.{ "-az", "x" } };
    try testing.expectEqual('a', (try unknown.next()).?.short.letter);
    try testing.expectError(error.UnknownOption, unknown.next());
    try testing.expectEqual('z', unknown.letter);
    try testing.expectEqual(null, try unknown.next());

    var colon: Parser = .{ .spec = "ab:", .args = &.{"-:"} };
    try testing.expectError(error.UnknownOption, colon.next());

    var missing: Parser = .{ .spec = "ab:", .args = &.{ "-a", "-b" } };
    _ = try missing.next();
    try testing.expectError(error.MissingValue, missing.next());
    try testing.expectEqual('b', missing.letter);
}

//! A getopt(3)-style parser for short options that also returns --name
//! arguments as long options. Parsing stops at the first operand or after --,
//! and the caller may consume operands and call next again.

const std = @import("std");

pub const Item = union(enum) {
    short: Short,
    long: []const u8,

    pub const Short = struct {
        letter: u8,
        value: ?[]const u8 = null,
    };
};

pub const Error = error{
    UnknownOption,
    MissingValue,
};

pub const Parser = struct {
    spec: []const u8,
    args: []const []const u8,
    index: usize = 0,
    offset: usize = 0,
    ended: bool = false,
    letter: u8 = 0,

    /// The next option, or null at the first operand or after --. A letter
    /// that takes a value takes the rest of its argument, or else the next
    /// argument. After an error the parser has moved past the letter.
    pub fn next(p: *Parser) Error!?Item {
        if (p.offset == 0) {
            if (p.index == p.args.len) return null;
            const arg = p.args[p.index];
            if (std.mem.eql(u8, arg, "--")) {
                p.index += 1;
                p.ended = true;
                return null;
            }
            // A lone - is an operand.
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

        // ':' marks values in spec and is not an option letter.
        if (at == null or letter == ':') {
            p.endGroupIfDone();
            return error.UnknownOption;
        }
        const takes_value = at.? + 1 < p.spec.len and p.spec[at.? + 1] == ':';
        if (!takes_value) {
            p.endGroupIfDone();
            return .{ .short = .{ .letter = letter } };
        }

        const joined = arg[p.offset..];
        p.offset = 0;
        p.index += 1;
        if (joined.len > 0) return .{ .short = .{ .letter = letter, .value = joined } };
        return .{ .short = .{ .letter = letter, .value = try p.value() } };
    }

    pub fn value(p: *Parser) Error![]const u8 {
        if (p.index == p.args.len) return error.MissingValue;
        defer p.index += 1;
        return p.args[p.index];
    }

    pub fn rest(p: *const Parser) []const []const u8 {
        return p.args[p.index..];
    }

    fn endGroupIfDone(p: *Parser) void {
        if (p.offset < p.args[p.index].len) return;
        p.offset = 0;
        p.index += 1;
    }
};

const testing = std.testing;

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

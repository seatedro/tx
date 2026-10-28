//! What the user's terminal reports about its colors: the foreground and
//! background (OSC 10 and 11), the 16 base colors (OSC 4) and its light or
//! dark scheme (`CSI ? 996 n`). The session's terminal answers with these
//! while no client is attached, as the user's terminal would.
//!
//! tx asks once, before it connects, in raw mode. The queries go out with
//! DA1 last, which every terminal answers, and answers come in order, so
//! the DA1 reply means every answer that will come has. Bytes that aren't
//! answers are what the user typed meanwhile, and are kept as input.
const std = @import("std");
const posix = std.posix;
const c = std.c;
const tty = @import("tty.zig");

pub const Rgb = struct { r: u8, g: u8, b: u8 };

pub const Colors = struct {
    foreground: ?Rgb = null,
    background: ?Rgb = null,
    palette: [16]?Rgb = @splat(null),
    /// From the scheme report: dark is `CSI ? 997 ; 1 n`.
    dark: ?bool = null,
};

/// `0xRRGGBB`, as `proto.Attach` carries a color.
pub fn packRgb(rgb: ?Rgb) ?u32 {
    const color = rgb orelse return null;
    return @as(u32, color.r) << 16 | @as(u32, color.g) << 8 | color.b;
}

/// The reported base colors, as `proto.Attach.palette` carries them, in
/// `buf`. Null if there are none.
pub fn paletteBytes(colors: *const Colors, buf: *[64]u8) ?[]const u8 {
    var len: usize = 0;
    for (colors.palette, 0..) |entry, i| {
        const rgb = entry orelse continue;
        buf[len..][0..4].* = .{ @intCast(i), rgb.r, rgb.g, rgb.b };
        len += 4;
    }
    return if (len == 0) null else buf[0..len];
}

/// How long tx waits for a terminal that doesn't answer DA1.
const timeout_ms = 300;

const queries = "\x1b]10;?\x1b\\\x1b]11;?\x1b\\" ++ paletteQueries() ++ "\x1b[?996n\x1b[c";

fn paletteQueries() []const u8 {
    comptime {
        var out: []const u8 = "";
        for (0..16) |i| out = out ++ std.fmt.comptimePrint("\x1b]4;{d};?\x1b\\", .{i});
        return out;
    }
}

/// Asks the terminal on `fd` for its colors. `typed` gets what the user
/// typed meanwhile. A terminal that isn't one, or doesn't answer, reports
/// nothing.
pub fn ask(fd: posix.fd_t, typed: *std.ArrayList(u8), gpa: std.mem.Allocator) !Colors {
    var raw = tty.RawMode.enter(fd) catch return .{};
    defer raw.restore();

    var rest: []const u8 = queries;
    while (rest.len > 0) {
        const n = c.write(fd, rest.ptr, rest.len);
        if (n <= 0) return .{};
        rest = rest[@intCast(n)..];
    }

    var parser: Parser = .{};
    var buf: [4096]u8 = undefined;
    const deadline = nowMs() + timeout_ms;
    while (!parser.done) {
        const left = deadline - nowMs();
        if (left <= 0) break;
        var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
        if (c.poll(&fds, 1, @intCast(left)) <= 0) break;
        const n = c.read(fd, &buf, buf.len);
        if (n <= 0) break;
        try parser.feed(gpa, buf[0..@intCast(n)], typed);
    }
    // A sequence cut off by the timeout was typed, or garbled.
    try typed.appendSlice(gpa, parser.partial.items);
    parser.partial.deinit(gpa);
    return parser.colors;
}

fn nowMs() i64 {
    var ts: c.timespec = undefined;
    _ = c.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

/// Splits the terminal's bytes into answers, which set `colors`, and the
/// rest, which is input.
const Parser = struct {
    colors: Colors = .{},
    /// The DA1 answer came.
    done: bool = false,
    /// A sequence not yet ended.
    partial: std.ArrayList(u8) = .empty,

    fn feed(p: *Parser, gpa: std.mem.Allocator, bytes: []const u8, typed: *std.ArrayList(u8)) !void {
        for (bytes) |byte| {
            if (p.done) {
                try typed.append(gpa, byte);
                continue;
            }
            if (p.partial.items.len == 0) {
                if (byte == 0x1b) try p.partial.append(gpa, byte) else try typed.append(gpa, byte);
                continue;
            }
            try p.partial.append(gpa, byte);
            const seq = p.partial.items;
            switch (seq[1]) {
                // OSC, ended by BEL or ST.
                ']' => {
                    const st = seq.len >= 2 and seq[seq.len - 2] == 0x1b and byte == '\\';
                    if (byte != 0x07 and !st) continue;
                    p.osc(seq[2 .. seq.len - @as(usize, if (st) 2 else 1)]);
                },
                // CSI, ended by a byte from @ to ~.
                '[' => {
                    if (seq.len < 3 or byte < 0x40 or byte > 0x7e) continue;
                    p.csi(seq[2..]);
                },
                // Escape and a key, such as Alt-x.
                else => try typed.appendSlice(gpa, seq),
            }
            p.partial.clearRetainingCapacity();
        }
    }

    fn osc(p: *Parser, body: []const u8) void {
        var fields = std.mem.splitScalar(u8, body, ';');
        const number = fields.next() orelse return;
        if (std.mem.eql(u8, number, "10")) p.colors.foreground = parseRgb(fields.rest());
        if (std.mem.eql(u8, number, "11")) p.colors.background = parseRgb(fields.rest());
        if (std.mem.eql(u8, number, "4")) {
            const index = std.fmt.parseInt(u8, fields.next() orelse return, 10) catch return;
            if (index < 16) p.colors.palette[index] = parseRgb(fields.rest());
        }
    }

    fn csi(p: *Parser, body: []const u8) void {
        // DA1 answers `CSI ? ... c`.
        if (body.len > 0 and body[0] == '?' and body[body.len - 1] == 'c') p.done = true;
        if (std.mem.eql(u8, body, "?997;1n")) p.colors.dark = true;
        if (std.mem.eql(u8, body, "?997;2n")) p.colors.dark = false;
    }
};

/// `rgb:R/G/B`, each 1 to 4 hex digits, scaled to 8 bits.
fn parseRgb(text: []const u8) ?Rgb {
    if (!std.mem.startsWith(u8, text, "rgb:")) return null;
    var parts = std.mem.splitScalar(u8, text["rgb:".len..], '/');
    var out: [3]u8 = undefined;
    for (&out) |*component| {
        const hex = parts.next() orelse return null;
        if (hex.len == 0 or hex.len > 4) return null;
        const value = std.fmt.parseInt(u16, hex, 16) catch return null;
        const max: u32 = (@as(u32, 1) << @intCast(hex.len * 4)) - 1;
        component.* = @intCast(@as(u32, value) * 255 / max);
    }
    if (parts.next() != null) return null;
    return .{ .r = out[0], .g = out[1], .b = out[2] };
}

const testing = std.testing;

test "answers set the colors, and the rest is input" {
    var p: Parser = .{};
    var typed: std.ArrayList(u8) = .empty;
    defer typed.deinit(testing.allocator);
    defer p.partial.deinit(testing.allocator);

    // Split mid-sequence, with a key typed between two answers.
    try p.feed(testing.allocator, "\x1b]10;rgb:ffff/8080/0000\x1b\\x\x1b]11;rgb:00/00/", &typed);
    try p.feed(testing.allocator, "00\x07\x1b]4;3;rgb:1/2/3\x1b\\\x1b[?997;1n\x1b[?62;22c", &typed);
    try p.feed(testing.allocator, "y", &typed);

    try testing.expectEqual(Rgb{ .r = 255, .g = 128, .b = 0 }, p.colors.foreground.?);
    try testing.expectEqual(Rgb{ .r = 0, .g = 0, .b = 0 }, p.colors.background.?);
    try testing.expectEqual(Rgb{ .r = 17, .g = 34, .b = 51 }, p.colors.palette[3].?);
    try testing.expectEqual(null, p.colors.palette[0]);
    try testing.expect(p.colors.dark.?);
    try testing.expect(p.done);
    try testing.expectEqualStrings("xy", typed.items);
}

test parseRgb {
    try testing.expectEqual(Rgb{ .r = 0x12, .g = 0x34, .b = 0x56 }, parseRgb("rgb:1212/3434/5656").?);
    try testing.expectEqual(null, parseRgb("rgb:12/34"));
    try testing.expectEqual(null, parseRgb("#123456"));
}

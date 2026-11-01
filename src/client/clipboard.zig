const std = @import("std");
const Allocator = std.mem.Allocator;

pub const paste_window_ms = 5000;

pub const poll_ms = 500;

pub const max_data_len = 64 << 20;

pub const Provider = struct {
    context: ?*anyopaque = null,
    change: *const fn (context: ?*anyopaque) u64,
    types: *const fn (context: ?*anyopaque, gpa: Allocator) Allocator.Error![]u8,
    read: *const fn (context: ?*anyopaque, gpa: Allocator, mime: []const u8) Allocator.Error!?[]u8,
    write: *const fn (context: ?*anyopaque, items: []const Item) u64,
};

pub const Item = struct {
    mime: []const u8,
    data: []const u8,
};

pub fn hasPaste(input: []const u8) bool {
    if (std.mem.indexOfScalar(u8, input, 0x16) != null) return true;
    if (std.mem.indexOf(u8, input, "\x1b[200~") != null) return true;

    var rest = input;
    while (std.mem.indexOf(u8, rest, "\x1b[")) |start| {
        rest = rest[start + 2 ..];
        const end = std.mem.indexOfNone(u8, rest, "0123456789;:") orelse return false;
        const params = rest[0..end];
        switch (rest[end]) {
            'u' => if (isCtrlV(params)) return true,
            '~' => if (isModifyOtherKeysCtrlV(params)) return true,
            else => {},
        }
    }
    return false;
}

fn isCtrlV(params: []const u8) bool {
    var fields = std.mem.splitScalar(u8, params, ';');
    const key = fields.next() orelse return false;
    if (!std.mem.eql(u8, firstCode(key), "118")) return false;
    const mods = fields.next() orelse return false;
    var parts = std.mem.splitScalar(u8, mods, ':');
    const value = std.fmt.parseInt(u32, parts.next().?, 10) catch return false;
    if (parts.next()) |event| if (std.mem.eql(u8, event, "3")) return false;
    return value >= 1 and (value - 1) & ctrl_bit != 0;
}

fn isModifyOtherKeysCtrlV(params: []const u8) bool {
    var fields = std.mem.splitScalar(u8, params, ';');
    if (!std.mem.eql(u8, fields.next() orelse return false, "27")) return false;
    const value = std.fmt.parseInt(u32, fields.next() orelse return false, 10) catch return false;
    if (!std.mem.eql(u8, fields.next() orelse return false, "118")) return false;
    return value >= 1 and (value - 1) & ctrl_bit != 0;
}

const ctrl_bit = 4;

fn firstCode(key: []const u8) []const u8 {
    return key[0 .. std.mem.indexOfScalar(u8, key, ':') orelse key.len];
}

const testing = std.testing;

test hasPaste {
    const pastes = [_][]const u8{
        "\x16",
        "ab\x16",
        "\x1b[200~text\x1b[201~",
        "\x1b[118;5u",
        "x\x1b[118;5:1u",
        "\x1b[118:86;5u",
        "\x1b[118;7u",
        "\x1b[27;5;118~",
    };
    for (pastes) |input| try testing.expect(hasPaste(input));

    const others = [_][]const u8{
        "v",
        "\x1b[118u",
        "\x1b[118;2u",
        "\x1b[118;5:3u",
        "\x1b[119;5u",
        "\x1b[27;2;118~",
        "\x1b[A\x1b[",
        "\x1b[201~",
    };
    for (others) |input| try testing.expect(!hasPaste(input));
}

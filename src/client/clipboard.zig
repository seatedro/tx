//! The user's clipboard, as the client offers it to programs on the host.
//!
//! The client offers the clipboard's types when they change, and answers
//! a program's read only within `paste_window_ms` of the user pasting: a
//! paste the client saw in the input, such as Ctrl-V for Claude Code, or a
//! bracketed paste. Otherwise any process on the host running as the user
//! could read the clipboard at any time, for example a compromised
//! dependency polling for copied passwords.
//!
//! A program's copy on the host comes the other way, and replaces the
//! clipboard. The client doesn't offer that change back.
const std = @import("std");
const Allocator = std.mem.Allocator;

/// How long after a paste the clipboard may be read.
pub const paste_window_ms = 5000;

/// How often the clipboard is checked for a change. macOS has no
/// notification for one.
pub const poll_ms = 500;

/// The most a program's copy or an answer holds.
pub const max_data_len = 64 << 20;

/// The clipboard where the client runs.
pub const Provider = struct {
    context: ?*anyopaque = null,
    /// A number that changes whenever the clipboard does.
    change: *const fn (context: ?*anyopaque) u64,
    /// The types the clipboard holds, as programs ask for them, each
    /// followed by NUL. The caller frees them.
    types: *const fn (context: ?*anyopaque, gpa: Allocator) Allocator.Error![]u8,
    /// The clipboard's data as `mime`, or null if it no longer holds that
    /// type. The caller frees it.
    read: *const fn (context: ?*anyopaque, gpa: Allocator, mime: []const u8) Allocator.Error!?[]u8,
    /// Replaces the clipboard with a program's copy, and returns its new
    /// `change`.
    write: *const fn (context: ?*anyopaque, items: []const Item) u64,
};

pub const Item = struct {
    mime: []const u8,
    data: []const u8,
};

/// Whether `input` holds a paste: Ctrl-V as the terminal sends it, plain
/// or with the Kitty keyboard protocol or xterm's modifyOtherKeys, or the
/// start of a bracketed paste. A sequence split between two reads is
/// missed.
pub fn hasPaste(input: []const u8) bool {
    if (std.mem.indexOfScalar(u8, input, 0x16) != null) return true;
    if (std.mem.indexOf(u8, input, "\x1b[200~") != null) return true;

    var rest = input;
    while (std.mem.indexOf(u8, rest, "\x1b[")) |start| {
        rest = rest[start + 2 ..];
        // Parameters, then the final byte.
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

/// `CSI key ; modifiers u`, where the key's first code is `v` (118), the
/// modifiers include Ctrl, and the event, if given, isn't a release.
fn isCtrlV(params: []const u8) bool {
    var fields = std.mem.splitScalar(u8, params, ';');
    const key = fields.next() orelse return false;
    if (!std.mem.eql(u8, firstCode(key), "118")) return false;
    const mods = fields.next() orelse return false;
    var parts = std.mem.splitScalar(u8, mods, ':');
    const value = std.fmt.parseInt(u32, parts.next().?, 10) catch return false;
    // A release is event type 3.
    if (parts.next()) |event| if (std.mem.eql(u8, event, "3")) return false;
    return value >= 1 and (value - 1) & ctrl_bit != 0;
}

/// `CSI 27 ; modifiers ; 118 ~`.
fn isModifyOtherKeysCtrlV(params: []const u8) bool {
    var fields = std.mem.splitScalar(u8, params, ';');
    if (!std.mem.eql(u8, fields.next() orelse return false, "27")) return false;
    const value = std.fmt.parseInt(u32, fields.next() orelse return false, 10) catch return false;
    if (!std.mem.eql(u8, fields.next() orelse return false, "118")) return false;
    return value >= 1 and (value - 1) & ctrl_bit != 0;
}

/// In both encodings, the modifiers are 1 plus a bit field.
const ctrl_bit = 4;

/// A key's code before any `:`-separated alternates.
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

//! ssh's escape sequences in typed input. The escape character at the start
//! of a line is held back. A '.' after it returns .disconnect, a second
//! escape character sends one, and any other byte sends both. session.zig
//! passes the terminal Reader's input through an Escape.

const std = @import("std");
const assert = std.debug.assert;

pub const Action = enum {
    disconnect,
};

/// forward is the input to send, a slice of feed's out. With an action, the
/// input after the sequence is dropped.
pub const Result = struct {
    forward: []u8,
    action: ?Action = null,
};

pub const Escape = struct {
    /// null turns escapes off.
    char: ?u8 = '~',
    state: State = .line_start,

    const State = enum {
        /// Before any input, or after CR or LF.
        line_start,
        mid_line,
        /// The escape character was held at the start of a line.
        pending,
    };

    /// out must hold input.len + 1 bytes, since a held escape character
    /// comes out with the byte after it. The state carries over between
    /// calls.
    pub fn feed(e: *Escape, input: []const u8, out: []u8) Result {
        assert(out.len >= input.len + 1);

        const char = e.char orelse {
            @memcpy(out[0..input.len], input);
            return .{ .forward = out[0..input.len] };
        };

        var len: usize = 0;
        for (input) |byte| {
            switch (e.state) {
                .line_start => if (byte == char) {
                    e.state = .pending;
                    continue;
                },

                .mid_line => {},

                .pending => {
                    if (byte == '.') {
                        e.state = .mid_line;
                        return .{ .forward = out[0..len], .action = .disconnect };
                    }

                    if (byte != char) {
                        out[len] = char;
                        len += 1;
                    }
                },
            }

            out[len] = byte;
            len += 1;
            e.state = if (byte == '\r' or byte == '\n') .line_start else .mid_line;
        }
        return .{ .forward = out[0..len] };
    }
};

const testing = std.testing;

const Expected = struct {
    forward: []const u8,
    action: ?Action = null,
};

fn expectFeed(e: *Escape, input: []const u8, expected: Expected) !void {
    var buf: [64]u8 = undefined;
    const result = e.feed(input, &buf);
    try testing.expectEqualStrings(expected.forward, result.forward);
    try testing.expectEqual(expected.action, result.action);
}

test "tilde dot after a carriage return disconnects" {
    var e: Escape = .{};
    try expectFeed(&e, "ls\r~.rest", .{ .forward = "ls\r", .action = .disconnect });
}

test "tilde dot after a line feed disconnects" {
    var e: Escape = .{};
    try expectFeed(&e, "ls\n~.", .{ .forward = "ls\n", .action = .disconnect });
}

test "tilde dot at the start of input disconnects" {
    var e: Escape = .{};
    try expectFeed(&e, "~.", .{ .forward = "", .action = .disconnect });
}

test "double tilde forwards one tilde" {
    var e: Escape = .{};
    try expectFeed(&e, "~~.", .{ .forward = "~." });
}

test "tilde and another byte are both forwarded" {
    var e: Escape = .{};
    try expectFeed(&e, "~x", .{ .forward = "~x" });
    try expectFeed(&e, "\r~\r~.", .{ .forward = "\r~\r", .action = .disconnect });
}

test "tilde mid-line is forwarded" {
    var e: Escape = .{};
    try expectFeed(&e, "a~.", .{ .forward = "a~." });
}

test "escape split across calls" {
    var e: Escape = .{};
    try expectFeed(&e, "echo\r", .{ .forward = "echo\r" });
    try expectFeed(&e, "~", .{ .forward = "" });
    try expectFeed(&e, ".", .{ .forward = "", .action = .disconnect });

    e = .{};
    try expectFeed(&e, "~", .{ .forward = "" });
    try expectFeed(&e, "x", .{ .forward = "~x" });
    try expectFeed(&e, "~.", .{ .forward = "~." });
}

test "custom escape character" {
    var e: Escape = .{ .char = '%' };
    try expectFeed(&e, "~.", .{ .forward = "~." });
    try expectFeed(&e, "\r%%\r%x\r%.", .{ .forward = "\r%\r%x\r", .action = .disconnect });
}

test "disabled escape forwards everything" {
    var e: Escape = .{ .char = null };
    try expectFeed(&e, "~.\r~.~~", .{ .forward = "~.\r~.~~" });
}

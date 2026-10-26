//! ssh's escape sequences over the bytes read from the user's terminal.
//!
//! The escape character is recognized after a carriage return or line feed
//! and at the start of input. `~.` disconnects and `~~` forwards one `~`.
//! Any other byte after `~` is forwarded along with the `~`.
//!
//! With the Kitty keyboard protocol's report-all-keys flag set, the terminal
//! encodes `~` and Enter as CSI sequences, and escapes are not recognized.
//! ssh has the same limitation.
const std = @import("std");
const assert = std.debug.assert;

pub const Action = enum {
    disconnect,
};

pub const Result = struct {
    /// A prefix of the `out` passed to `feed`.
    forward: []u8,
    /// Input after the escape that produced an action was not processed.
    action: ?Action = null,
};

pub const Escape = struct {
    /// Null disables escapes, like ssh's `EscapeChar none`.
    char: ?u8 = '~',
    state: State = .line_start,

    const State = enum {
        line_start,
        mid_line,
        /// The escape character was read at the start of a line and not
        /// forwarded.
        pending,
    };

    /// Asserts `out.len >= input.len + 1`. A pending escape character from
    /// the previous call can be forwarded with the first byte of `input`.
    pub fn feed(e: *Escape, input: []const u8, out: []u8) Result {
        assert(out.len >= input.len + 1);

        // Escapes are off: forward everything.
        const char = e.char orelse {
            @memcpy(out[0..input.len], input);
            return .{ .forward = out[0..input.len] };
        };

        var len: usize = 0;
        for (input) |byte| {
            switch (e.state) {
                // Hold back an escape character at the start of a line until
                // the next byte shows what it is.
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

                    // `~~` forwards one `~`. Any other byte forwards the held
                    // `~` before it. This is the one place `out` gains a byte
                    // over `input`.
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

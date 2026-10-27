//! The Terminal fed the program's output, and the log of what it consumed.
//!
//! State changes go through `output` and `resize`, which append to the log
//! before applying, so a terminal fed the log from seq 0 reaches the same
//! state.
//!
//! `rebuild` writes bytes that bring a fresh terminal to the same state,
//! for a client attaching to a running session. The log may have dropped
//! its start by then.
//!
//! Query replies (DA, DSR, DECRQM and so on) and external effects come from
//! the stream handler's effect callbacks, which the host installs through
//! `handler`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const vt = @import("ghostty-vt");
const log_pkg = @import("log.zig");
const rebuild_pkg = @import("rebuild.zig");

const Log = log_pkg.Log;

pub const Stream = vt.TerminalStream;
pub const Handler = Stream.Handler;

pub const Options = struct {
    cols: u16,
    rows: u16,
    max_scrollback_bytes: ?usize = 10_000_000,
    max_scrollback_lines: ?usize = null,
    kitty_image_storage_limit: usize = 320 * 1000 * 1000,
    /// In bytes.
    log_capacity: usize = 8 * 1024 * 1024,
    /// The longest unfinished sequence `rebuild` can end with.
    max_continuation: usize = 1024 * 1024,
};

pub const Primary = struct {
    gpa: Allocator,
    terminal: vt.Terminal,
    /// Points at `terminal`. A Primary must not be moved.
    stream: Stream,
    log: Log,
    /// Host data for effect callbacks, which receive only the handler. See
    /// `fromHandler`.
    context: ?*anyopaque = null,

    pub fn create(gpa: Allocator, io: std.Io, options: Options) !*Primary {
        const self = try gpa.create(Primary);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .terminal = try .init(io, gpa, .{
                .cols = options.cols,
                .rows = options.rows,
                .max_scrollback_bytes = options.max_scrollback_bytes,
                .max_scrollback_lines = options.max_scrollback_lines,
                .kitty_image_storage_limit = options.kitty_image_storage_limit,
            }),
            .stream = undefined,
            .log = .init(gpa, options.log_capacity),
        };
        self.stream = .init(.{
            .allocator = gpa,
            .handler = .init(&self.terminal),
            .continuation_max_bytes = options.max_continuation,
        });
        return self;
    }

    pub fn destroy(self: *Primary) void {
        const gpa = self.gpa;
        self.stream.deinit();
        self.terminal.deinit(gpa);
        self.log.deinit();
        gpa.destroy(self);
    }

    /// For installing effect callbacks such as `write_pty`. The reply
    /// policies such as `title_report` may also be set. None of these
    /// change terminal state.
    pub fn handler(self: *Primary) *Handler {
        return &self.stream.handler;
    }

    /// The Primary whose handler an effect callback was called with.
    pub fn fromHandler(h: *Handler) *Primary {
        const stream: *Stream = @fieldParentPtr("handler", h);
        return @fieldParentPtr("stream", stream);
    }

    /// Appends program output to the log and applies it. Output longer than
    /// `Log.maxOutputLen` is split across records.
    pub fn output(self: *Primary, bytes: []const u8) log_pkg.AppendError!void {
        var rest = bytes;
        while (rest.len > 0) {
            const chunk = rest[0..@min(rest.len, self.log.maxOutputLen())];
            _ = try self.log.append(.{ .output = chunk });
            self.stream.nextSlice(chunk);
            rest = rest[chunk.len..];
        }
    }

    pub const RebuildError = std.Io.Writer.Error || error{
        /// The output ends in an unfinished sequence longer than
        /// `Options.max_continuation`. Try again after more output.
        Unfinished,
    };

    /// Writes bytes that bring a terminal in its initial state, at this
    /// terminal's size, to this terminal's state. When the output ends
    /// inside a sequence, they end with its start, so the next record
    /// finishes it.
    pub fn rebuild(self: *const Primary, w: *std.Io.Writer) RebuildError!void {
        // Checked first, since the rest is wasted without it.
        if (self.stream.continuation.?.broken) return error.Unfinished;
        try rebuild_pkg.write(w, &self.terminal);
        self.stream.writeContinuation(w) catch |err| switch (err) {
            error.ContinuationUnavailable => return error.Unfinished,
            error.ContinuationDisabled => unreachable,
            error.WriteFailed => return error.WriteFailed,
        };
    }

    /// Appends a resize to the log and applies it. The host resizes the PTY
    /// at the same point.
    pub fn resize(self: *Primary, size: log_pkg.Resize) (log_pkg.AppendError || vt.Terminal.ResizeError)!void {
        // Checked before logging so the log holds no record that fails to
        // apply.
        if (size.cols == 0 or size.rows == 0) return error.InvalidValue;
        _ = try self.log.append(.{ .resize = size });
        try self.stream.handler.resize(size.terminal());
    }
};

const testing = std.testing;
const state = @import("state.zig");

test "output and resize are logged in order" {
    const primary: *Primary = try .create(testing.allocator, testing.io, .{ .cols = 10, .rows = 3 });
    defer primary.destroy();

    try primary.output("hi");
    try primary.resize(.{ .cols = 12, .rows = 4 });
    try primary.output("\x1b[1m");
    try testing.expectError(error.InvalidValue, primary.resize(.{ .cols = 0, .rows = 4 }));

    try testing.expectEqual(3, primary.log.nextSeq());
    try testing.expectEqualStrings("hi", (try primary.log.get(0)).payload.output);
    try testing.expectEqual(12, (try primary.log.get(1)).payload.resize.cols);
    try testing.expectEqual(12, primary.terminal.cols);
    try testing.expect(primary.terminal.screens.active.cursor.style.flags.bold);
}

test "output longer than a record is split" {
    const primary: *Primary = try .create(testing.allocator, testing.io, .{
        .cols = 10,
        .rows = 3,
        .log_capacity = 4 * (Log.record_overhead + 8),
    });
    defer primary.destroy();

    const max = primary.log.maxOutputLen();
    const bytes = try testing.allocator.alloc(u8, 2 * max + 1);
    defer testing.allocator.free(bytes);
    @memset(bytes, 'x');
    try primary.output(bytes);
    try testing.expectEqual(3, primary.log.nextSeq());
    try testing.expectEqual(1, (try primary.log.get(primary.log.nextSeq() - 1)).payload.output.len);
}

/// Feeds `bytes` to a fresh terminal and checks it ends in `primary`'s
/// state.
fn expectRebuildMatches(primary: *Primary, bytes: []const u8) !void {
    const copy: *Primary = try .create(testing.allocator, testing.io, .{ .cols = primary.terminal.cols, .rows = primary.terminal.rows });
    defer copy.destroy();
    try copy.output(bytes);
    const want = try state.dumpAlloc(testing.allocator, &primary.terminal);
    defer testing.allocator.free(want);
    const got = try state.dumpAlloc(testing.allocator, &copy.terminal);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

test "a rebuild ends inside the sequence the output ends in" {
    const primary: *Primary = try .create(testing.allocator, testing.io, .{ .cols = 10, .rows = 3 });
    defer primary.destroy();
    try primary.output("ab\x1b]2;ti");

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try primary.rebuild(&out.writer);
    try testing.expect(std.mem.endsWith(u8, out.written(), "\x1b]2;ti"));

    // The rest of the title arrives after the rebuild.
    try primary.output("tle\x1b\\");
    try out.writer.writeAll("tle\x1b\\");
    try expectRebuildMatches(primary, out.written());
    try testing.expectEqualStrings("title", primary.terminal.getTitle().?);
}

test "a rebuild inside a sequence too long to keep waits for its end" {
    const primary: *Primary = try .create(testing.allocator, testing.io, .{ .cols = 10, .rows = 3, .max_continuation = 8 });
    defer primary.destroy();
    try primary.output("\x1b]2;a long title");

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try testing.expectError(error.Unfinished, primary.rebuild(&out.writer));

    try primary.output("\x1b\\");
    out.clearRetainingCapacity();
    try primary.rebuild(&out.writer);
    try expectRebuildMatches(primary, out.written());
}

test "fromHandler finds the primary from an effect callback" {
    const primary: *Primary = try .create(testing.allocator, testing.io, .{ .cols = 10, .rows = 3 });
    defer primary.destroy();

    const Replies = struct {
        bytes: std.ArrayList(u8) = .empty,

        fn writePty(h: *Handler, data: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(Primary.fromHandler(h).context.?));
            self.bytes.appendSlice(testing.allocator, data) catch @panic("OOM");
        }
    };
    var replies: Replies = .{};
    defer replies.bytes.deinit(testing.allocator);
    primary.context = &replies;
    primary.handler().effects.write_pty = &Replies.writePty;

    // DSR 6, a cursor position report.
    try primary.output("ab\x1b[6n");
    try testing.expectEqualStrings("\x1b[1;3R", replies.bytes.items);
}

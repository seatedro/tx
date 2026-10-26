//! The Terminal fed the program's output, and the log replicas replay to
//! reproduce it.
//!
//! State changes go through `output` and `resize`, which append to the log
//! before applying. A replica restored from `snapshot` that applies the log
//! from the returned seq reaches the same state.
//!
//! Query replies (DA, DSR, DECRQM and so on) and external effects come from
//! the stream handler's effect callbacks, which the host installs through
//! `handler`. Replicas leave them null.
const std = @import("std");
const Allocator = std.mem.Allocator;
const vt = @import("ghostty-vt");
const log_pkg = @import("log.zig");

const Log = log_pkg.Log;

pub const Stream = vt.TerminalStream;
pub const Handler = Stream.Handler;

pub const Options = struct {
    cols: u16,
    rows: u16,
    /// Carried in the snapshot.
    max_scrollback_bytes: ?usize = 10_000_000,
    max_scrollback_lines: ?usize = null,
    /// Not carried in the snapshot. Pass the same value as
    /// `replica.Options.kitty_image_storage_limit`.
    kitty_image_storage_limit: usize = 320 * 1000 * 1000,
    /// In bytes.
    log_capacity: usize = 8 * 1024 * 1024,
    /// The longest unfinished sequence a snapshot can carry. A snapshot cut
    /// inside a longer one fails with `ContinuationUnavailable` until the
    /// stream returns to ground or starts a new sequence.
    continuation_max_bytes: usize = 1024 * 1024,
};

pub const SnapshotError = vt.snapshot.EncodeError || Allocator.Error || error{
    /// The unfinished sequence at the cut is longer than
    /// `Options.continuation_max_bytes`. Retry after more output.
    ContinuationUnavailable,
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
            .continuation_max_bytes = options.continuation_max_bytes,
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

    /// Appends a resize to the log and applies it. The host resizes the PTY
    /// at the same point.
    pub fn resize(self: *Primary, size: log_pkg.Resize) (log_pkg.AppendError || vt.Terminal.ResizeError)!void {
        // Checked before logging so the log holds no record that fails to
        // apply.
        if (size.cols == 0 or size.rows == 0) return error.InvalidValue;
        _ = try self.log.append(.{ .resize = size });
        try self.stream.handler.resize(size.terminal());
    }

    /// Encodes the current state, including the stream's unfinished
    /// sequence. Returns the seq of the first record a replica restored
    /// from it must apply.
    pub fn snapshot(self: *Primary, gpa: Allocator, writer: *std.Io.Writer) SnapshotError!u64 {
        var continuation: std.Io.Writer.Allocating = .init(gpa);
        defer continuation.deinit();
        self.stream.writeContinuation(&continuation.writer) catch |err| switch (err) {
            error.WriteFailed => return error.OutOfMemory,
            error.ContinuationDisabled => unreachable,
            error.ContinuationUnavailable => return error.ContinuationUnavailable,
        };
        const bytes = continuation.written();
        try vt.snapshot.encode(gpa, writer, &self.terminal, .{
            .continuation = if (bytes.len == 0) .ground else .{ .bytes = bytes },
        });
        return self.log.nextSeq();
    }
};

const testing = std.testing;

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

test "a snapshot cut inside a sequence carries it" {
    const primary: *Primary = try .create(testing.allocator, testing.io, .{ .cols = 10, .rows = 3 });
    defer primary.destroy();

    try primary.output("a\x1b]2;ti");
    var encoded: std.Io.Writer.Allocating = .init(testing.allocator);
    defer encoded.deinit();
    try testing.expectEqual(1, try primary.snapshot(testing.allocator, &encoded.writer));

    var reader: std.Io.Reader = .fixed(encoded.written());
    var decoded = try vt.snapshot.decode(testing.allocator, testing.io, &reader, .{
        .max_continuation_bytes = 1024,
    });
    defer decoded.deinit(testing.allocator);
    try testing.expectEqualStrings("\x1b]2;ti", decoded.continuation.bytes);
}

test "a snapshot inside a sequence too long to carry fails until the sequence ends" {
    const primary: *Primary = try .create(testing.allocator, testing.io, .{
        .cols = 10,
        .rows = 3,
        .continuation_max_bytes = 8,
    });
    defer primary.destroy();

    var encoded: std.Io.Writer.Allocating = .init(testing.allocator);
    defer encoded.deinit();
    try primary.output("\x1b]2;a long title");
    try testing.expectError(error.ContinuationUnavailable, primary.snapshot(testing.allocator, &encoded.writer));
    try primary.output("\x07");
    try testing.expectEqual(2, try primary.snapshot(testing.allocator, &encoded.writer));
}

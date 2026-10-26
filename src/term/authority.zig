//! The authoritative terminal: the one Terminal fed the program's real
//! output, and the log that lets mirrors reproduce it.
//!
//! Everything that changes terminal state goes through `output` or
//! `resize`, which append to the log before applying, so the log is
//! always exactly the history of this Terminal since it was created. A
//! mirror restored from `snapshot` and given the log from the returned seq
//! on reaches the same state.
//!
//! This is also the only terminal that answers the program. Query replies
//! (DA, DSR, DECRQM and so on) and external effects come from the stream
//! handler's effect callbacks, which the host installs through `handler`.
//! The mirror leaves all of them null.
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
    /// Scrollback limits. They travel in the snapshot, so mirrors match.
    max_scrollback_bytes: ?usize = 10_000_000,
    max_scrollback_lines: ?usize = null,
    /// Not carried by the snapshot: the mirror must be given the same value
    /// (`mirror.Options.kitty_image_storage_limit`).
    kitty_image_storage_limit: usize = 320 * 1000 * 1000,
    /// The log's capacity in bytes.
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

pub const Authority = struct {
    gpa: Allocator,
    terminal: vt.Terminal,
    /// Points at `terminal`, which is why an Authority never moves.
    stream: Stream,
    log: Log,
    /// For the host's effect callbacks, which get only the handler; see
    /// `fromHandler`.
    context: ?*anyopaque = null,

    pub fn create(gpa: Allocator, io: std.Io, options: Options) !*Authority {
        const self = try gpa.create(Authority);
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

    pub fn destroy(self: *Authority) void {
        const gpa = self.gpa;
        self.stream.deinit();
        self.terminal.deinit(gpa);
        self.log.deinit();
        gpa.destroy(self);
    }

    /// The stream handler, for installing effect callbacks such as
    /// `write_pty`. Callbacks may also set `title_report` and the other
    /// reply policies; none of them change terminal state.
    pub fn handler(self: *Authority) *Handler {
        return &self.stream.handler;
    }

    /// The Authority whose handler an effect callback was called with.
    pub fn fromHandler(h: *Handler) *Authority {
        const stream: *Stream = @fieldParentPtr("handler", h);
        return @fieldParentPtr("stream", stream);
    }

    /// Feed program output: append it to the log and apply it. Output
    /// longer than one record allows is split, which the terminal can't
    /// tell apart from one record.
    pub fn output(self: *Authority, bytes: []const u8) log_pkg.AppendError!void {
        var rest = bytes;
        while (rest.len > 0) {
            const chunk = rest[0..@min(rest.len, self.log.maxOutputLen())];
            _ = try self.log.append(.{ .output = chunk });
            self.stream.nextSlice(chunk);
            rest = rest[chunk.len..];
        }
    }

    /// Resize: append it to the log and apply it. The host resizes the PTY
    /// at the same point.
    pub fn resize(self: *Authority, size: log_pkg.Resize) (log_pkg.AppendError || vt.Terminal.ResizeError)!void {
        // Rejected before logging, so the log never holds a record that
        // fails to apply.
        if (size.cols == 0 or size.rows == 0) return error.InvalidValue;
        _ = try self.log.append(.{ .resize = size });
        try self.stream.handler.resize(size.terminal());
    }

    /// Encode a snapshot of the current state, including the stream's
    /// unfinished sequence, and return the seq of the first record a
    /// mirror restored from it must apply.
    pub fn snapshot(self: *Authority, gpa: Allocator, writer: *std.Io.Writer) SnapshotError!u64 {
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
    const authority: *Authority = try .create(testing.allocator, testing.io, .{ .cols = 10, .rows = 3 });
    defer authority.destroy();

    try authority.output("hi");
    try authority.resize(.{ .cols = 12, .rows = 4 });
    try authority.output("\x1b[1m");
    try testing.expectError(error.InvalidValue, authority.resize(.{ .cols = 0, .rows = 4 }));

    try testing.expectEqual(3, authority.log.nextSeq());
    try testing.expectEqualStrings("hi", (try authority.log.get(0)).payload.output);
    try testing.expectEqual(12, (try authority.log.get(1)).payload.resize.cols);
    try testing.expectEqual(12, authority.terminal.cols);
    try testing.expect(authority.terminal.screens.active.cursor.style.flags.bold);
}

test "output longer than a record is split" {
    const authority: *Authority = try .create(testing.allocator, testing.io, .{
        .cols = 10,
        .rows = 3,
        .log_capacity = 4 * (Log.record_overhead + 8),
    });
    defer authority.destroy();

    const max = authority.log.maxOutputLen();
    const bytes = try testing.allocator.alloc(u8, 2 * max + 1);
    defer testing.allocator.free(bytes);
    @memset(bytes, 'x');
    try authority.output(bytes);
    try testing.expectEqual(3, authority.log.nextSeq());
    try testing.expectEqual(1, (try authority.log.get(authority.log.nextSeq() - 1)).payload.output.len);
}

test "effect callbacks reach the authority" {
    const authority: *Authority = try .create(testing.allocator, testing.io, .{ .cols = 10, .rows = 3 });
    defer authority.destroy();

    const Replies = struct {
        bytes: std.ArrayList(u8) = .empty,

        fn writePty(h: *Handler, data: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(Authority.fromHandler(h).context.?));
            self.bytes.appendSlice(testing.allocator, data) catch @panic("OOM");
        }
    };
    var replies: Replies = .{};
    defer replies.bytes.deinit(testing.allocator);
    authority.context = &replies;
    authority.handler().effects.write_pty = &Replies.writePty;

    // DSR 6, a cursor position report.
    try authority.output("ab\x1b[6n");
    try testing.expectEqualStrings("\x1b[1;3R", replies.bytes.items);
}

test "a snapshot cut inside a sequence carries it" {
    const authority: *Authority = try .create(testing.allocator, testing.io, .{ .cols = 10, .rows = 3 });
    defer authority.destroy();

    try authority.output("a\x1b]2;ti");
    var encoded: std.Io.Writer.Allocating = .init(testing.allocator);
    defer encoded.deinit();
    try testing.expectEqual(1, try authority.snapshot(testing.allocator, &encoded.writer));

    var reader: std.Io.Reader = .fixed(encoded.written());
    var decoded = try vt.snapshot.decode(testing.allocator, testing.io, &reader, .{
        .max_continuation_bytes = 1024,
    });
    defer decoded.deinit(testing.allocator);
    try testing.expectEqualStrings("\x1b]2;ti", decoded.continuation.bytes);
}

test "a snapshot inside a sequence too long to carry waits for it to end" {
    const authority: *Authority = try .create(testing.allocator, testing.io, .{
        .cols = 10,
        .rows = 3,
        .continuation_max_bytes = 8,
    });
    defer authority.destroy();

    var encoded: std.Io.Writer.Allocating = .init(testing.allocator);
    defer encoded.deinit();
    try authority.output("\x1b]2;a long title");
    try testing.expectError(error.ContinuationUnavailable, authority.snapshot(testing.allocator, &encoded.writer));
    try authority.output("\x07");
    try testing.expectEqual(2, try authority.snapshot(testing.allocator, &encoded.writer));
}

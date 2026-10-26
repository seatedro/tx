//! A Terminal restored from a primary's snapshot and kept in step by
//! applying the primary's log.
//!
//! All effect callbacks are null, so a replica sends no query replies and
//! fires no external effects. Kitty images load from inline data only
//! (`setKittyGraphicsLoadingLimits(.direct)`), so replayed bytes can't open
//! files or shared memory.
const std = @import("std");
const Allocator = std.mem.Allocator;
const vt = @import("ghostty-vt");
const log = @import("log.zig");

pub const Stream = vt.TerminalStream;

pub const Options = struct {
    /// Must equal the primary's. The snapshot doesn't carry it.
    kitty_image_storage_limit: usize = 320 * 1000 * 1000,
    /// The longest unfinished sequence accepted from a snapshot. Should be
    /// at least the primary's `continuation_max_bytes`.
    max_continuation_bytes: usize = 1024 * 1024,
};

pub const RestoreError = vt.snapshot.DecodeError || error{
    /// Replaying the snapshot's continuation didn't leave the stream in the
    /// state the snapshot described.
    ContinuationMismatch,
};

pub const ApplyError = vt.Terminal.ResizeError || error{
    /// The record's seq is not `next_seq`. A replica that missed a record
    /// needs a new snapshot.
    OutOfOrder,
};

pub const Replica = struct {
    gpa: Allocator,
    terminal: vt.Terminal,
    /// Points at `terminal`. A Replica must not be moved.
    stream: Stream,
    next_seq: u64,

    /// `seq` is the value `Primary.snapshot` returned. Reads one snapshot
    /// from `reader` and leaves the bytes after it unread.
    pub fn restore(
        gpa: Allocator,
        io: std.Io,
        reader: *std.Io.Reader,
        seq: u64,
        options: Options,
    ) (RestoreError || Allocator.Error)!*Replica {
        var decoded = try vt.snapshot.decode(gpa, io, reader, .{
            .max_continuation_bytes = options.max_continuation_bytes,
            .kitty_image_storage_limit = options.kitty_image_storage_limit,
        });
        defer decoded.deinit(gpa);

        const self = try gpa.create(Replica);
        errdefer gpa.destroy(self);
        // The stream points at the Terminal, so the Terminal moves to its
        // final address first.
        self.* = .{
            .gpa = gpa,
            .terminal = decoded.toOwned(),
            .stream = undefined,
            .next_seq = seq,
        };
        errdefer self.terminal.deinit(gpa);
        if (comptime @TypeOf(self.terminal.screens.active.kitty_images) != void) {
            self.terminal.setKittyGraphicsLoadingLimits(.direct);
        }
        // libghostty-vt gives a created alternate screen no line limit and a
        // restored one a limit of 0. Neither keeps scrollback; null matches
        // the primary.
        if (self.terminal.screens.get(.alternate)) |alt| alt.pages.setMaxLines(null);
        self.stream = .init(.{
            .allocator = gpa,
            .handler = .init(&self.terminal),
            .continuation_max_bytes = @max(options.max_continuation_bytes, 1),
        });
        errdefer self.stream.deinit();

        switch (decoded.continuation) {
            .ground => {},
            .bytes => |bytes| {
                self.stream.nextSlice(bytes);
                // The snapshot docs require checking that replay reproduces
                // the continuation.
                var buf: std.Io.Writer.Allocating = .init(gpa);
                defer buf.deinit();
                self.stream.writeContinuation(&buf.writer) catch return error.ContinuationMismatch;
                if (!std.mem.eql(u8, buf.written(), bytes)) return error.ContinuationMismatch;
            },
        }
        return self;
    }

    pub fn destroy(self: *Replica) void {
        const gpa = self.gpa;
        self.stream.deinit();
        self.terminal.deinit(gpa);
        gpa.destroy(self);
    }

    pub fn apply(self: *Replica, record: log.Record) ApplyError!void {
        if (record.seq != self.next_seq) return error.OutOfOrder;
        switch (record.payload) {
            .output => |bytes| self.stream.nextSlice(bytes),
            .resize => |size| try self.stream.handler.resize(size.terminal()),
        }
        self.next_seq += 1;
    }
};

//! A mirror: a Terminal restored from an authority's snapshot and kept in
//! step by applying its log.
//!
//! The mirror only reproduces state. Its handler has every effect callback
//! null, so it never answers a query (the authority does) and never fires
//! an external effect from restored or replayed bytes. It loads Kitty
//! images only from inline data, so no byte it is given can make it open a
//! file or shared memory.
const std = @import("std");
const Allocator = std.mem.Allocator;
const vt = @import("ghostty-vt");
const log = @import("log.zig");

pub const Stream = vt.TerminalStream;

pub const Options = struct {
    /// Must equal the authority's, which the snapshot doesn't carry.
    kitty_image_storage_limit: usize = 320 * 1000 * 1000,
    /// The longest unfinished sequence accepted from a snapshot. Should be
    /// at least the authority's `continuation_max_bytes`.
    max_continuation_bytes: usize = 1024 * 1024,
};

pub const RestoreError = vt.snapshot.DecodeError || error{
    /// Replaying the snapshot's continuation didn't leave the stream in the
    /// state the snapshot described.
    ContinuationMismatch,
};

pub const ApplyError = vt.Terminal.ResizeError || error{
    /// The record isn't the next one. Records must be applied in seq order
    /// without gaps; a mirror that missed one needs a new snapshot.
    OutOfOrder,
};

pub const Mirror = struct {
    gpa: Allocator,
    terminal: vt.Terminal,
    /// Points at `terminal`, which is why a Mirror never moves.
    stream: Stream,
    /// The seq of the next record to apply.
    next_seq: u64,

    /// Restore from one snapshot read from `reader`, cut at `seq` (the value
    /// `Authority.snapshot` returned). Reads exactly the snapshot, leaving
    /// whatever follows it in `reader`.
    pub fn restore(
        gpa: Allocator,
        io: std.Io,
        reader: *std.Io.Reader,
        seq: u64,
        options: Options,
    ) (RestoreError || Allocator.Error)!*Mirror {
        var decoded = try vt.snapshot.decode(gpa, io, reader, .{
            .max_continuation_bytes = options.max_continuation_bytes,
            .kitty_image_storage_limit = options.kitty_image_storage_limit,
        });
        defer decoded.deinit(gpa);

        const self = try gpa.create(Mirror);
        errdefer gpa.destroy(self);
        // The stream must point at the Terminal's final address, so it is
        // moved into place before the stream exists.
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
        // libghostty-vt gives an alternate screen it creates no line limit,
        // but one it restores a limit of zero lines. The alternate screen
        // keeps no scrollback either way, but match the authority's.
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
                // The snapshot docs ask for this check: replay must give back
                // exactly the continuation it came from.
                var buf: std.Io.Writer.Allocating = .init(gpa);
                defer buf.deinit();
                self.stream.writeContinuation(&buf.writer) catch return error.ContinuationMismatch;
                if (!std.mem.eql(u8, buf.written(), bytes)) return error.ContinuationMismatch;
            },
        }
        return self;
    }

    pub fn destroy(self: *Mirror) void {
        const gpa = self.gpa;
        self.stream.deinit();
        self.terminal.deinit(gpa);
        gpa.destroy(self);
    }

    /// Apply the next record of the authority's log.
    pub fn apply(self: *Mirror, record: log.Record) ApplyError!void {
        if (record.seq != self.next_seq) return error.OutOfOrder;
        switch (record.payload) {
            .output => |bytes| self.stream.nextSlice(bytes),
            .resize => |size| try self.stream.handler.resize(size.terminal()),
        }
        self.next_seq += 1;
    }
};

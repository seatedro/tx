//! The ordered records of what the primary terminal consumed: output bytes,
//! and events outside the byte stream that change terminal state. The client
//! stream is built from them, and a replica restored from a snapshot applies
//! them to reach the primary's current state.
//!
//! Seqs number records from 0 without gaps. A reader whose next seq has
//! been dropped from the ring gets `error.Trimmed`: a client then needs a
//! repaint, and a replica a new snapshot.
const std = @import("std");
const Allocator = std.mem.Allocator;
const vt = @import("ghostty-vt");

pub const Record = struct {
    seq: u64,
    payload: Payload,
};

/// Default colors from the host will be added as another variant.
pub const Payload = union(enum) {
    /// Bytes fed to the primary terminal's stream. Where output is split
    /// into records does not affect terminal state.
    output: []const u8,

    /// Applied at this point in the stream on both ends.
    resize: Resize,
};

/// The arguments to libghostty-vt's `Terminal.resize`.
pub const Resize = struct {
    cols: u16,
    rows: u16,
    /// Null if the host doesn't know it. Images and pixel size reports
    /// depend on it.
    cell_size_px: ?CellSize = null,

    pub const CellSize = struct {
        width: u32,
        height: u32,
    };

    pub fn terminal(self: Resize) vt.Terminal.Resize {
        return .{
            .cols = self.cols,
            .rows = self.rows,
            .cell_size_px = if (self.cell_size_px) |c| .{ .width = c.width, .height = c.height } else null,
        };
    }
};

pub const AppendError = Allocator.Error || error{
    /// The record alone would exceed the log's capacity. Split output into
    /// records of at most `maxOutputLen` bytes.
    RecordTooLarge,
};

pub const ReadError = error{
    /// The seq was dropped from the ring. The reader needs a snapshot.
    Trimmed,
    /// The seq has not been appended yet.
    Ahead,
};

/// A bounded ring of records that owns copies of their payloads. When an
/// append would exceed the capacity, the oldest records are dropped.
pub const Log = struct {
    gpa: Allocator,
    capacity: usize,
    /// Bytes charged against `capacity`.
    used: usize = 0,
    entries: std.Deque(Entry) = .empty,
    /// The seq of `entries.at(0)`, or of the next append when empty.
    first_seq: u64 = 0,

    /// Charged per record on top of its payload bytes, so records without
    /// bytes still count against the capacity.
    pub const record_overhead = @sizeOf(Entry);

    const Entry = struct {
        payload: Payload,

        fn cost(self: Entry) usize {
            return record_overhead + switch (self.payload) {
                .output => |bytes| bytes.len,
                .resize => 0,
            };
        }
    };

    pub fn init(gpa: Allocator, capacity: usize) Log {
        return .{ .gpa = gpa, .capacity = capacity };
    }

    pub fn deinit(self: *Log) void {
        while (self.entries.popFront()) |entry| self.free(entry);
        self.entries.deinit(self.gpa);
        self.* = undefined;
    }

    /// The largest `output` payload a record can carry.
    pub fn maxOutputLen(self: *const Log) usize {
        return self.capacity -| record_overhead;
    }

    pub fn nextSeq(self: *const Log) u64 {
        return self.first_seq + self.entries.len;
    }

    /// Equals `nextSeq` when the log is empty.
    pub fn firstSeq(self: *const Log) u64 {
        return self.first_seq;
    }

    /// Copies `payload` into the log, dropping the oldest records to make
    /// room, and returns its seq. Invalidates all `Record`s and `Iterator`s
    /// obtained earlier.
    pub fn append(self: *Log, payload: Payload) AppendError!u64 {
        const owned: Payload = switch (payload) {
            .output => |bytes| owned: {
                if (bytes.len > self.maxOutputLen()) return error.RecordTooLarge;
                break :owned .{ .output = try self.gpa.dupe(u8, bytes) };
            },
            .resize => payload,
        };
        const entry: Entry = .{ .payload = owned };
        errdefer self.free(entry);
        if (entry.cost() > self.capacity) return error.RecordTooLarge;

        try self.entries.ensureUnusedCapacity(self.gpa, 1);
        while (self.used + entry.cost() > self.capacity) self.dropOldest();
        self.entries.pushBackAssumeCapacity(entry);
        self.used += entry.cost();
        return self.nextSeq() - 1;
    }

    /// The record with this seq. Its payload is valid until the next append.
    pub fn get(self: *const Log, seq: u64) ReadError!Record {
        try self.check(seq);
        if (seq == self.nextSeq()) return error.Ahead;
        return .{ .seq = seq, .payload = self.entries.at(@intCast(seq - self.first_seq)).payload };
    }

    /// `seq` may equal `nextSeq`, which yields nothing. Invalidated by the
    /// next append.
    pub fn iterator(self: *const Log, seq: u64) ReadError!Iterator {
        try self.check(seq);
        return .{ .log = self, .seq = seq };
    }

    pub const Iterator = struct {
        log: *const Log,
        seq: u64,

        pub fn next(self: *Iterator) ?Record {
            const record = self.log.get(self.seq) catch return null;
            self.seq += 1;
            return record;
        }
    };

    fn check(self: *const Log, seq: u64) ReadError!void {
        if (seq < self.first_seq) return error.Trimmed;
        if (seq > self.nextSeq()) return error.Ahead;
    }

    fn dropOldest(self: *Log) void {
        const entry = self.entries.popFront().?;
        self.used -= entry.cost();
        self.first_seq += 1;
        self.free(entry);
    }

    fn free(self: *Log, entry: Entry) void {
        switch (entry.payload) {
            .output => |bytes| self.gpa.free(bytes),
            .resize => {},
        }
    }
};

const testing = std.testing;

test "seqs count records from zero in order" {
    var log: Log = .init(testing.allocator, 1024);
    defer log.deinit();

    try testing.expectEqual(0, log.nextSeq());
    try testing.expectEqual(0, try log.append(.{ .output = "ab" }));
    try testing.expectEqual(1, try log.append(.{ .resize = .{ .cols = 80, .rows = 24 } }));
    try testing.expectEqual(2, try log.append(.{ .output = "c" }));

    var it = try log.iterator(0);
    try testing.expectEqualStrings("ab", it.next().?.payload.output);
    const resize = it.next().?;
    try testing.expectEqual(1, resize.seq);
    try testing.expectEqual(80, resize.payload.resize.cols);
    const last = it.next().?;
    try testing.expectEqual(2, last.seq);
    try testing.expectEqualStrings("c", last.payload.output);
    try testing.expectEqual(null, it.next());

    var from_middle = try log.iterator(2);
    try testing.expectEqual(2, from_middle.next().?.seq);
    var at_end = try log.iterator(3);
    try testing.expectEqual(null, at_end.next());
    try testing.expectError(error.Ahead, log.iterator(4));
    try testing.expectError(error.Ahead, log.get(3));
}

test "the log owns copies of output" {
    var log: Log = .init(testing.allocator, 1024);
    defer log.deinit();

    var bytes = "hello".*;
    _ = try log.append(.{ .output = &bytes });
    bytes[0] = 'j';
    try testing.expectEqualStrings("hello", (try log.get(0)).payload.output);
}

test "a full log drops its oldest records" {
    const capacity = 3 * (Log.record_overhead + 10);
    var log: Log = .init(testing.allocator, capacity);
    defer log.deinit();

    for (0..3) |_| _ = try log.append(.{ .output = "0123456789" });
    try testing.expectEqual(0, log.firstSeq());

    // A fourth record of the same size drops one.
    try testing.expectEqual(3, try log.append(.{ .output = "abcdefghij" }));
    try testing.expectEqual(1, log.firstSeq());
    try testing.expectError(error.Trimmed, log.iterator(0));
    try testing.expectError(error.Trimmed, log.get(0));
    try testing.expectEqualStrings("abcdefghij", (try log.get(3)).payload.output);

    // A record twice as big drops two.
    _ = try log.append(.{ .output = "0123456789" ++ "0123456789" });
    try testing.expectEqual(3, log.firstSeq());
    var it = try log.iterator(3);
    try testing.expectEqual(3, it.next().?.seq);
    try testing.expectEqual(4, it.next().?.seq);
    try testing.expectEqual(null, it.next());

    // Records without bytes still count against the capacity.
    for (0..10) |_| _ = try log.append(.{ .resize = .{ .cols = 1, .rows = 1 } });
    try testing.expectEqual(15, log.nextSeq());
    try testing.expectEqual(capacity / Log.record_overhead, log.nextSeq() - log.firstSeq());
    try testing.expect(log.used <= capacity);
}

test "a record larger than the log is refused" {
    var log: Log = .init(testing.allocator, Log.record_overhead + 4);
    defer log.deinit();

    try testing.expectEqual(4, log.maxOutputLen());
    try testing.expectError(error.RecordTooLarge, log.append(.{ .output = "12345" }));
    try testing.expectEqual(0, log.nextSeq());
    _ = try log.append(.{ .output = "1234" });
    try testing.expectEqual(1, log.nextSeq());
}

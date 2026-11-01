//! A Primary's log of the output chunks and resizes it fed its terminal, in
//! order, each numbered by a seq counting from zero. The log holds a bounded
//! number of bytes and drops its oldest records to make room. A reader keeps
//! the seq it wants next. Feeding the records from a seq on to a terminal that
//! saw everything before it brings that terminal to the Primary's state.

const std = @import("std");
const Allocator = std.mem.Allocator;
const vt = @import("ghostty-vt");

/// Output bytes belong to the log and stay valid until a later append drops
/// the record or the log is freed.
pub const Record = struct {
    seq: u64,
    payload: Payload,
};

pub const Payload = union(enum) {
    output: []const u8,

    resize: Resize,
};

pub const Resize = struct {
    cols: u16,
    rows: u16,
    /// Null leaves the terminal's pixel size as it was.
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
    RecordTooLarge,
};

pub const ReadError = error{
    Trimmed,
    Ahead,
};

pub const Log = struct {
    gpa: Allocator,
    capacity: usize,
    used: usize = 0,
    entries: std.Deque(Entry) = .empty,
    first_seq: u64 = 0,

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

    /// capacity is in bytes, and each record costs record_overhead plus its
    /// output.
    pub fn init(gpa: Allocator, capacity: usize) Log {
        return .{ .gpa = gpa, .capacity = capacity };
    }

    pub fn deinit(self: *Log) void {
        while (self.entries.popFront()) |entry| self.free(entry);
        self.entries.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn maxOutputLen(self: *const Log) usize {
        return self.capacity -| record_overhead;
    }

    pub fn nextSeq(self: *const Log) u64 {
        return self.first_seq + self.entries.len;
    }

    pub fn firstSeq(self: *const Log) u64 {
        return self.first_seq;
    }

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

        // Reserving before dropping leaves the log as it was if the
        // allocation fails. The entry's cost is within the capacity, so the
        // loop stops by the time the log is empty.
        try self.entries.ensureUnusedCapacity(self.gpa, 1);
        while (self.used + entry.cost() > self.capacity) self.dropOldest();
        self.entries.pushBackAssumeCapacity(entry);
        self.used += entry.cost();
        return self.nextSeq() - 1;
    }

    pub fn get(self: *const Log, seq: u64) ReadError!Record {
        try self.check(seq);
        if (seq == self.nextSeq()) return error.Ahead;
        return .{ .seq = seq, .payload = self.entries.at(@intCast(seq - self.first_seq)).payload };
    }

    pub fn iterator(self: *const Log, seq: u64) ReadError!Iterator {
        try self.check(seq);
        return .{ .log = self, .seq = seq };
    }

    pub const Iterator = struct {
        log: *const Log,
        seq: u64,

        /// Returns null at the end of the log, and later calls return the
        /// records appended since. Once the next record has been dropped,
        /// every call returns null.
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

    try testing.expectEqual(3, try log.append(.{ .output = "abcdefghij" }));
    try testing.expectEqual(1, log.firstSeq());
    try testing.expectError(error.Trimmed, log.iterator(0));
    try testing.expectError(error.Trimmed, log.get(0));
    try testing.expectEqualStrings("abcdefghij", (try log.get(3)).payload.output);

    _ = try log.append(.{ .output = "0123456789" ++ "0123456789" });
    try testing.expectEqual(3, log.firstSeq());
    var it = try log.iterator(3);
    try testing.expectEqual(3, it.next().?.seq);
    try testing.expectEqual(4, it.next().?.seq);
    try testing.expectEqual(null, it.next());

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

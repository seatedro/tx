//! Messages on a byte stream. A frame is a varint type id, a varint body
//! length, and the body messages.zig encodes. Decoder rebuilds frames from a
//! stream that arrives in chunks of any size, and copies only the frames that
//! span chunks.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const wire = @import("wire.zig");
const messages = @import("messages.zig");
const Message = messages.Message;
const DecodeError = wire.DecodeError;

pub const max_header_len = 2 * wire.max_varint_len;

/// Length of m's frame, header included. encode writes exactly this many
/// bytes, so a buffer of this size and a fixed Writer can't overflow.
pub fn encodedLen(m: Message) usize {
    const body_len = m.encodedLen();
    return wire.varintLen(m.typeId()) + wire.varintLen(body_len) + body_len;
}

/// Writes m as one frame.
pub fn encode(w: *Writer, m: Message) Writer.Error!void {
    try wire.writeVarint(w, m.typeId());
    try wire.writeVarint(w, m.encodedLen());
    try m.encode(w);
}

const Header = struct {
    type_id: u64,
    body_len: usize,
    len: usize,
};

/// Truncated means bytes end inside the header. Oversize is known from the
/// header alone, before any of the body arrives.
fn readHeader(bytes: []const u8, max_body_len: usize) DecodeError!Header {
    const type_id = try wire.readVarint(bytes);
    const body_len = try wire.readVarint(bytes[type_id.len..]);

    if (body_len.value > max_body_len) return error.Oversize;

    return .{
        .type_id = type_id.value,
        .body_len = @intCast(body_len.value),
        .len = type_id.len + body_len.len,
    };
}

/// Decodes the frame at the start of bytes, which other data may follow.
/// Returns the message and the frame's length, or null while bytes hold less
/// than the whole frame. The message points into bytes.
pub fn firstMessage(bytes: []const u8, max_body_len: usize) DecodeError!?struct { Message, usize } {
    const header = readHeader(bytes, max_body_len) catch |err| switch (err) {
        error.Truncated => return null,
        else => return err,
    };
    const len = header.len + header.body_len;
    if (bytes.len < len) return null;
    return .{ try Message.decode(header.type_id, bytes[header.len..len]), len };
}

/// Splits a byte stream into frames. A frame that lies inside one chunk is
/// returned in place and points into that chunk. A frame that spans chunks is
/// assembled in the decoder and stays valid until the next feed or reset.
pub const Decoder = struct {
    gpa: Allocator,
    /// A frame whose header declares a longer body fails with Oversize. It
    /// may change between frames.
    max_body_len: usize,
    /// The unread rest of the chunk given to feed.
    input: []const u8 = &.{},
    /// The start of a frame that the next chunk continues.
    pending: std.ArrayList(u8) = .empty,
    /// The frame most recently assembled in pending, kept until the next feed.
    completed: std.ArrayList(u8) = .empty,

    pub const Error = DecodeError || Allocator.Error;

    pub fn init(gpa: Allocator, max_body_len: usize) Decoder {
        return .{ .gpa = gpa, .max_body_len = max_body_len };
    }

    pub fn deinit(d: *Decoder) void {
        d.pending.deinit(d.gpa);
        d.completed.deinit(d.gpa);
        d.* = undefined;
    }

    /// Drops a partial frame and the unread input, to start on a new stream.
    pub fn reset(d: *Decoder) void {
        d.input = &.{};
        d.pending.clearRetainingCapacity();
        d.completed.clearRetainingCapacity();
    }

    /// Hands the decoder the next chunk of the stream. next or nextRaw must
    /// have returned null for the previous chunk.
    pub fn feed(d: *Decoder, chunk: []const u8) void {
        std.debug.assert(d.input.len == 0);
        d.completed.clearRetainingCapacity();
        d.input = chunk;
    }

    /// Returns the next message, or null when the chunk is used up.
    pub fn next(d: *Decoder) Error!?Message {
        const raw = (try d.nextRaw()) orelse return null;
        return try raw.decode();
    }

    /// A frame with its body not yet decoded. bytes is the whole frame,
    /// header included, and body is the part after the header.
    pub const Raw = struct {
        type_id: u64,
        bytes: []const u8,
        body: []const u8,

        pub fn decode(raw: Raw) DecodeError!Message {
            return Message.decode(raw.type_id, raw.body);
        }
    };

    /// Returns the next frame, or null when the chunk is used up.
    pub fn nextRaw(d: *Decoder) Error!?Raw {
        const header, const bytes = (try d.nextFrame()) orelse return null;
        return .{ .type_id = header.type_id, .bytes = bytes, .body = bytes[header.len..][0..header.body_len] };
    }

    fn nextFrame(d: *Decoder) Error!?struct { Header, []const u8 } {
        if (d.pending.items.len > 0) return d.continuePending();
        if (d.input.len == 0) return null;

        const header = readHeader(d.input, d.max_body_len) catch |err| switch (err) {
            // The chunk ends inside the header, so pending takes fewer than
            // max_header_len bytes.
            error.Truncated => {
                try d.pending.appendSlice(d.gpa, d.input);
                d.input = &.{};
                return null;
            },
            else => return err,
        };

        const total = header.len + header.body_len;
        if (d.input.len >= total) {
            const bytes = d.input[0..total];
            d.input = d.input[total..];
            return .{ header, bytes };
        }

        // max_body_len bounds this allocation.
        try d.pending.ensureTotalCapacity(d.gpa, total);
        d.pending.appendSliceAssumeCapacity(d.input);
        d.input = &.{};
        return null;
    }

    fn continuePending(d: *Decoder) Error!?struct { Header, []const u8 } {
        // Bytes move into pending one at a time until the header parses, so
        // the body length is checked before any of the body is buffered.
        const header = while (true) {
            if (readHeader(d.pending.items, d.max_body_len)) |header| {
                break header;
            } else |err| switch (err) {
                error.Truncated => {},
                else => return err,
            }
            if (d.input.len == 0) return null;
            try d.pending.append(d.gpa, d.input[0]);
            d.input = d.input[1..];
        };

        const total = header.len + header.body_len;
        try d.pending.ensureTotalCapacity(d.gpa, total);
        const n = @min(total - d.pending.items.len, d.input.len);
        d.pending.appendSliceAssumeCapacity(d.input[0..n]);
        d.input = d.input[n..];
        if (d.pending.items.len < total) return null;

        // Bytes go to pending only when a chunk runs out, so a feed completes
        // at most one frame here, and that feed emptied completed.
        std.debug.assert(d.completed.items.len == 0);

        // completed holds the frame until the next feed. pending takes
        // completed's empty buffer.
        std.mem.swap(std.ArrayList(u8), &d.pending, &d.completed);
        return .{ header, d.completed.items };
    }
};

const testing = std.testing;

const samples = [_]Message{
    .{ .hello = .{ .revision = messages.revision, .term = "xterm-ghostty", .cols = 80, .rows = 24 } },
    .{ .hello_reply = .{ .revision = 0 } },
    .{ .attach = .{} },
    .{ .attached = .{ .session_id = 0xfedc_ba98_7654_3210, .resume_key = "k" } },
    .{ .output = .{ .seq = 0, .bytes = &@as([200]u8, @splat('x')) } },
    .{ .unknown = .{ .type_id = 4000, .body = "\x01\x02\xff\xff" } },
    .{ .unknown = .{ .type_id = 1 << 20, .body = &@as([70]u8, @splat('u')) } },
    .{ .unknown = .{ .type_id = 1 << 40, .body = "" } },
    .{ .output = .{ .seq = 1, .bytes = "" } },
    .{ .ack = .{ .seq = 1 } },
    .{ .input = .{ .bytes = "\x1b[A" } },
    .{ .resize = .{ .cols = 100, .rows = 30, .cell_width_px = 9, .cell_height_px = 18 } },
    .{ .unknown = .{ .type_id = messages.ClipboardCopy.type_id + 1, .body = "" } },
    .{ .detach = .{} },
    .{ .exit = .{ .signal = "HUP" } },
    .{ .@"error" = .{ .code = 1, .message = "bye" } },
};

fn sampleStream(gpa: Allocator) ![]u8 {
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    for (samples) |m| try encode(&out.writer, m);
    return out.toOwnedSlice();
}

fn expectSamples(stream: []const u8, splits: []const usize) !void {
    var d: Decoder = .init(testing.allocator, 1024);
    defer d.deinit();
    var i: usize = 0;
    var start: usize = 0;
    for (0..splits.len + 1) |k| {
        const end = if (k < splits.len) splits[k] else stream.len;
        d.feed(stream[start..end]);
        start = end;
        while (try d.next()) |m| {
            try testing.expect(i < samples.len);
            try testing.expectEqualDeep(samples[i], m);
            i += 1;
        }
    }
    try testing.expectEqual(samples.len, i);
}

test firstMessage {
    var buf: [64]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try encode(&w, .{ .clipboard_data = .{ .id = 3 } });
    const len = w.buffered().len;
    try w.writeAll("raw bytes");

    try testing.expectEqual(null, try firstMessage(w.buffered()[0 .. len - 1], 64));
    const m, const used = (try firstMessage(w.buffered(), 64)).?;
    try testing.expectEqual(len, used);
    try testing.expectEqual(3, m.clipboard_data.id);
    try testing.expectError(error.Oversize, firstMessage(w.buffered(), 1));
}

test "encodedLen matches the encoding" {
    for (samples) |m| {
        var out: Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        try encode(&out.writer, m);
        try testing.expectEqual(encodedLen(m), out.written().len);
    }
}

test "a stream decodes in one chunk" {
    const stream = try sampleStream(testing.allocator);
    defer testing.allocator.free(stream);
    try expectSamples(stream, &.{});
}

test "a stream decodes when split at any offset" {
    const stream = try sampleStream(testing.allocator);
    defer testing.allocator.free(stream);
    for (0..stream.len + 1) |i| try expectSamples(stream, &.{i});
    for (0..stream.len + 1) |i| {
        for (i..@min(i + 40, stream.len + 1)) |j| try expectSamples(stream, &.{ i, j });
    }
}

test "a stream decodes one byte at a time" {
    const stream = try sampleStream(testing.allocator);
    defer testing.allocator.free(stream);
    const splits = try testing.allocator.alloc(usize, stream.len);
    defer testing.allocator.free(splits);
    for (splits, 0..) |*s, i| s.* = i;
    try expectSamples(stream, splits);
}

test "a stream decodes with random splits" {
    const stream = try sampleStream(testing.allocator);
    defer testing.allocator.free(stream);
    var prng: std.Random.DefaultPrng = .init(0x7478);
    const random = prng.random();
    var splits: [16]usize = undefined;
    for (0..500) |_| {
        for (&splits) |*s| s.* = random.uintAtMost(usize, stream.len);
        std.mem.sortUnstable(usize, &splits, {}, std.sort.asc(usize));
        try expectSamples(stream, &splits);
    }
}

test "messages split across chunks stay valid until the next feed" {
    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try encode(&out.writer, .{ .input = .{ .bytes = "first" } });
    try encode(&out.writer, .{ .input = .{ .bytes = "second" } });
    try encode(&out.writer, .{ .input = .{ .bytes = "third" } });
    const stream = out.written();

    var d: Decoder = .init(testing.allocator, 64);
    defer d.deinit();
    d.feed(stream[0..3]);
    try testing.expectEqual(null, try d.next());
    d.feed(stream[3 .. stream.len - 2]);
    const first = (try d.next()).?;
    const second = (try d.next()).?;
    try testing.expectEqual(null, try d.next());
    try testing.expectEqualStrings("first", first.input.bytes);
    try testing.expectEqualStrings("second", second.input.bytes);
    d.feed(stream[stream.len - 2 ..]);
    try testing.expectEqualStrings("third", (try d.next()).?.input.bytes);
    try testing.expectEqual(null, try d.next());
}

test "an oversize message fails before its body arrives" {
    var buf: [16]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try wire.writeVarint(&w, messages.Output.type_id);
    try wire.writeVarint(&w, 1025);

    var d: Decoder = .init(testing.allocator, 1024);
    defer d.deinit();
    d.feed(w.buffered());
    try testing.expectError(error.Oversize, d.next());
    try testing.expectEqual(0, d.pending.capacity);

    var split: Decoder = .init(testing.allocator, 1024);
    defer split.deinit();
    split.feed(w.buffered()[0..2]);
    try testing.expectEqual(null, try split.next());
    split.feed(w.buffered()[2..]);
    try testing.expectError(error.Oversize, split.next());

    var huge: Decoder = .init(testing.allocator, 1024);
    defer huge.deinit();
    huge.feed(&.{ 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff });
    try testing.expectError(error.Oversize, huge.next());
}

test "a message at the size limit decodes" {
    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    const m: Message = .{ .input = .{ .bytes = &@as([100]u8, @splat('y')) } };
    try encode(&out.writer, m);
    var d: Decoder = .init(testing.allocator, m.encodedLen());
    defer d.deinit();
    d.feed(out.written());
    try testing.expectEqualDeep(m, (try d.next()).?);
}

test "a truncated body is an error" {
    var d: Decoder = .init(testing.allocator, 1024);
    defer d.deinit();
    d.feed(&.{ 0x05, 0x03, 0x02, 0x05, 'a' });
    try testing.expectError(error.Truncated, d.next());
}

test "a stream that ends inside a message yields nothing more" {
    const stream = try sampleStream(testing.allocator);
    defer testing.allocator.free(stream);
    var d: Decoder = .init(testing.allocator, 1024);
    defer d.deinit();
    d.feed(stream[0 .. stream.len - 1]);
    var n: usize = 0;
    while (try d.next()) |_| n += 1;
    try testing.expectEqual(samples.len - 1, n);
    try testing.expect(d.pending.items.len > 0);
}

const fuzz = @import("fuzz");

test "fuzz: a stream decodes the same whole and in chunks, and its messages encode back" {
    try fuzz.run({}, fuzzStream, .{});
}

fn fuzzStream(_: void, in: fuzz.Input) !void {
    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try writeFuzzStream(in, &out.writer);
    const stream = out.written();

    // One chunk holds the whole stream, so every frame points into stream and
    // stays valid for the comparison below.
    var whole: Decoder = .init(testing.allocator, fuzz_max_body);
    defer whole.deinit();
    var frames: std.ArrayList(Decoder.Raw) = .empty;
    defer frames.deinit(testing.allocator);
    whole.feed(stream);
    const whole_end: Decoder.Error!void = while (true) {
        const raw = (whole.nextRaw() catch |err| break err) orelse break;
        try frames.append(testing.allocator, raw);
        if (raw.decode()) |m| try expectEncodesBack(m) else |_| {}
    };

    var split: Decoder = .init(testing.allocator, fuzz_max_body);
    defer split.deinit();
    var n: usize = 0;
    var start: usize = 0;
    const split_end: Decoder.Error!void = chunks: while (start < stream.len) {
        const end = @min(stream.len, start + in.int(u8, 1, 64));
        split.feed(stream[start..end]);
        start = end;
        while (true) {
            const raw = (split.nextRaw() catch |err| break :chunks err) orelse break;
            try testing.expect(n < frames.items.len);
            try testing.expectEqual(frames.items[n].type_id, raw.type_id);
            try testing.expectEqualSlices(u8, frames.items[n].bytes, raw.bytes);
            n += 1;
        }
    };

    try testing.expectEqual(frames.items.len, n);
    try testing.expectEqual(whole_end, split_end);
}

const fuzz_max_body = 512;

const fuzz_type_ids = ids: {
    var ids: []const u64 = &.{};
    for (@typeInfo(Message).@"union".field_types) |T| {
        if (T != Message.Unknown) ids = ids ++ .{T.type_id};
    }
    break :ids ids[0..ids.len].*;
};

fn writeFuzzStream(in: fuzz.Input, w: *Writer) !void {
    var body_buf: [fuzz_max_body + 64]u8 = undefined;
    for (0..32) |_| {
        if (in.done()) break;
        const type_id = if (in.chance(7, 1))
            fuzz_type_ids[in.index(fuzz_type_ids.len)]
        else
            in.any(u64) & wire.max_varint;

        var body: Writer = .fixed(&body_buf);
        if (in.chance(7, 1)) {
            for (0..16) |_| {
                if (in.done()) break;
                const tag = in.int(u64, 0, 12);
                var value_buf: [64]u8 = undefined;
                (switch (in.index(3)) {
                    0 => wire.writeUintField(&body, tag, in.int(u64, 0, 300)),
                    1 => wire.writeUintField(&body, tag, in.any(u64)),
                    else => wire.writeBytesField(&body, tag, in.bytes(&value_buf)),
                }) catch break;
            }
        } else {
            body.end = in.bytes(&body_buf).len;
        }

        // A declared length that differs from the body's misaligns the frames
        // after it, and one over fuzz_max_body is Oversize.
        const len = if (in.chance(15, 1)) body.end else in.int(u64, 0, fuzz_max_body + 64);
        try wire.writeVarint(w, type_id);
        try wire.writeVarint(w, len);
        try w.writeAll(body.buffered());
    }
}

fn expectEncodesBack(m: Message) !void {
    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try encode(&out.writer, m);
    try testing.expectEqual(encodedLen(m), out.written().len);

    var d: Decoder = .init(testing.allocator, out.written().len);
    defer d.deinit();
    d.feed(out.written());
    try testing.expectEqualDeep(m, (try d.next()).?);
    try testing.expectEqual(null, try d.next());
}

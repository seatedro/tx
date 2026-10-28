//! Messages on a byte stream. Each message is `type varint, length varint,
//! body`, where the length counts the body bytes.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const wire = @import("wire.zig");
const messages = @import("messages.zig");
const Message = messages.Message;
const DecodeError = wire.DecodeError;

/// The type and length varints.
pub const max_header_len = 2 * wire.max_varint_len;

/// The encoded size of `m`, header included.
pub fn encodedLen(m: Message) usize {
    const body_len = m.encodedLen();
    return wire.varintLen(m.typeId()) + wire.varintLen(body_len) + body_len;
}

pub fn encode(w: *Writer, m: Message) Writer.Error!void {
    try wire.writeVarint(w, m.typeId());
    try wire.writeVarint(w, m.encodedLen());
    try m.encode(w);
}

const Header = struct {
    type_id: u64,
    body_len: usize,
    /// Bytes taken by the type and length.
    len: usize,
};

/// Returns error.Truncated if `bytes` ends inside the header.
fn readHeader(bytes: []const u8, max_body_len: usize) DecodeError!Header {
    const type_id = try wire.readVarint(bytes);
    const body_len = try wire.readVarint(bytes[type_id.len..]);

    // Checked before the body arrives. An oversized message is not
    // buffered.
    if (body_len.value > max_body_len) return error.Oversize;

    return .{
        .type_id = type_id.value,
        .body_len = @intCast(body_len.value),
        .len = type_id.len + body_len.len,
    };
}

/// Splits a byte stream into messages. Feed it chunks of any size with
/// `feed`, then call `next` until it returns null.
///
/// A message from `next` points into the chunk given to the last `feed` or
/// into the decoder's buffers. It is valid until the next `feed` or
/// `deinit`, provided the chunk is not modified or freed before then.
///
/// A message split across chunks is copied into a buffer that grows to at
/// most `max_header_len + max_body_len` bytes. A message contained in one
/// chunk is not copied.
///
/// After `next` returns an error other than `error.OutOfMemory`, the stream
/// is unusable.
pub const Decoder = struct {
    gpa: Allocator,
    max_body_len: usize,
    /// The unread part of the last chunk.
    input: []const u8 = &.{},
    /// The received bytes of a message split across chunks.
    pending: std.ArrayList(u8) = .empty,
    /// The bytes of the message last completed in `pending`. Kept until
    /// the next `feed`.
    completed: std.ArrayList(u8) = .empty,

    pub const Error = DecodeError || Allocator.Error;

    /// `max_body_len` limits the body length of a message in bytes.
    pub fn init(gpa: Allocator, max_body_len: usize) Decoder {
        return .{ .gpa = gpa, .max_body_len = max_body_len };
    }

    pub fn deinit(d: *Decoder) void {
        d.pending.deinit(d.gpa);
        d.completed.deinit(d.gpa);
        d.* = undefined;
    }

    /// Drops what was fed and a message received in part, for a new
    /// stream.
    pub fn reset(d: *Decoder) void {
        d.input = &.{};
        d.pending.clearRetainingCapacity();
        d.completed.clearRetainingCapacity();
    }

    /// Asserts that `next` returned null or an error since the last feed.
    pub fn feed(d: *Decoder, chunk: []const u8) void {
        std.debug.assert(d.input.len == 0);
        d.completed.clearRetainingCapacity();
        d.input = chunk;
    }

    /// Returns the next complete message, or null when the fed bytes are
    /// used up.
    pub fn next(d: *Decoder) Error!?Message {
        const raw = (try d.nextRaw()) orelse return null;
        return try raw.decode();
    }

    /// A message as it arrived, for forwarding it unchanged.
    pub const Raw = struct {
        type_id: u64,
        /// The whole message, header included.
        bytes: []const u8,
        body: []const u8,

        pub fn decode(raw: Raw) DecodeError!Message {
            return Message.decode(raw.type_id, raw.body);
        }
    };

    /// As `next`, without decoding the body.
    pub fn nextRaw(d: *Decoder) Error!?Raw {
        const header, const bytes = (try d.nextFrame()) orelse return null;
        return .{ .type_id = header.type_id, .bytes = bytes, .body = bytes[header.len..][0..header.body_len] };
    }

    /// Returns the next message's header and its bytes, header included.
    fn nextFrame(d: *Decoder) Error!?struct { Header, []const u8 } {
        // A message started in an earlier chunk is finished first.
        if (d.pending.items.len > 0) return d.continuePending();
        if (d.input.len == 0) return null;

        // The chunk ends inside a header: keep what there is.
        const header = readHeader(d.input, d.max_body_len) catch |err| switch (err) {
            error.Truncated => {
                try d.pending.appendSlice(d.gpa, d.input);
                d.input = &.{};
                return null;
            },
            else => return err,
        };

        // The whole message is in the chunk: return it without copying.
        const total = header.len + header.body_len;
        if (d.input.len >= total) {
            const bytes = d.input[0..total];
            d.input = d.input[total..];
            return .{ header, bytes };
        }

        // The chunk ends inside the body. The rest of the chunk belongs to
        // this message.
        try d.pending.ensureTotalCapacity(d.gpa, total);
        d.pending.appendSliceAssumeCapacity(d.input);
        d.input = &.{};
        return null;
    }

    fn continuePending(d: *Decoder) Error!?struct { Header, []const u8 } {
        // The header is read a byte at a time so that `pending` never holds
        // bytes past the end of its message.
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

        // Take as much of the body as this chunk has, and no more.
        const total = header.len + header.body_len;
        try d.pending.ensureTotalCapacity(d.gpa, total);
        const n = @min(total - d.pending.items.len, d.input.len);
        d.pending.appendSliceAssumeCapacity(d.input[0..n]);
        d.input = d.input[n..];
        if (d.pending.items.len < total) return null;

        // `pending` completes at most one message per feed. After it does,
        // bytes go to `pending` only from the end of the chunk.
        std.debug.assert(d.completed.items.len == 0);

        // The message moves to `completed`, which stays valid until the
        // next `feed`, and `pending` is free for the next split message.
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
    .{ .unknown = .{ .type_id = messages.Killed.type_id + 1, .body = "" } },
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

/// Feeds `stream` in chunks ending at each offset in `splits` and checks
/// that the decoder yields `samples`.
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
    // Completes "first" in the buffer, holds "second" whole, and ends
    // inside "third".
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
    // An Output whose length covers a field with a longer value.
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

/// One input: a stream from `writeFuzzStream`, given whole to one decoder
/// and in fuzzed chunks to another. Both must yield the same frames, then
/// stop the same way: out of input, or with the same error. Each frame
/// that decodes must decode the same after it is encoded again.
fn fuzzStream(_: void, in: fuzz.Input) !void {
    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try writeFuzzStream(in, &out.writer);
    const stream = out.written();

    // Whole. Its frames point into `stream`.
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

    // In chunks of 1 to 64 bytes.
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

/// The longest body the fuzz decoders take.
const fuzz_max_body = 512;

/// The type of every message this revision defines.
const fuzz_type_ids = ids: {
    var ids: []const u64 = &.{};
    for (@typeInfo(Message).@"union".field_types) |T| {
        if (T != Message.Unknown) ids = ids ++ .{T.type_id};
    }
    break :ids ids[0..ids.len].*;
};

/// Writes up to 32 frames: mostly of defined types, with bodies of fields
/// with the small tags messages use, and true lengths. The rest of the
/// types, bodies and lengths are anything.
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

        const len = if (in.chance(15, 1)) body.end else in.int(u64, 0, fuzz_max_body + 64);
        try wire.writeVarint(w, type_id);
        try wire.writeVarint(w, len);
        try w.writeAll(body.buffered());
    }
}

/// `m` encodes to `encodedLen(m)` bytes, which decode to `m`.
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

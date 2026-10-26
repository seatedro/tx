//! Variable-length integers and tagged fields.
//!
//! A varint is a QUIC variable-length integer (RFC 9000 §16): the two high
//! bits of the first byte give the length (1, 2, 4 or 8 bytes) and the
//! remaining bits hold a big-endian value of up to 62 bits. Decoding rejects
//! an encoding longer than the value needs.
//!
//! A field is `tag varint, length varint, value`. Value encodings:
//!
//! - Unsigned integer: big-endian with no leading zero bytes, 0 to 8 bytes.
//!   Zero is the empty value.
//! - Bytes and strings: the bytes. Strings are not checked for UTF-8.
//!
//! Field rules: a tag is never reused, a field added later is optional with
//! a default, and a field's type does not change. A decoder skips fields
//! with unknown tags.
const std = @import("std");
const Writer = std.Io.Writer;

pub const DecodeError = error{
    /// The input ends inside a varint, field or message.
    Truncated,
    /// A message length is larger than the decoder's maximum.
    Oversize,
    /// A varint or integer field is longer than its value needs.
    NonMinimal,
    /// A required field is absent.
    MissingField,
    /// A field's value does not decode as the field's type, or an integer
    /// does not fit the field's range.
    WrongType,
};

pub const max_varint: u64 = (1 << 62) - 1;

pub const max_varint_len = 8;

pub fn varintLen(value: u64) usize {
    std.debug.assert(value <= max_varint);
    if (value < 1 << 6) return 1;
    if (value < 1 << 14) return 2;
    if (value < 1 << 30) return 4;
    return 8;
}

/// Asserts `value <= max_varint`.
pub fn writeVarint(w: *Writer, value: u64) Writer.Error!void {
    switch (varintLen(value)) {
        1 => try w.writeByte(@intCast(value)),
        2 => try w.writeInt(u16, @as(u16, @intCast(value)) | 0x4000, .big),
        4 => try w.writeInt(u32, @as(u32, @intCast(value)) | 0x8000_0000, .big),
        8 => try w.writeInt(u64, value | 0xc000_0000_0000_0000, .big),
        else => unreachable,
    }
}

pub const Varint = struct {
    value: u64,
    /// Bytes consumed.
    len: usize,
};

/// Decodes the varint at the start of `bytes`.
pub fn readVarint(bytes: []const u8) DecodeError!Varint {
    if (bytes.len == 0) return error.Truncated;
    const len = @as(usize, 1) << @intCast(bytes[0] >> 6);
    if (bytes.len < len) return error.Truncated;
    var value: u64 = bytes[0] & 0x3f;
    for (bytes[1..len]) |b| value = (value << 8) | b;
    if (len > 1 and varintLen(value) != len) return error.NonMinimal;
    return .{ .value = value, .len = len };
}

pub fn uintLen(value: u64) usize {
    return (64 - @clz(value) + 7) / 8;
}

pub fn writeUint(w: *Writer, value: u64) Writer.Error!void {
    const len = uintLen(value);
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    try w.writeAll(buf[8 - len ..]);
}

/// Decodes an integer field's value as `T`.
pub fn readUint(comptime T: type, value: []const u8) DecodeError!T {
    if (value.len > 8) return error.WrongType;
    if (value.len > 0 and value[0] == 0) return error.NonMinimal;
    var n: u64 = 0;
    for (value) |b| n = (n << 8) | b;
    return std.math.cast(T, n) orelse error.WrongType;
}

pub fn fieldLen(tag: u64, value_len: usize) usize {
    return varintLen(tag) + varintLen(value_len) + value_len;
}

pub fn uintFieldLen(tag: u64, value: u64) usize {
    return fieldLen(tag, uintLen(value));
}

pub fn writeUintField(w: *Writer, tag: u64, value: u64) Writer.Error!void {
    try writeVarint(w, tag);
    try writeVarint(w, uintLen(value));
    try writeUint(w, value);
}

pub fn writeBytesField(w: *Writer, tag: u64, value: []const u8) Writer.Error!void {
    try writeVarint(w, tag);
    try writeVarint(w, value.len);
    try w.writeAll(value);
}

pub const Field = struct {
    tag: u64,
    /// Points into the bytes given to `FieldIterator`.
    value: []const u8,
};

/// Walks the fields of a message body.
pub const FieldIterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) FieldIterator {
        return .{ .bytes = bytes };
    }

    pub fn next(it: *FieldIterator) DecodeError!?Field {
        if (it.pos == it.bytes.len) return null;
        const rest = it.bytes[it.pos..];
        const tag = try readVarint(rest);
        const len = try readVarint(rest[tag.len..]);
        const start = tag.len + len.len;
        if (len.value > rest.len - start) return error.Truncated;
        const end = start + @as(usize, @intCast(len.value));
        it.pos += end;
        return .{ .tag = tag.value, .value = rest[start..end] };
    }
};

const testing = std.testing;

fn expectVarint(value: u64, encoded: []const u8) !void {
    var buf: [max_varint_len]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try writeVarint(&w, value);
    try testing.expectEqualSlices(u8, encoded, w.buffered());
    try testing.expectEqual(encoded.len, varintLen(value));
    const got = try readVarint(encoded);
    try testing.expectEqual(value, got.value);
    try testing.expectEqual(encoded.len, got.len);
}

test "varint round trips at each length boundary" {
    try expectVarint(0, &.{0x00});
    try expectVarint(63, &.{0x3f});
    try expectVarint(64, &.{ 0x40, 0x40 });
    try expectVarint(16383, &.{ 0x7f, 0xff });
    try expectVarint(16384, &.{ 0x80, 0x00, 0x40, 0x00 });
    try expectVarint((1 << 30) - 1, &.{ 0xbf, 0xff, 0xff, 0xff });
    try expectVarint(1 << 30, &.{ 0xc0, 0, 0, 0, 0x40, 0, 0, 0 });
    try expectVarint(max_varint, &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff });
}

test "varint examples from RFC 9000 appendix A.1" {
    try expectVarint(151288809941952652, &.{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c });
    try expectVarint(494878333, &.{ 0x9d, 0x7f, 0x3e, 0x7d });
    try expectVarint(15293, &.{ 0x7b, 0xbd });
    try expectVarint(37, &.{0x25});
}

test "varint decoding ignores bytes after the varint" {
    const got = try readVarint(&.{ 0x40, 0x40, 0xff });
    try testing.expectEqual(64, got.value);
    try testing.expectEqual(2, got.len);
}

test "non-minimal varints are rejected" {
    // RFC 9000 §A.1 lists 0x4025 as a valid two-byte encoding of 37.
    try testing.expectError(error.NonMinimal, readVarint(&.{ 0x40, 0x25 }));
    try testing.expectError(error.NonMinimal, readVarint(&.{ 0x80, 0x00, 0x3f, 0xff }));
    try testing.expectError(error.NonMinimal, readVarint(&.{ 0xc0, 0, 0, 0, 0x3f, 0xff, 0xff, 0xff }));
    try testing.expectError(error.NonMinimal, readVarint(&.{ 0x40, 0x00 }));
}

test "truncated varints are rejected" {
    try testing.expectError(error.Truncated, readVarint(&.{}));
    try testing.expectError(error.Truncated, readVarint(&.{0x40}));
    try testing.expectError(error.Truncated, readVarint(&.{ 0x80, 0x00, 0x40 }));
    try testing.expectError(error.Truncated, readVarint(&.{ 0xc0, 0, 0, 0, 0x40, 0, 0 }));
}

test "integer values round trip" {
    const values = [_]u64{ 0, 1, 0xff, 0x100, 0xffff, 0x1_0000, 1 << 62, std.math.maxInt(u64) };
    for (values) |value| {
        var buf: [8]u8 = undefined;
        var w: Writer = .fixed(&buf);
        try writeUint(&w, value);
        try testing.expectEqual(uintLen(value), w.buffered().len);
        try testing.expectEqual(value, try readUint(u64, w.buffered()));
    }
    try testing.expectEqual(0, uintLen(0));
}

test "integer values that are too long or out of range are rejected" {
    try testing.expectError(error.NonMinimal, readUint(u64, &.{ 0x00, 0x01 }));
    try testing.expectError(error.NonMinimal, readUint(u64, &.{0x00}));
    try testing.expectError(error.WrongType, readUint(u64, &[_]u8{ 0x01, 0, 0, 0, 0, 0, 0, 0, 0 }));
    try testing.expectError(error.WrongType, readUint(u16, &.{ 0x01, 0x00, 0x00 }));
    try testing.expectEqual(0xffff, try readUint(u16, &.{ 0xff, 0xff }));
}

test "field iterator walks fields and rejects a truncated value" {
    var buf: [64]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try writeUintField(&w, 1, 300);
    try writeBytesField(&w, 200, "abc");
    try writeBytesField(&w, 3, "");
    try testing.expectEqual(uintFieldLen(1, 300) + fieldLen(200, 3) + fieldLen(3, 0), w.buffered().len);

    var it: FieldIterator = .init(w.buffered());
    const a = (try it.next()).?;
    try testing.expectEqual(1, a.tag);
    try testing.expectEqual(300, try readUint(u16, a.value));
    const b = (try it.next()).?;
    try testing.expectEqual(200, b.tag);
    try testing.expectEqualStrings("abc", b.value);
    const c = (try it.next()).?;
    try testing.expectEqual(3, c.tag);
    try testing.expectEqual(0, c.value.len);
    try testing.expectEqual(null, try it.next());

    var short: FieldIterator = .init(w.buffered()[0 .. w.buffered().len - fieldLen(3, 0) - 1]);
    _ = try short.next();
    try testing.expectError(error.Truncated, short.next());
}

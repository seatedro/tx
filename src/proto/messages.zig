//! The messages of protocol revision 0.
//!
//! Each message type declares `type_id`, its numeric message type, and
//! `tags`, the field tag of each struct field. A struct field with a default
//! is optional on the wire; one without is required. A null optional field
//! is left out when encoding. When a tag appears more than once in a body,
//! the last occurrence is used.
//!
//! Decoded `[]const u8` fields point into the bytes passed to `decode`.
const std = @import("std");
const Writer = std.Io.Writer;
const wire = @import("wire.zig");
const DecodeError = wire.DecodeError;

pub const revision: u32 = 0;

/// The first message from the client.
pub const Hello = struct {
    revision: u32,
    /// The client's `TERM`.
    term: []const u8,
    /// The client's `COLORTERM`, null if unset.
    colorterm: ?[]const u8 = null,
    cols: u16,
    rows: u16,
    /// Null if the client's terminal doesn't report it.
    cell_width_px: ?u32 = null,
    cell_height_px: ?u32 = null,

    pub const type_id = 1;
    pub const tags = .{
        .revision = 1,
        .term = 2,
        .colorterm = 3,
        .cols = 4,
        .rows = 5,
        .cell_width_px = 6,
        .cell_height_px = 7,
    };

    pub fn encodedLen(m: Hello) usize {
        return bodyLen(Hello, m);
    }

    pub fn encode(m: Hello, w: *Writer) Writer.Error!void {
        return encodeBody(Hello, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Hello {
        return decodeBody(Hello, bytes);
    }
};

/// The server's answer to `Hello`.
pub const HelloReply = struct {
    revision: u32,

    pub const type_id = 2;
    pub const tags = .{ .revision = 1 };

    pub fn encodedLen(m: HelloReply) usize {
        return bodyLen(HelloReply, m);
    }

    pub fn encode(m: HelloReply, w: *Writer) Writer.Error!void {
        return encodeBody(HelloReply, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!HelloReply {
        return decodeBody(HelloReply, bytes);
    }
};

pub const Attach = struct {
    /// Null starts a new session running the user's shell.
    session_id: ?u64 = null,

    pub const type_id = 3;
    pub const tags = .{ .session_id = 1 };

    pub fn encodedLen(m: Attach) usize {
        return bodyLen(Attach, m);
    }

    pub fn encode(m: Attach, w: *Writer) Writer.Error!void {
        return encodeBody(Attach, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Attach {
        return decodeBody(Attach, bytes);
    }
};

pub const Attached = struct {
    session_id: u64,
    /// The key that resumes the session on a new connection (see
    /// `auth.resume_`). Replaced at each attach.
    resume_key: []const u8,
    /// The bytes of input the session got from the client since it
    /// attached, counted across resumes. The client sends again the input
    /// that follows them.
    input_offset: u64 = 0,

    pub const type_id = 4;
    pub const tags = .{ .session_id = 1, .resume_key = 2, .input_offset = 3 };

    pub fn encodedLen(m: Attached) usize {
        return bodyLen(Attached, m);
    }

    pub fn encode(m: Attached, w: *Writer) Writer.Error!void {
        return encodeBody(Attached, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Attached {
        return decodeBody(Attached, bytes);
    }
};

/// Bytes for the client's terminal.
pub const Output = struct {
    seq: u64,
    bytes: []const u8,

    pub const type_id = 5;
    pub const tags = .{ .seq = 1, .bytes = 2 };

    pub fn encodedLen(m: Output) usize {
        return bodyLen(Output, m);
    }

    pub fn encode(m: Output, w: *Writer) Writer.Error!void {
        return encodeBody(Output, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Output {
        return decodeBody(Output, bytes);
    }
};

pub const Ack = struct {
    /// The highest `Output.seq` written to the user's terminal.
    seq: u64,

    pub const type_id = 6;
    pub const tags = .{ .seq = 1 };

    pub fn encodedLen(m: Ack) usize {
        return bodyLen(Ack, m);
    }

    pub fn encode(m: Ack, w: *Writer) Writer.Error!void {
        return encodeBody(Ack, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Ack {
        return decodeBody(Ack, bytes);
    }
};

/// Bytes from the user's terminal.
pub const Input = struct {
    bytes: []const u8,

    pub const type_id = 7;
    pub const tags = .{ .bytes = 1 };

    pub fn encodedLen(m: Input) usize {
        return bodyLen(Input, m);
    }

    pub fn encode(m: Input, w: *Writer) Writer.Error!void {
        return encodeBody(Input, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Input {
        return decodeBody(Input, bytes);
    }
};

pub const Resize = struct {
    cols: u16,
    rows: u16,
    /// Null if the client's terminal doesn't report it.
    cell_width_px: ?u32 = null,
    cell_height_px: ?u32 = null,

    pub const type_id = 8;
    pub const tags = .{
        .cols = 1,
        .rows = 2,
        .cell_width_px = 3,
        .cell_height_px = 4,
    };

    pub fn encodedLen(m: Resize) usize {
        return bodyLen(Resize, m);
    }

    pub fn encode(m: Resize, w: *Writer) Writer.Error!void {
        return encodeBody(Resize, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Resize {
        return decodeBody(Resize, bytes);
    }
};

pub const Detach = struct {
    pub const type_id = 9;
    pub const tags = .{};

    pub fn encodedLen(m: Detach) usize {
        return bodyLen(Detach, m);
    }

    pub fn encode(m: Detach, w: *Writer) Writer.Error!void {
        return encodeBody(Detach, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Detach {
        return decodeBody(Detach, bytes);
    }
};

/// The session's program ended.
pub const Exit = struct {
    /// The exit status. 0 when `signal` is set.
    status: u8 = 0,
    /// The name of the signal that terminated the program, without the
    /// "SIG" prefix, as in RFC 4254 §6.10. Signal numbers differ between
    /// platforms.
    signal: ?[]const u8 = null,

    pub const type_id = 10;
    pub const tags = .{ .status = 1, .signal = 2 };

    pub fn encodedLen(m: Exit) usize {
        return bodyLen(Exit, m);
    }

    pub fn encode(m: Exit, w: *Writer) Writer.Error!void {
        return encodeBody(Exit, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Exit {
        return decodeBody(Exit, bytes);
    }
};

/// The codes of `Error`.
pub const ErrorCode = enum(u32) {
    protocol = 1,
    revision = 2,
    no_session = 3,
    log_trimmed = 4,
    spawn = 5,
    /// The login failed. The message doesn't say why.
    auth = 6,
    /// Another client attached to the session.
    attached_elsewhere = 7,
};

pub const Error = struct {
    code: u32,
    message: []const u8 = "",

    pub const type_id = 11;
    pub const tags = .{ .code = 1, .message = 2 };

    pub fn encodedLen(m: Error) usize {
        return bodyLen(Error, m);
    }

    pub fn encode(m: Error, w: *Writer) Writer.Error!void {
        return encodeBody(Error, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Error {
        return decodeBody(Error, bytes);
    }
};

/// Asks whether the server would accept `key` for `user`. The client probes
/// before it signs: a signature can cost the user a touch or a prompt.
pub const AuthProbe = struct {
    user: []const u8,
    /// An SSH public key blob.
    key: []const u8,

    pub const type_id = 12;
    pub const tags = .{ .user = 1, .key = 2 };

    pub fn encodedLen(m: AuthProbe) usize {
        return bodyLen(AuthProbe, m);
    }

    pub fn encode(m: AuthProbe, w: *Writer) Writer.Error!void {
        return encodeBody(AuthProbe, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!AuthProbe {
        return decodeBody(AuthProbe, bytes);
    }
};

pub const AuthProbeReply = struct {
    /// The probed key.
    key: []const u8,
    accepted: bool,

    pub const type_id = 13;
    pub const tags = .{ .key = 1, .accepted = 2 };

    pub fn encodedLen(m: AuthProbeReply) usize {
        return bodyLen(AuthProbeReply, m);
    }

    pub fn encode(m: AuthProbeReply, w: *Writer) Writer.Error!void {
        return encodeBody(AuthProbeReply, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!AuthProbeReply {
        return decodeBody(AuthProbeReply, bytes);
    }
};

/// Logs in as `user` with a signature over the connection's login
/// transcript (see `auth.login`).
pub const AuthSignature = struct {
    user: []const u8,
    /// An SSH public key blob.
    key: []const u8,
    /// An SSH signature blob.
    signature: []const u8,

    pub const type_id = 14;
    pub const tags = .{ .user = 1, .key = 2, .signature = 3 };

    pub fn encodedLen(m: AuthSignature) usize {
        return bodyLen(AuthSignature, m);
    }

    pub fn encode(m: AuthSignature, w: *Writer) Writer.Error!void {
        return encodeBody(AuthSignature, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!AuthSignature {
        return decodeBody(AuthSignature, bytes);
    }
};

/// The login succeeded.
pub const AuthOk = struct {
    pub const type_id = 15;
    pub const tags = .{};

    pub fn encodedLen(m: AuthOk) usize {
        return bodyLen(AuthOk, m);
    }

    pub fn encode(m: AuthOk, w: *Writer) Writer.Error!void {
        return encodeBody(AuthOk, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!AuthOk {
        return decodeBody(AuthOk, bytes);
    }
};

/// Bytes that bring the client's terminal, at the size the client gave,
/// to the session's state (see `term.rebuild`). Sent on attach, and on a
/// resume that can't continue from the client's seq. A rebuild longer
/// than a message is sent in parts.
pub const Rebuild = struct {
    /// The seq of the first `Output` after the rebuild.
    seq: u64,
    bytes: []const u8,

    pub const type_id = 16;
    pub const tags = .{ .seq = 1, .bytes = 2 };

    pub fn encodedLen(m: Rebuild) usize {
        return bodyLen(Rebuild, m);
    }

    pub fn encode(m: Rebuild, w: *Writer) Writer.Error!void {
        return encodeBody(Rebuild, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Rebuild {
        return decodeBody(Rebuild, bytes);
    }
};

/// Logs in and attaches to a session on a new connection, for a client
/// that was attached to it (see `auth.resume_`). The server answers with
/// `Attached`, or `Error`.
pub const Resume = struct {
    session_id: u64,
    /// The seq of the first `Output` the client hasn't written. Null, or a
    /// seq the log no longer holds, gets a repaint.
    next_seq: ?u64 = null,
    proof: []const u8,

    pub const type_id = 17;
    pub const tags = .{ .session_id = 1, .next_seq = 2, .proof = 3 };

    pub fn encodedLen(m: Resume) usize {
        return bodyLen(Resume, m);
    }

    pub fn encode(m: Resume, w: *Writer) Writer.Error!void {
        return encodeBody(Resume, m, w);
    }

    pub fn decode(bytes: []const u8) DecodeError!Resume {
        return decodeBody(Resume, bytes);
    }
};

pub const Message = union(enum) {
    hello: Hello,
    hello_reply: HelloReply,
    attach: Attach,
    attached: Attached,
    output: Output,
    ack: Ack,
    input: Input,
    resize: Resize,
    detach: Detach,
    exit: Exit,
    @"error": Error,
    auth_probe: AuthProbe,
    auth_probe_reply: AuthProbeReply,
    auth_signature: AuthSignature,
    auth_ok: AuthOk,
    rebuild: Rebuild,
    @"resume": Resume,
    /// A message type this revision does not define.
    unknown: Unknown,

    pub const Unknown = struct {
        type_id: u64,
        body: []const u8,
    };

    // Two messages with one type ID would decode as whichever comes first.
    comptime {
        const types = @typeInfo(Message).@"union".field_types;
        for (types, 0..) |T, i| {
            if (T == Unknown) continue;
            for (types[0..i]) |U| {
                if (U != Unknown and U.type_id == T.type_id)
                    @compileError(@typeName(T) ++ " reuses a message type");
            }
        }
    }

    pub fn typeId(m: Message) u64 {
        return switch (m) {
            .unknown => |u| u.type_id,
            inline else => |v| @TypeOf(v).type_id,
        };
    }

    /// The length of the encoded body.
    pub fn encodedLen(m: Message) usize {
        return switch (m) {
            .unknown => |u| u.body.len,
            inline else => |v| v.encodedLen(),
        };
    }

    /// Writes the body.
    pub fn encode(m: Message, w: *Writer) Writer.Error!void {
        return switch (m) {
            .unknown => |u| w.writeAll(u.body),
            inline else => |v| v.encode(w),
        };
    }

    /// Decodes a body. An unknown `type_id` gives `.unknown`.
    pub fn decode(type_id: u64, body: []const u8) DecodeError!Message {
        // Unrolled at compile time into one comparison per message type.
        inline for (@typeInfo(Message).@"union".field_names, @typeInfo(Message).@"union".field_types) |name, T| {
            if (T != Unknown and type_id == T.type_id)
                return @unionInit(Message, name, try T.decode(body));
        }
        return .{ .unknown = .{ .type_id = type_id, .body = body } };
    }
};

/// Checks a message type's declarations at compile time.
fn checkSchema(comptime M: type) void {
    comptime {
        const info = @typeInfo(M).@"struct";
        const Tags = @TypeOf(M.tags);
        const tag_names = @typeInfo(Tags).@"struct".field_names;
        if (tag_names.len != info.field_names.len)
            @compileError(@typeName(M) ++ ".tags must name each field once");

        // `decodeBody` tracks the fields it has seen in a u64.
        if (info.field_names.len > 64)
            @compileError(@typeName(M) ++ " has more than 64 fields");

        for (info.field_names, info.field_types, 0..) |name, T, i| {
            if (!@hasField(Tags, name))
                @compileError(@typeName(M) ++ "." ++ name ++ " has no tag");

            // Tags are written as varints.
            const tag = @field(M.tags, name);
            if (tag < 0 or tag > wire.max_varint)
                @compileError(@typeName(M) ++ "." ++ name ++ " has an invalid tag");

            for (info.field_names[0..i]) |prev| {
                if (@field(M.tags, prev) == tag)
                    @compileError(@typeName(M) ++ "." ++ name ++ " reuses a tag");
            }

            // Fields are byte strings, bools or unsigned integers of up to
            // 64 bits, optional or not.
            const V = switch (@typeInfo(T)) {
                .optional => |o| o.child,
                else => T,
            };
            if (V != []const u8 and V != bool and !(@typeInfo(V) == .int and
                @typeInfo(V).int.signedness == .unsigned and @typeInfo(V).int.bits <= 64))
                @compileError(@typeName(M) ++ "." ++ name ++ " has an unsupported type");
        }
    }
}

/// The encoded size of one field. `T` is a field type without the optional.
fn valueLen(comptime T: type, tag: u64, value: T) usize {
    if (T == []const u8) return wire.fieldLen(tag, value.len);
    if (T == bool) return wire.uintFieldLen(tag, @intFromBool(value));
    return wire.uintFieldLen(tag, value);
}

fn writeValue(comptime T: type, w: *Writer, tag: u64, value: T) Writer.Error!void {
    if (T == []const u8) return wire.writeBytesField(w, tag, value);
    if (T == bool) return wire.writeUintField(w, tag, @intFromBool(value));
    return wire.writeUintField(w, tag, value);
}

fn readValue(comptime T: type, bytes: []const u8) DecodeError!T {
    if (@typeInfo(T) == .optional) return try readValue(@typeInfo(T).optional.child, bytes);
    if (T == []const u8) return bytes;
    // A bool is the integer 0 or 1.
    if (T == bool) return try wire.readUint(u1, bytes) == 1;
    return wire.readUint(T, bytes);
}

/// The encoded size of `m`'s fields. Null optional fields take no bytes.
fn bodyLen(comptime M: type, m: M) usize {
    comptime checkSchema(M);
    const info = @typeInfo(M).@"struct";
    var len: usize = 0;
    inline for (info.field_names, info.field_types) |name, T| {
        const tag = @field(M.tags, name);
        const value = @field(m, name);
        switch (@typeInfo(T)) {
            .optional => |o| if (value) |v| {
                len += valueLen(o.child, tag, v);
            },
            else => len += valueLen(T, tag, value),
        }
    }
    return len;
}

/// Writes `m`'s fields in declaration order, leaving out null optionals.
fn encodeBody(comptime M: type, m: M, w: *Writer) Writer.Error!void {
    comptime checkSchema(M);
    const info = @typeInfo(M).@"struct";
    inline for (info.field_names, info.field_types) |name, T| {
        const tag = @field(M.tags, name);
        const value = @field(m, name);
        switch (@typeInfo(T)) {
            .optional => |o| if (value) |v| try writeValue(o.child, w, tag, v),
            else => try writeValue(T, w, tag, value),
        }
    }
}

fn decodeBody(comptime M: type, bytes: []const u8) DecodeError!M {
    comptime checkSchema(M);
    const info = @typeInfo(M).@"struct";
    var m: M = undefined;

    // Bit i is set once struct field i has been read.
    var seen: u64 = 0;

    // Fields can come in any order. A tag no struct field has is skipped,
    // and a repeated tag overwrites the earlier value.
    var it: wire.FieldIterator = .init(bytes);
    while (try it.next()) |field| {
        inline for (info.field_names, info.field_types, 0..) |name, T, i| {
            if (field.tag == @field(M.tags, name)) {
                @field(m, name) = try readValue(T, field.value);
                seen |= @as(u64, 1) << i;
            }
        }
    }

    // Absent fields take their defaults. A field without one is required.
    inline for (info.field_names, info.field_types, info.field_attrs, 0..) |name, T, attrs, i| {
        if (seen & (@as(u64, 1) << i) == 0)
            @field(m, name) = attrs.defaultValue(T) orelse return error.MissingField;
    }
    return m;
}

const testing = std.testing;

/// The result points into `buf`.
fn roundTrip(buf: []u8, m: Message) !Message {
    var w: Writer = .fixed(buf);
    try m.encode(&w);
    try testing.expectEqual(m.encodedLen(), w.buffered().len);
    return Message.decode(m.typeId(), w.buffered());
}

test "every message round trips" {
    const samples = [_]Message{
        .{ .hello = .{
            .revision = revision,
            .term = "xterm-ghostty",
            .colorterm = "truecolor",
            .cols = 80,
            .rows = 24,
            .cell_width_px = 10,
            .cell_height_px = 20,
        } },
        .{ .hello_reply = .{ .revision = 7 } },
        .{ .attach = .{ .session_id = std.math.maxInt(u64) } },
        .{ .attach = .{} },
        .{ .attached = .{ .session_id = 0x0123_4567_89ab_cdef, .resume_key = "key", .input_offset = 9 } },
        .{ .output = .{ .seq = 1 << 40, .bytes = "\x1b[1mhi\x1b[m" } },
        .{ .output = .{ .seq = 0, .bytes = "" } },
        .{ .ack = .{ .seq = 300 } },
        .{ .input = .{ .bytes = "\x03" } },
        .{ .resize = .{ .cols = 65535, .rows = 1, .cell_width_px = 0, .cell_height_px = 1 << 31 } },
        .{ .detach = .{} },
        .{ .exit = .{ .status = 255 } },
        .{ .exit = .{ .signal = "KILL" } },
        .{ .@"error" = .{ .code = 4, .message = "no such session" } },
        .{ .auth_probe = .{ .user = "rohit", .key = "blob" } },
        .{ .auth_probe_reply = .{ .key = "blob", .accepted = true } },
        .{ .auth_probe_reply = .{ .key = "blob", .accepted = false } },
        .{ .auth_signature = .{ .user = "rohit", .key = "blob", .signature = "sig" } },
        .{ .auth_ok = .{} },
        .{ .rebuild = .{ .seq = 12, .bytes = "\x1b[Hab" } },
        .{ .rebuild = .{ .seq = 0, .bytes = "" } },
        .{ .@"resume" = .{ .session_id = 3, .next_seq = 40, .proof = "proof" } },
        .{ .@"resume" = .{ .session_id = 3, .proof = "" } },
        .{ .unknown = .{ .type_id = 1000, .body = "\x01\x00" } },
    };
    var buf: [256]u8 = undefined;
    for (samples) |m| try testing.expectEqualDeep(m, try roundTrip(&buf, m));
}

test "absent optional fields decode to their defaults" {
    var buf: [256]u8 = undefined;
    const hello = try roundTrip(&buf, .{ .hello = .{ .revision = 0, .term = "xterm", .cols = 80, .rows = 24 } });
    try testing.expectEqual(null, hello.hello.colorterm);
    try testing.expectEqual(null, hello.hello.cell_width_px);
    try testing.expectEqual(null, hello.hello.cell_height_px);

    try testing.expectEqual(null, (try Attach.decode("")).session_id);
    const exit = try Exit.decode("");
    try testing.expectEqual(0, exit.status);
    try testing.expectEqual(null, exit.signal);
    try testing.expectEqualStrings("", (try Error.decode(&.{ 0x01, 0x00 })).message);
}

test "a missing required field is an error" {
    try testing.expectError(error.MissingField, Output.decode(&.{ 0x01, 0x00 }));
    try testing.expectError(error.MissingField, Hello.decode(""));
    try testing.expectError(error.MissingField, Error.decode(&.{ 0x02, 0x01, 'x' }));
}

test "a field value of the wrong type is an error" {
    // cols = 70000 overflows u16.
    try testing.expectError(error.WrongType, Resize.decode(&.{ 0x01, 0x03, 0x01, 0x11, 0x70, 0x02, 0x00 }));
    // A nine-byte integer.
    try testing.expectError(error.WrongType, Ack.decode(&.{ 0x01, 0x09, 1, 0, 0, 0, 0, 0, 0, 0, 0 }));
    try testing.expectError(error.NonMinimal, Ack.decode(&.{ 0x01, 0x01, 0x00 }));
}

test "a bool is 0 or 1" {
    try testing.expectError(error.WrongType, AuthProbeReply.decode(&.{ 0x01, 0x00, 0x02, 0x01, 0x02 }));
    try testing.expectEqual(false, (try AuthProbeReply.decode(&.{ 0x01, 0x00, 0x02, 0x00 })).accepted);
}

test "unknown fields are skipped" {
    var buf: [64]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try wire.writeBytesField(&w, 1000, "from a later revision");
    try (Ack{ .seq = 9 }).encode(&w);
    try wire.writeUintField(&w, 63, 1);
    try testing.expectEqual(9, (try Ack.decode(w.buffered())).seq);
}

test "the last occurrence of a repeated field is used" {
    try testing.expectEqual(2, (try Ack.decode(&.{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x02 })).seq);
}

test "decoded bytes point into the input" {
    const body = [_]u8{ 0x01, 0x01, 0x05, 0x02, 0x02, 'h', 'i' };
    const output = try Output.decode(&body);
    try testing.expectEqual(5, output.seq);
    try testing.expectEqual(@as([*]const u8, &body) + 5, output.bytes.ptr);
}

test "Hello encoding is stable" {
    var buf: [64]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try (Hello{ .revision = 0, .term = "xterm", .colorterm = "truecolor", .cols = 80, .rows = 300 }).encode(&w);
    try testing.expectEqualSlices(u8, "\x01\x00" ++
        "\x02\x05xterm" ++
        "\x03\x09truecolor" ++
        "\x04\x01\x50" ++
        "\x05\x02\x01\x2c", w.buffered());
}

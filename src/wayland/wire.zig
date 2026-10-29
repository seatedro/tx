//! The Wayland wire format.
//!
//! A message is a header and its arguments, in 32-bit words in the host's
//! byte order. The header is the object's ID, then a word with the
//! message's size in bytes, header included, in its high 16 bits and the
//! opcode in its low 16. Arguments, by type:
//!
//! - int, uint, fixed, object and new_id: one word. A null object is 0.
//! - string: a word with the length, counting the terminating NUL, then
//!   the bytes and the NUL, padded to a word. A null string has length 0.
//! - array: a word with the length, then the bytes, padded to a word.
//! - fd: nothing in the message. File descriptors travel beside the bytes
//!   (`SCM_RIGHTS`), in the order of the messages that carry them.
//!
//! The message's interface and opcode give its arguments' types; nothing
//! on the wire does. `wl_registry.bind` is the one request whose new_id
//! has no fixed interface: it is sent as a string (the interface's name),
//! a uint (the version) and the ID.
//!
//! Nothing here performs I/O or owns file descriptors.
const std = @import("std");
const Allocator = std.mem.Allocator;
const fd_t = std.posix.fd_t;

pub const header_len = 8;

/// The largest message: libwayland's limit, which its clients keep to and
/// expect from servers.
pub const max_message_len = 4096;

pub const DecodeError = error{
    /// A header's size is under the header's own, isn't a multiple of 4,
    /// or is over `max_message_len`.
    BadSize,
    /// An argument runs past the end of its message.
    Truncated,
    /// A string isn't terminated by NUL, or has a NUL before its end.
    BadString,
    /// A message takes a file descriptor that didn't arrive before it.
    MissingFd,
    /// The message is longer than its arguments.
    TrailingBytes,
};

pub const Header = struct {
    object: u32,
    opcode: u16,
    /// In bytes, header included.
    size: u16,

    pub fn read(bytes: *const [header_len]u8) DecodeError!Header {
        const object = std.mem.readInt(u32, bytes[0..4], .native);
        const word = std.mem.readInt(u32, bytes[4..8], .native);
        const size: u16 = @intCast(word >> 16);
        if (size < header_len or size % 4 != 0 or size > max_message_len) return error.BadSize;
        return .{ .object = object, .opcode = @truncate(word), .size = size };
    }
};

pub const Message = struct {
    header: Header,
    /// The arguments' bytes.
    args: []const u8,
};

/// The first message in `bytes` and the bytes it takes, or null if
/// `bytes` ends inside it.
pub fn next(bytes: []const u8) DecodeError!?struct { Message, usize } {
    if (bytes.len < header_len) return null;
    const header = try Header.read(bytes[0..header_len]);
    if (bytes.len < header.size) return null;
    return .{ .{ .header = header, .args = bytes[header_len..header.size] }, header.size };
}

/// Reads a message's arguments, in order. File descriptors come from the
/// front of `fds`, the connection's received descriptors that no message
/// has taken yet. A descriptor `fd` returns belongs to the caller.
pub const Reader = struct {
    bytes: []const u8,
    fds: *std.Deque(fd_t),

    pub fn init(message: Message, fds: *std.Deque(fd_t)) Reader {
        return .{ .bytes = message.args, .fds = fds };
    }

    pub fn uint(r: *Reader) DecodeError!u32 {
        if (r.bytes.len < 4) return error.Truncated;
        defer r.bytes = r.bytes[4..];
        return std.mem.readInt(u32, r.bytes[0..4], .native);
    }

    pub fn int(r: *Reader) DecodeError!i32 {
        return @bitCast(try r.uint());
    }

    /// Null for 0, the null object.
    pub fn object(r: *Reader) DecodeError!?u32 {
        const id = try r.uint();
        return if (id == 0) null else id;
    }

    /// Null for the null string. Without the NUL.
    pub fn string(r: *Reader) DecodeError!?[]const u8 {
        const bytes = try r.sized();
        if (bytes.len == 0) return null;
        if (bytes[bytes.len - 1] != 0) return error.BadString;
        const text = bytes[0 .. bytes.len - 1];
        if (std.mem.indexOfScalar(u8, text, 0) != null) return error.BadString;
        return text;
    }

    pub fn array(r: *Reader) DecodeError![]const u8 {
        return r.sized();
    }

    pub fn fd(r: *Reader) DecodeError!fd_t {
        return r.fds.popFront() orelse error.MissingFd;
    }

    /// Checks that the arguments took the whole message.
    pub fn end(r: *const Reader) DecodeError!void {
        if (r.bytes.len != 0) return error.TrailingBytes;
    }

    /// A length word, then that many bytes, padded to a word.
    fn sized(r: *Reader) DecodeError![]const u8 {
        const len = try r.uint();
        const padded = std.mem.alignForward(usize, len, 4);
        if (r.bytes.len < padded) return error.Truncated;
        defer r.bytes = r.bytes[padded..];
        return r.bytes[0..len];
    }
};

/// An argument of an event being written.
pub const Arg = union(enum) {
    /// Also an object or a new_id.
    uint: u32,
    int: i32,
    /// Null for the null string. Without the NUL.
    string: ?[]const u8,
    array: []const u8,
    fd: fd_t,

    /// Bytes in the message.
    fn len(arg: Arg) usize {
        return switch (arg) {
            .uint, .int => 4,
            .string => |s| if (s) |text| 4 + std.mem.alignForward(usize, text.len + 1, 4) else 4,
            .array => |bytes| 4 + std.mem.alignForward(usize, bytes.len, 4),
            .fd => 0,
        };
    }
};

pub const EncodeError = Allocator.Error || error{
    /// The message would be over `max_message_len`.
    MessageTooLong,
    /// A string has a NUL in it.
    BadString,
};

/// Events waiting to be sent, and the file descriptors that go with them.
/// The descriptors are the caller's until it sends them; the outbox only
/// keeps them in order.
pub const Outbox = struct {
    bytes: std.ArrayList(u8) = .empty,
    fds: std.ArrayList(fd_t) = .empty,

    pub fn deinit(o: *Outbox, gpa: Allocator) void {
        o.bytes.deinit(gpa);
        o.fds.deinit(gpa);
        o.* = undefined;
    }

    /// Appends an event for `object`. On error nothing is appended.
    pub fn event(o: *Outbox, gpa: Allocator, object: u32, opcode: u16, args: []const Arg) EncodeError!void {
        var size: usize = header_len;
        var fd_count: usize = 0;
        for (args) |arg| {
            switch (arg) {
                .string => |s| if (s) |text| if (std.mem.indexOfScalar(u8, text, 0) != null) return error.BadString,
                .fd => fd_count += 1,
                else => {},
            }
            size += arg.len();
        }
        if (size > max_message_len) return error.MessageTooLong;
        try o.bytes.ensureUnusedCapacity(gpa, size);
        try o.fds.ensureUnusedCapacity(gpa, fd_count);

        // From here nothing fails.
        o.word(object);
        o.word(@as(u32, @intCast(size)) << 16 | opcode);
        for (args) |arg| switch (arg) {
            .uint => |v| o.word(v),
            .int => |v| o.word(@bitCast(v)),
            .string => |s| if (s) |text| {
                o.word(@intCast(text.len + 1));
                o.bytes.appendSliceAssumeCapacity(text);
                o.pad(text.len, text.len + 1);
            } else o.word(0),
            .array => |bytes| {
                o.word(@intCast(bytes.len));
                o.bytes.appendSliceAssumeCapacity(bytes);
                o.pad(bytes.len, bytes.len);
            },
            .fd => |fd| o.fds.appendAssumeCapacity(fd),
        };
    }

    fn word(o: *Outbox, value: u32) void {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, value, .native);
        o.bytes.appendSliceAssumeCapacity(&buf);
    }

    /// NULs after `written` bytes of a value `len` long on the wire, up to
    /// the next word. A string's terminating NUL is the first of them.
    fn pad(o: *Outbox, written: usize, len: usize) void {
        const padded = std.mem.alignForward(usize, len, 4);
        o.bytes.appendNTimesAssumeCapacity(0, padded - written);
    }
};

const testing = std.testing;

/// The bytes of a message, written word by word, with strings padded by
/// hand.
fn words(comptime values: []const u32) [values.len * 4]u8 {
    var out: [values.len * 4]u8 = undefined;
    for (values, 0..) |v, i| std.mem.writeInt(u32, out[i * 4 ..][0..4], v, .native);
    return out;
}

test "an event's words, with a string padded to a word and its NUL counted" {
    var out: Outbox = .{};
    defer out.deinit(testing.allocator);

    // wl_registry.global(name 1, "wl_seat", version 7) on object 2.
    try out.event(testing.allocator, 2, 0, &.{ .{ .uint = 1 }, .{ .string = "wl_seat" }, .{ .uint = 7 } });
    const want = words(&.{ 2, 28 << 16 | 0, 1, 8 }) ++ "wl_seat\x00".* ++ words(&.{7});
    try testing.expectEqualSlices(u8, &want, out.bytes.items);
}

test "events read back, and descriptors keep their order" {
    var out: Outbox = .{};
    defer out.deinit(testing.allocator);
    try out.event(testing.allocator, 5, 1, &.{ .{ .string = "text/plain" }, .{ .fd = 10 } });
    try out.event(testing.allocator, 0xff00_0000, 3, &.{ .{ .string = null }, .{ .array = "abcde" }, .{ .int = -2 }, .{ .fd = 11 } });

    var fds: std.Deque(fd_t) = .empty;
    defer fds.deinit(testing.allocator);
    try fds.pushBackSlice(testing.allocator, out.fds.items);

    const first, const first_len = (try next(out.bytes.items)).?;
    try testing.expectEqual(Header{ .object = 5, .opcode = 1, .size = 24 }, first.header);
    var r: Reader = .init(first, &fds);
    try testing.expectEqualStrings("text/plain", (try r.string()).?);
    try testing.expectEqual(10, try r.fd());
    try r.end();

    const second, _ = (try next(out.bytes.items[first_len..])).?;
    r = .init(second, &fds);
    try testing.expectEqual(null, try r.string());
    try testing.expectEqualStrings("abcde", try r.array());
    try testing.expectEqual(-2, try r.int());
    try testing.expectEqual(11, try r.fd());
    try r.end();
}

test "a message is complete only when its whole size has arrived" {
    const bytes = words(&.{ 1, 12 << 16 | 1, 2 });
    try testing.expectEqual(null, try next(bytes[0..7]));
    try testing.expectEqual(null, try next(bytes[0..11]));
    const message, const len = (try next(&bytes)).?;
    try testing.expectEqual(12, len);
    try testing.expectEqual(4, message.args.len);
}

test "bad sizes" {
    try testing.expectError(error.BadSize, next(&words(&.{ 1, 4 << 16 })));
    try testing.expectError(error.BadSize, next(&words(&.{ 1, 10 << 16 })));
    try testing.expectError(error.BadSize, next(&words(&.{ 1, (max_message_len + 4) << 16 })));
}

test "bad arguments" {
    var fds: std.Deque(fd_t) = .empty;
    defer fds.deinit(testing.allocator);

    const cases = [_]struct { []const u8, DecodeError }{
        // A string's length past the message's end.
        .{ &words(&.{8}), error.Truncated },
        // No NUL at the end, and a NUL inside.
        .{ &(words(&.{4}) ++ "abcd".*), error.BadString },
        .{ &(words(&.{4}) ++ "a\x00c\x00".*), error.BadString },
    };
    for (cases) |case| {
        const bytes, const err = case;
        var r: Reader = .{ .bytes = bytes, .fds = &fds };
        try testing.expectError(err, r.string());
    }

    var r: Reader = .{ .bytes = &words(&.{ 1, 2 }), .fds = &fds };
    try testing.expectError(error.MissingFd, r.fd());
    _ = try r.uint();
    try testing.expectError(error.TrailingBytes, r.end());
}

test "an event that doesn't fit, or has a NUL in a string, appends nothing" {
    var out: Outbox = .{};
    defer out.deinit(testing.allocator);
    const long: [max_message_len]u8 = @splat('a');
    try testing.expectError(error.MessageTooLong, out.event(testing.allocator, 1, 0, &.{.{ .string = &long }}));
    try testing.expectError(error.BadString, out.event(testing.allocator, 1, 0, &.{ .{ .fd = 3 }, .{ .string = "a\x00b" } }));
    try testing.expectEqual(0, out.bytes.items.len);
    try testing.expectEqual(0, out.fds.items.len);
}

const fuzz = @import("fuzz");

test "fuzz: any bytes split into messages, read as any arguments" {
    try fuzz.run({}, struct {
        fn one(_: void, in: fuzz.Input) !void {
            var buf: [512]u8 = undefined;
            var rest: []const u8 = in.bytes(&buf);

            var fds: std.Deque(fd_t) = .empty;
            defer fds.deinit(testing.allocator);
            for (0..in.int(usize, 0, 4)) |i| try fds.pushBack(testing.allocator, @intCast(i));

            while (true) {
                const message, const len = (next(rest) catch return) orelse return;
                rest = rest[len..];
                var r: Reader = .init(message, &fds);
                while (!in.done()) {
                    switch (in.int(u8, 0, 4)) {
                        0 => _ = r.uint() catch break,
                        1 => _ = r.string() catch break,
                        2 => _ = r.array() catch break,
                        3 => _ = r.fd() catch break,
                        else => _ = r.object() catch break,
                    }
                }
                r.end() catch {};
            }
        }
    }.one, .{});
}

test "fuzz: events read back as written" {
    try fuzz.run({}, struct {
        fn one(_: void, in: fuzz.Input) !void {
            var out: Outbox = .{};
            defer out.deinit(testing.allocator);
            var fds: std.Deque(fd_t) = .empty;
            defer fds.deinit(testing.allocator);

            // Arguments of each type, with strings and arrays of any
            // length that fits.
            var strings: [4][64]u8 = undefined;
            var args: [4]Arg = undefined;
            for (&args, &strings) |*arg, *string_buf| {
                const text = in.bytes(string_buf);
                for (text) |*b| if (b.* == 0) {
                    b.* = 1;
                };
                arg.* = switch (in.int(u8, 0, 4)) {
                    0 => .{ .uint = in.any(u32) },
                    1 => .{ .int = in.any(i32) },
                    2 => .{ .string = if (in.chance(1, 7)) null else text },
                    3 => .{ .array = text },
                    else => .{ .fd = in.any(u8) },
                };
            }
            const object = in.any(u32);
            const opcode = in.any(u16);
            try out.event(testing.allocator, object, opcode, &args);
            try fds.pushBackSlice(testing.allocator, out.fds.items);

            const message, const len = (try next(out.bytes.items)).?;
            try testing.expectEqual(out.bytes.items.len, len);
            try testing.expectEqual(object, message.header.object);
            try testing.expectEqual(opcode, message.header.opcode);
            var r: Reader = .init(message, &fds);
            for (args) |arg| switch (arg) {
                .uint => |v| try testing.expectEqual(v, try r.uint()),
                .int => |v| try testing.expectEqual(v, try r.int()),
                .string => |s| if (s) |text| try testing.expectEqualStrings(text, (try r.string()).?) else try testing.expectEqual(null, try r.string()),
                .array => |bytes| try testing.expectEqualSlices(u8, bytes, try r.array()),
                .fd => |fd| try testing.expectEqual(fd, try r.fd()),
            };
            try r.end();
        }
    }.one, .{});
}

//! The knock: a server with a knock key answers only clients that hold it.
//!
//! A QUIC client picks the source connection ID of its first packets. A
//! client with the key makes it `nonce || minute || tag`: 8 random bytes,
//! the Unix time in minutes, and the first 8 bytes of an HMAC-SHA256 of the
//! two under the key. The server reads the ID from the packet's header,
//! with no cryptography or parsing beyond it, and drops the packet unless
//!
//! - the tag is right,
//! - the minute is within `window_minutes` of the server's clock, and
//! - the nonce is new, or came before from the same address and port.
//!
//! For anyone without the key, the server sends nothing, and the port
//! looks closed. A first packet copied off the network can't be reused
//! from another address. The client retransmits its first packet, and
//! sends it again after a Retry, with the same ID and from the same
//! address, so those pass.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const crypto = @import("crypto");

pub const Key = [32]u8;

pub const nonce_len = 8;
const tag_len = 8;

/// The length of a marked connection ID, the most QUIC allows.
pub const cid_len = nonce_len + 4 + tag_len;

/// How far a client's clock may be from the server's.
pub const window_minutes = 5;

/// The most nonces a server remembers. Past it, new clients are dropped
/// until old nonces expire. Only clients with the key add nonces.
const max_seen = 1 << 16;

pub fn generate() Key {
    var key: Key = undefined;
    crypto.random(&key);
    return key;
}

/// The Unix time in minutes.
pub fn minuteNow(io: Io) i64 {
    return @divFloor(Io.Clock.real.now(io).toSeconds(), 60);
}

/// A connection ID marked with `key`, for a connection started now.
pub fn cid(io: Io, key: *const Key) [cid_len]u8 {
    var nonce: [nonce_len]u8 = undefined;
    crypto.random(&nonce);
    return mark(key, nonce, @intCast(minuteNow(io)));
}

pub fn mark(key: *const Key, nonce: [nonce_len]u8, minute: u32) [cid_len]u8 {
    var out: [cid_len]u8 = undefined;
    out[0..nonce_len].* = nonce;
    std.mem.writeInt(u32, out[nonce_len..][0..4], minute, .big);
    out[nonce_len + 4 ..].* = tag(key, out[0 .. nonce_len + 4]);
    return out;
}

fn tag(key: *const Key, message: []const u8) [tag_len]u8 {
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, message, key);
    return mac[0..tag_len].*;
}

/// The server's side. All of a server's endpoints share one.
pub const Guard = struct {
    gpa: Allocator,
    key: Key,
    /// Nonces that passed, until their minute leaves the window.
    seen: std.AutoHashMapUnmanaged([nonce_len]u8, Seen) = .empty,
    /// The minute `seen` was last pruned in.
    pruned: i64 = 0,

    const Seen = struct {
        from: IpAddress,
        minute: i64,
    };

    pub fn init(gpa: Allocator, key: Key) Guard {
        return .{ .gpa = gpa, .key = key };
    }

    pub fn deinit(g: *Guard) void {
        g.seen.deinit(g.gpa);
        std.crypto.secureZero(u8, &g.key);
    }

    /// Whether a first packet with source connection ID `id`, from `from`,
    /// may be answered.
    pub fn check(g: *Guard, id: []const u8, from: IpAddress, now_minute: i64) bool {
        if (id.len != cid_len) return false;

        // The clock first: it costs nothing.
        const minute: i64 = std.mem.readInt(u32, id[nonce_len..][0..4], .big);
        if (@abs(minute - now_minute) > window_minutes) return false;

        const expected = tag(&g.key, id[0 .. nonce_len + 4]);
        if (!std.crypto.timing_safe.eql([tag_len]u8, expected, id[nonce_len + 4 ..][0..tag_len].*)) return false;

        g.prune(now_minute);
        const nonce = id[0..nonce_len].*;
        if (g.seen.get(nonce)) |seen| return seen.from.eql(&from);
        if (g.seen.count() >= max_seen) return false;
        g.seen.put(g.gpa, nonce, .{ .from = from, .minute = minute }) catch return false;
        return true;
    }

    /// Forgets nonces whose minute is out of the window, once a minute.
    /// Their packets fail the clock check.
    fn prune(g: *Guard, now_minute: i64) void {
        if (now_minute == g.pruned) return;
        g.pruned = now_minute;

        // Copied into a new map. Removing while iterating isn't safe.
        var kept: std.AutoHashMapUnmanaged([nonce_len]u8, Seen) = .empty;
        var it = g.seen.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.minute + window_minutes < now_minute) continue;
            kept.put(g.gpa, entry.key_ptr.*, entry.value_ptr.*) catch break;
        }
        g.seen.deinit(g.gpa);
        g.seen = kept;
    }
};

const testing = std.testing;

test "only a client with the key, inside the window, gets through" {
    const key: Key = @splat(7);
    var g: Guard = .init(testing.allocator, key);
    defer g.deinit();
    const a: IpAddress = try .parseIp4("192.0.2.1", 5000);
    const b: IpAddress = try .parseIp4("192.0.2.2", 5000);
    const now = 29_000_000;

    // Marked now, and at the edges of the window.
    try testing.expect(g.check(&mark(&key, @splat(1), now), a, now));
    try testing.expect(g.check(&mark(&key, @splat(2), now - window_minutes), a, now));
    try testing.expect(g.check(&mark(&key, @splat(3), now + window_minutes), a, now));

    // Outside it, with another key, or not marked at all.
    try testing.expect(!g.check(&mark(&key, @splat(4), now - window_minutes - 1), a, now));
    try testing.expect(!g.check(&mark(&key, @splat(4), now + window_minutes + 1), a, now));
    try testing.expect(!g.check(&mark(&@as(Key, @splat(8)), @splat(4), now), a, now));
    var flipped = mark(&key, @splat(4), now);
    flipped[cid_len - 1] ^= 1;
    try testing.expect(!g.check(&flipped, a, now));
    try testing.expect(!g.check(&@as([16]u8, @splat(0)), a, now));

    // A nonce seen before passes again from the same address only.
    const first = mark(&key, @splat(5), now);
    try testing.expect(g.check(&first, a, now));
    try testing.expect(g.check(&first, a, now));
    try testing.expect(!g.check(&first, b, now));
}

test "nonces are forgotten once their minute leaves the window" {
    const key: Key = @splat(7);
    var g: Guard = .init(testing.allocator, key);
    defer g.deinit();
    const a: IpAddress = try .parseIp4("192.0.2.1", 5000);
    const now = 29_000_000;

    try testing.expect(g.check(&mark(&key, @splat(1), now), a, now));
    try testing.expect(g.check(&mark(&key, @splat(2), now + 3), a, now + 3));
    try testing.expectEqual(2, g.seen.count());

    // The first nonce's minute is out of the window, and it is dropped.
    try testing.expect(g.check(&mark(&key, @splat(3), now + 6), a, now + 6));
    try testing.expectEqual(2, g.seen.count());
    try testing.expect(!g.seen.contains(@splat(1)));
}

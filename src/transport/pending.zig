//! Limits on a server's connections that the app hasn't admitted, such as
//! connections that haven't logged in. All of a server's endpoints share
//! one `Pending`.
//!
//! A connection counts from its first packet until `Conn.admit`, or until
//! it closes. A new connection is dropped while the server has
//! `Limits.max` of them, or `Limits.max_per_source` from the client's IPv4
//! address or IPv6 /64. From `Limits.retry_from` on, a new connection must
//! first show it receives at its address. The endpoint answers its first
//! Initial packet with a Retry, and accepts only an Initial that returns
//! the Retry's token. A connection that isn't admitted within
//! `Limits.timeout_ns` is closed.
const std = @import("std");
const Allocator = std.mem.Allocator;
const IpAddress = std.Io.net.IpAddress;
const crypto = @import("crypto");

pub const Limits = struct {
    max: u32 = 64,
    max_per_source: u32 = 8,
    retry_from: u32 = 16,
    timeout_ns: u64 = 60 * std.time.ns_per_s,
};

/// An IPv4 address, or the /64 of an IPv6 address. One host often has a
/// whole IPv6 /64.
pub const Source = struct {
    family: enum(u8) { ip4, ip6 },
    prefix: [8]u8,

    pub fn of(address: IpAddress) Source {
        var source: Source = .{ .family = .ip4, .prefix = @splat(0) };
        switch (address) {
            .ip4 => |a| @memcpy(source.prefix[0..4], &a.bytes),
            .ip6 => |a| {
                // An IPv4 address on a dual-stack socket, as ::ffff:a.b.c.d.
                const mapped = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
                if (std.mem.eql(u8, a.bytes[0..12], &mapped)) {
                    @memcpy(source.prefix[0..4], a.bytes[12..16]);
                } else {
                    source.family = .ip6;
                    @memcpy(&source.prefix, a.bytes[0..8]);
                }
            },
        }
        return source;
    }
};

pub const Pending = struct {
    gpa: Allocator,
    limits: Limits,
    total: u32 = 0,
    sources: std.AutoHashMapUnmanaged(Source, u32) = .empty,
    /// Keys the Retry tokens. A token from before a restart doesn't verify.
    retry_secret: [32]u8,
    /// Retry packets sent, for tests.
    retries: u64 = 0,

    pub const Admission = enum { accept, retry, drop };

    pub fn init(gpa: Allocator, limits: Limits) Pending {
        var p: Pending = .{ .gpa = gpa, .limits = limits, .retry_secret = undefined };
        crypto.random(&p.retry_secret);
        return p;
    }

    pub fn deinit(p: *Pending) void {
        p.sources.deinit(p.gpa);
    }

    /// What to do with a new connection from `source`. `validated` means
    /// its Initial returned a Retry token.
    pub fn check(p: *const Pending, source: Source, validated: bool) Admission {
        if (p.total >= p.limits.max) return .drop;
        if ((p.sources.get(source) orelse 0) >= p.limits.max_per_source) return .drop;
        if (!validated and p.total >= p.limits.retry_from) return .retry;
        return .accept;
    }

    pub fn add(p: *Pending, source: Source) Allocator.Error!void {
        const entry = try p.sources.getOrPut(p.gpa, source);
        if (!entry.found_existing) entry.value_ptr.* = 0;
        entry.value_ptr.* += 1;
        p.total += 1;
    }

    pub fn remove(p: *Pending, source: Source) void {
        const count = p.sources.getPtr(source).?;
        count.* -= 1;
        if (count.* == 0) _ = p.sources.remove(source);
        p.total -= 1;
    }
};

const testing = std.testing;

test "a source is an IPv4 address or an IPv6 /64" {
    const a: IpAddress = try .parseIp4("192.0.2.1", 1);
    const mapped: IpAddress = try .parseIp6("::ffff:192.0.2.1", 2);
    try testing.expectEqual(Source.of(a), Source.of(mapped));

    const b: IpAddress = try .parseIp6("2001:db8:1:2::1", 1);
    const same_64: IpAddress = try .parseIp6("2001:db8:1:2:ffff::9", 1);
    const other_64: IpAddress = try .parseIp6("2001:db8:1:3::1", 1);
    try testing.expectEqual(Source.of(b), Source.of(same_64));
    try testing.expect(!std.meta.eql(Source.of(b), Source.of(other_64)));
}

test "connections past a limit are dropped, and past retry_from retried" {
    crypto.init(testing.io);
    var p: Pending = .init(testing.allocator, .{ .max = 3, .max_per_source = 2, .retry_from = 1 });
    defer p.deinit();
    const a = Source.of(try .parseIp4("192.0.2.1", 1));
    const b = Source.of(try .parseIp4("192.0.2.2", 1));

    try testing.expectEqual(.accept, p.check(a, false));
    try p.add(a);
    try testing.expectEqual(.retry, p.check(a, false));
    try testing.expectEqual(.accept, p.check(a, true));
    try p.add(a);
    try testing.expectEqual(.drop, p.check(a, true));
    try testing.expectEqual(.accept, p.check(b, true));
    try p.add(b);
    try testing.expectEqual(.drop, p.check(b, true));

    p.remove(a);
    try testing.expectEqual(.accept, p.check(a, true));
    p.remove(a);
    p.remove(b);
    try testing.expectEqual(0, p.total);
    try testing.expectEqual(0, p.sources.count());
}

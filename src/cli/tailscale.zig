//! Whether an address is one of the user's own tailnet nodes, so that tx
//! can trust a host's key on first contact without asking (see `tx.zig`).
//!
//! `tailscale status --json` lists this node and its peers, with each
//! node's tailnet addresses, user and tags. A node is the user's own when
//! it is this node, or when its user is this node's and it has no tags.
//! tailscaled ties each tailnet address to a node by the node's WireGuard
//! key, so a reply from the address comes from that node.
//!
//! It runs only for an address in Tailscale's ranges. On macOS, when
//! `tailscale` isn't in PATH, the app's own binary is the CLI.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;

const clis: []const []const u8 = if (builtin.os.tag.isDarwin())
    &.{ "tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale" }
else
    &.{"tailscale"};

/// The name of the node at `address`, if it is one of the user's own. Null
/// when it isn't, or when Tailscale can't tell.
pub fn ownNode(arena: Allocator, io: Io, address: IpAddress) ?[]const u8 {
    if (!isTailnetAddress(address)) return null;
    const output = status(arena, io) orelse return null;
    return ownNodeIn(arena, output, address);
}

/// `tailscale status --json`, or null if no CLI runs or tailscaled isn't
/// up.
fn status(arena: Allocator, io: Io) ?[]const u8 {
    for (clis) |cli| {
        const result = std.process.run(arena, io, .{
            .argv = &.{ cli, "status", "--json" },
            .stdout_limit = .limited(8 << 20),
            .stderr_limit = .limited(4096),
        }) catch continue;
        return if (result.term.success()) result.stdout else null;
    }
    return null;
}

/// The fields of `tailscale status --json` that tx reads.
const Status = struct {
    Self: ?Node = null,
    Peer: ?std.json.ArrayHashMap(Node) = null,
};

const Node = struct {
    DNSName: []const u8 = "",
    UserID: i64 = 0,
    TailscaleIPs: ?[]const []const u8 = null,
    Tags: ?[]const []const u8 = null,
};

fn ownNodeIn(arena: Allocator, output: []const u8, address: IpAddress) ?[]const u8 {
    const parsed = std.json.parseFromSliceLeaky(Status, arena, output, .{ .ignore_unknown_fields = true }) catch return null;
    const self = parsed.Self orelse return null;
    if (hasAddress(self, address)) return name(self);

    const peers = parsed.Peer orelse return null;
    for (peers.map.values()) |peer| {
        if (!hasAddress(peer, address)) continue;
        // A tagged node belongs to no person, even if its user matches.
        const tagged = if (peer.Tags) |tags| tags.len > 0 else false;
        if (tagged or peer.UserID != self.UserID) return null;
        return name(peer);
    }
    return null;
}

fn hasAddress(node: Node, address: IpAddress) bool {
    for (node.TailscaleIPs orelse return false) |text| {
        const ip = IpAddress.parse(text, 0) catch continue;
        if (sameIp(ip, address)) return true;
    }
    return false;
}

/// The DNS name, without the trailing dot.
fn name(node: Node) []const u8 {
    return std.mem.trimEnd(u8, node.DNSName, ".");
}

fn sameIp(a: IpAddress, b: IpAddress) bool {
    return switch (a) {
        .ip4 => |x| b == .ip4 and std.mem.eql(u8, &x.bytes, &b.ip4.bytes),
        .ip6 => |x| b == .ip6 and std.mem.eql(u8, &x.bytes, &b.ip6.bytes),
    };
}

/// 100.64.0.0/10, or fd7a:115c:a1e0::/48.
fn isTailnetAddress(address: IpAddress) bool {
    return switch (address) {
        .ip4 => |a| a.bytes[0] == 100 and a.bytes[1] & 0xc0 == 64,
        .ip6 => |a| std.mem.eql(u8, a.bytes[0..6], &.{ 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0 }),
    };
}

const testing = std.testing;

test ownNodeIn {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const output =
        \\{
        \\  "Version": "1.98.10",
        \\  "Self": {"DNSName": "pulsar.example.ts.net.", "UserID": 7, "TailscaleIPs": ["100.84.4.32", "fd7a:115c:a1e0::5a29:421"], "Tags": null},
        \\  "Peer": {
        \\    "nodekey:a": {"DNSName": "slopbox.example.ts.net.", "UserID": 7, "TailscaleIPs": ["100.102.22.65", "fd7a:115c:a1e0::8833:1641"]},
        \\    "nodekey:b": {"DNSName": "macbox.example.ts.net.", "UserID": 9, "TailscaleIPs": ["100.95.217.103"], "Tags": ["tag:ci"]},
        \\    "nodekey:c": {"DNSName": "tagged.example.ts.net.", "UserID": 7, "TailscaleIPs": ["100.95.0.1"], "Tags": ["tag:server"]},
        \\    "nodekey:d": {"DNSName": "friend.example.ts.net.", "UserID": 8, "TailscaleIPs": ["100.95.0.2"]}
        \\  },
        \\  "User": {"7": {"LoginName": "rohit@example.com"}}
        \\}
    ;
    const a = arena.allocator();
    try testing.expectEqualStrings("slopbox.example.ts.net", ownNodeIn(a, output, try .parse("100.102.22.65", 8739)).?);
    try testing.expectEqualStrings("slopbox.example.ts.net", ownNodeIn(a, output, try .parse("fd7a:115c:a1e0::8833:1641", 8739)).?);
    try testing.expectEqualStrings("pulsar.example.ts.net", ownNodeIn(a, output, try .parse("100.84.4.32", 8739)).?);

    // Tagged, another user's, or not in the tailnet.
    try testing.expectEqual(null, ownNodeIn(a, output, try .parse("100.95.217.103", 8739)));
    try testing.expectEqual(null, ownNodeIn(a, output, try .parse("100.95.0.1", 8739)));
    try testing.expectEqual(null, ownNodeIn(a, output, try .parse("100.95.0.2", 8739)));
    try testing.expectEqual(null, ownNodeIn(a, output, try .parse("100.64.0.9", 8739)));
    try testing.expectEqual(null, ownNodeIn(a, "not json", try .parse("100.102.22.65", 8739)));
}

test isTailnetAddress {
    try testing.expect(isTailnetAddress(try .parse("100.64.0.1", 0)));
    try testing.expect(isTailnetAddress(try .parse("100.127.255.254", 0)));
    try testing.expect(!isTailnetAddress(try .parse("100.128.0.1", 0)));
    try testing.expect(!isTailnetAddress(try .parse("16.145.9.171", 0)));
    try testing.expect(isTailnetAddress(try .parse("fd7a:115c:a1e0::1", 0)));
    try testing.expect(!isTailnetAddress(try .parse("fd7a:115c:a1e1::1", 0)));
}

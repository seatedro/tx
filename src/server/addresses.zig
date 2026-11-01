const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const PosixAddress = Io.Threaded.PosixAddress;
const c = std.c;

const Ifaddrs = extern struct {
    next: ?*Ifaddrs,
    name: [*:0]const u8,
    flags: c_uint,
    addr: ?*const c.sockaddr,
    netmask: ?*const c.sockaddr,
    dstaddr: ?*const c.sockaddr,
    data: ?*anyopaque,
};

extern "c" fn getifaddrs(ifap: *?*Ifaddrs) c_int;
extern "c" fn freeifaddrs(ifa: ?*Ifaddrs) void;

const iff_up = 0x1;

pub fn isWildcard(address: IpAddress) bool {
    return switch (address) {
        .ip4 => |a| std.mem.allEqual(u8, &a.bytes, 0),
        .ip6 => |a| std.mem.allEqual(u8, &a.bytes, 0),
    };
}

pub fn covers(wildcard: IpAddress, address: IpAddress) bool {
    return wildcard == .ip6 or address == .ip4;
}

pub fn eql(a: IpAddress, b: IpAddress) bool {
    return switch (a) {
        .ip4 => |x| b == .ip4 and std.mem.eql(u8, &x.bytes, &b.ip4.bytes),
        .ip6 => |x| b == .ip6 and std.mem.eql(u8, &x.bytes, &b.ip6.bytes),
    };
}

pub const Scope = enum {
    all,
    tailnet,
};

const Entry = struct {
    interface: []const u8,
    address: IpAddress,
};

pub fn interfaces(gpa: Allocator, wildcard: IpAddress, scope: Scope) ![]IpAddress {
    var list: ?*Ifaddrs = null;
    if (getifaddrs(&list) != 0) return error.GetIfaddrsFailed;
    defer freeifaddrs(list);

    const entries = try upAddresses(gpa, list);
    defer gpa.free(entries);
    return select(gpa, entries, wildcard, scope);
}

pub fn hasTailnet(gpa: Allocator) !bool {
    var list: ?*Ifaddrs = null;
    if (getifaddrs(&list) != 0) return error.GetIfaddrsFailed;
    defer freeifaddrs(list);

    const entries = try upAddresses(gpa, list);
    defer gpa.free(entries);
    for (entries) |e| if (isTailnet(entries, e.interface)) return true;
    return false;
}

fn upAddresses(gpa: Allocator, list: ?*Ifaddrs) ![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    errdefer out.deinit(gpa);

    var it = list;
    while (it) |ifa| : (it = ifa.next) {
        if (ifa.flags & iff_up == 0) continue;
        const sa = ifa.addr orelse continue;
        if (sa.family != c.AF.INET and sa.family != c.AF.INET6) continue;
        try out.append(gpa, .{
            .interface = std.mem.span(ifa.name),
            .address = Io.Threaded.addressFromPosix(@ptrCast(@alignCast(sa))),
        });
    }
    return out.toOwnedSlice(gpa);
}

fn select(gpa: Allocator, entries: []const Entry, wildcard: IpAddress, scope: Scope) ![]IpAddress {
    var out: std.ArrayList(IpAddress) = .empty;
    errdefer out.deinit(gpa);

    for (entries) |e| {
        var address = e.address;
        if (!covers(wildcard, address) or isLinkLocal(address)) continue;
        if (scope == .tailnet and !isLoopback(address) and !isTailnet(entries, e.interface)) continue;

        address.setPort(wildcard.getPort());
        try appendNew(gpa, &out, address);
    }
    return out.toOwnedSlice(gpa);
}

fn isTailnet(entries: []const Entry, interface: []const u8) bool {
    if (std.mem.startsWith(u8, interface, "tailscale")) return true;
    for (entries) |e| {
        if (std.mem.eql(u8, e.interface, interface) and inTailscaleIp6(e.address)) return true;
    }
    return false;
}

fn inTailscaleIp6(address: IpAddress) bool {
    return switch (address) {
        .ip4 => false,
        .ip6 => |a| std.mem.eql(u8, a.bytes[0..6], &.{ 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0 }),
    };
}

pub fn hostLoopback(gpa: Allocator, io: Io, wildcard: IpAddress) ![]IpAddress {
    var name_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const name = std.posix.gethostname(&name_buf) catch return &.{};
    const host: Io.net.HostName = Io.net.HostName.init(name) catch return &.{};

    var buf: [16]Io.net.HostName.LookupResult = undefined;
    var results: Io.Queue(Io.net.HostName.LookupResult) = .init(&buf);
    host.lookup(io, &results, .{ .port = wildcard.getPort() }) catch return &.{};

    var out: std.ArrayList(IpAddress) = .empty;
    errdefer out.deinit(gpa);
    while (results.getOne(io)) |result| switch (result) {
        .address => |address| if (covers(wildcard, address) and isLoopback(address)) try appendNew(gpa, &out, address),
        .canonical_name => {},
    } else |err| switch (err) {
        error.Closed => {},
        error.Canceled => |e| return e,
    }
    return out.toOwnedSlice(gpa);
}

fn appendNew(gpa: Allocator, list: *std.ArrayList(IpAddress), address: IpAddress) !void {
    for (list.items) |a| if (eql(a, address)) return;
    try list.append(gpa, address);
}

fn isLinkLocal(address: IpAddress) bool {
    return switch (address) {
        .ip4 => false,
        .ip6 => |a| a.bytes[0] == 0xfe and a.bytes[1] & 0xc0 == 0x80,
    };
}

fn isLoopback(address: IpAddress) bool {
    return switch (address) {
        .ip4 => |a| a.bytes[0] == 127,
        .ip6 => |a| std.mem.eql(u8, &a.bytes, &(@as([15]u8, @splat(0)) ++ [_]u8{1})),
    };
}

const testing = std.testing;

test "the interfaces include loopback, with the wildcard's port" {
    const any4: IpAddress = try .parseIp4("0.0.0.0", 8739);
    const list = try interfaces(testing.allocator, any4, .all);
    defer testing.allocator.free(list);

    const loopback: IpAddress = try .parseIp4("127.0.0.1", 8739);
    for (list) |a| {
        try testing.expect(a == .ip4);
        try testing.expectEqual(8739, a.getPort());
    }
    for (list) |a| {
        if (eql(a, loopback)) break;
    } else return error.NoLoopback;
}

test "wildcards" {
    try testing.expect(isWildcard(try .parseIp4("0.0.0.0", 1)));
    try testing.expect(isWildcard(try .parseIp6("::", 1)));
    try testing.expect(!isWildcard(try .parseIp4("127.0.0.1", 1)));
    try testing.expect(covers(try .parseIp6("::", 1), try .parseIp4("10.0.0.1", 1)));
    try testing.expect(!covers(try .parseIp4("0.0.0.0", 1), try .parseIp6("::1", 1)));
}

test "a tailnet scope keeps Tailscale's interface and loopback" {
    const ip4 = IpAddress.parseIp4;
    const ip6 = IpAddress.parseIp6;
    const entries = [_]Entry{
        .{ .interface = "lo", .address = try ip4("127.0.0.1", 0) },
        .{ .interface = "lo", .address = try ip6("::1", 0) },
        .{ .interface = "eth0", .address = try ip4("16.145.9.171", 0) },
        .{ .interface = "eth0", .address = try ip6("2600:1f14::1", 0) },
        .{ .interface = "tailscale0", .address = try ip4("100.101.102.103", 0) },
        .{ .interface = "utun3", .address = try ip4("100.90.1.2", 0) },
        .{ .interface = "utun3", .address = try ip6("fd7a:115c:a1e0::1", 0) },
        .{ .interface = "utun4", .address = try ip4("100.70.0.1", 0) },
    };
    const any: IpAddress = try ip6("::", 8739);

    const tailnet = try select(testing.allocator, &entries, any, .tailnet);
    defer testing.allocator.free(tailnet);
    const want = [_]IpAddress{
        try ip4("127.0.0.1", 8739),
        try ip6("::1", 8739),
        try ip4("100.101.102.103", 8739),
        try ip4("100.90.1.2", 8739),
        try ip6("fd7a:115c:a1e0::1", 8739),
    };
    try testing.expectEqual(want.len, tailnet.len);
    for (want, tailnet) |w, got| try testing.expect(eql(w, got) and got.getPort() == 8739);

    const all = try select(testing.allocator, &entries, any, .all);
    defer testing.allocator.free(all);
    try testing.expectEqual(entries.len, all.len);
}

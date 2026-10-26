//! The addresses a server listens on when told to listen on a wildcard
//! address.
//!
//! A UDP socket bound to a wildcard address sends each reply from the
//! address the kernel's routing picks, which need not be the address the
//! client sent to. A QUIC client drops packets from an address it didn't
//! send to, so the server binds a socket to each address instead.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const PosixAddress = Io.Threaded.PosixAddress;
const c = std.c;

/// `struct ifaddrs`. Linux and macOS lay it out the same way.
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

/// IFF_UP on Linux and macOS.
const iff_up = 0x1;

/// Whether `address` is 0.0.0.0 or `::`.
pub fn isWildcard(address: IpAddress) bool {
    return switch (address) {
        .ip4 => |a| std.mem.allEqual(u8, &a.bytes, 0),
        .ip6 => |a| std.mem.allEqual(u8, &a.bytes, 0),
    };
}

/// The addresses a wildcard covers: 0.0.0.0 covers IPv4, and `::` covers
/// IPv4 and IPv6, as a dual-stack socket would.
pub fn covers(wildcard: IpAddress, address: IpAddress) bool {
    return wildcard == .ip6 or address == .ip4;
}

pub fn eql(a: IpAddress, b: IpAddress) bool {
    return switch (a) {
        .ip4 => |x| b == .ip4 and std.mem.eql(u8, &x.bytes, &b.ip4.bytes),
        .ip6 => |x| b == .ip6 and std.mem.eql(u8, &x.bytes, &b.ip6.bytes),
    };
}

/// The addresses of the interfaces that are up and that `wildcard` covers,
/// with `wildcard`'s port. IPv6 link-local addresses are left out: binding
/// one needs its interface, and clients reach a host by other addresses.
pub fn interfaces(gpa: Allocator, wildcard: IpAddress) ![]IpAddress {
    var list: ?*Ifaddrs = null;
    if (getifaddrs(&list) != 0) return error.GetIfaddrsFailed;
    defer freeifaddrs(list);

    var out: std.ArrayList(IpAddress) = .empty;
    errdefer out.deinit(gpa);

    var it = list;
    while (it) |ifa| : (it = ifa.next) {
        if (ifa.flags & iff_up == 0) continue;
        const sa = ifa.addr orelse continue;
        if (sa.family != c.AF.INET and sa.family != c.AF.INET6) continue;

        var address = Io.Threaded.addressFromPosix(@ptrCast(@alignCast(sa)));
        if (!covers(wildcard, address) or isLinkLocal(address)) continue;
        address.setPort(wildcard.getPort());
        try appendNew(gpa, &out, address);
    }
    return out.toOwnedSlice(gpa);
}

/// The loopback addresses the machine's host name resolves to, with
/// `wildcard`'s port. Debian maps the host name to 127.0.1.1 and NixOS to
/// 127.0.0.2. Those reach the machine through the 127.0.0.0/8 route
/// without being an interface's address.
pub fn hostLoopback(gpa: Allocator, io: Io, wildcard: IpAddress) ![]IpAddress {
    var name_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const name = std.posix.gethostname(&name_buf) catch return &.{};
    const host: Io.net.HostName = Io.net.HostName.init(name) catch return &.{};

    // With room for 16 results, the lookup doesn't block on the queue.
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

/// fe80::/10.
fn isLinkLocal(address: IpAddress) bool {
    return switch (address) {
        .ip4 => false,
        .ip6 => |a| a.bytes[0] == 0xfe and a.bytes[1] & 0xc0 == 0x80,
    };
}

/// 127.0.0.0/8 or ::1.
fn isLoopback(address: IpAddress) bool {
    return switch (address) {
        .ip4 => |a| a.bytes[0] == 127,
        .ip6 => |a| std.mem.eql(u8, &a.bytes, &(@as([15]u8, @splat(0)) ++ [_]u8{1})),
    };
}

const testing = std.testing;

test "the interfaces include loopback, with the wildcard's port" {
    const any4: IpAddress = try .parseIp4("0.0.0.0", 8739);
    const list = try interfaces(testing.allocator, any4);
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

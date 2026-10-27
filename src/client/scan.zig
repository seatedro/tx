//! Learns a server's key, as `ssh-keyscan` does: a handshake that accepts
//! any key, closed as soon as it completes. The handshake proves the server
//! holds the key's secret half. Nothing is sent over the connection.
//!
//! The server's addresses are raced as for a session (see `connect`).
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const xev = @import("xev");
const transport = @import("transport");
const connect = @import("connect.zig");

const Conn = transport.endpoint.Conn;
const CloseReason = transport.endpoint.CloseReason;

pub const Result = union(enum) {
    found: Found,
    /// Every attempt closed before its handshake completed.
    failed: CloseReason,

    pub const Found = struct {
        key: [32]u8,
        /// The address that answered.
        address: IpAddress,
    };
};

pub fn hostKey(gpa: Allocator, io: Io, servers: []const IpAddress, idle_timeout_ns: u64) !Result {
    transport.crypto.init(io);

    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();

    var scan: Scan = .{};
    var racer: connect.Racer = undefined;
    try racer.init(gpa, io, &loop, .{
        .addresses = servers,
        .accept = .any,
        .idle_timeout_ns = idle_timeout_ns,
        .handler = .{ .ctx = &scan, .connected = Scan.onConnected, .closed = Scan.onClosed },
    });
    defer racer.deinit();

    while (scan.result == null) try loop.run(.once);

    // Lets the endpoints' completions finish.
    racer.stop();
    try loop.run(.until_done);

    return switch (scan.result.?) {
        .connected => .{ .found = .{ .key = racer.presentedKey().?, .address = racer.address().? } },
        .closed => |reason| .{ .failed = reason },
    };
}

const Scan = struct {
    result: ?union(enum) { connected, closed: CloseReason } = null,

    fn onConnected(ctx: ?*anyopaque, conn: *Conn) void {
        const scan: *Scan = @ptrCast(@alignCast(ctx.?));
        scan.result = .connected;
        conn.close(0);
    }

    fn onClosed(ctx: ?*anyopaque, _: *Conn, reason: CloseReason) void {
        const scan: *Scan = @ptrCast(@alignCast(ctx.?));
        if (scan.result == null) scan.result = .{ .closed = reason };
    }
};

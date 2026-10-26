//! Learns a server's key, as `ssh-keyscan` does: a handshake that accepts
//! any key, closed as soon as it completes. The handshake proves the server
//! holds the key's secret half. Nothing is sent over the connection.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const xev = @import("xev");
const transport = @import("transport");

const Endpoint = transport.endpoint.Endpoint;
const Conn = transport.endpoint.Conn;
const CloseReason = transport.endpoint.CloseReason;

pub const Result = union(enum) {
    key: [32]u8,
    /// The connection closed before the handshake completed.
    failed: CloseReason,
};

pub fn hostKey(gpa: Allocator, io: Io, server: IpAddress, idle_timeout_ns: u64) !Result {
    transport.crypto.init(io);

    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();

    var tls: transport.quic.Client = try .init(.any);
    defer tls.deinit();

    var scan: Scan = .{};
    var endpoint: Endpoint = undefined;
    try endpoint.init(gpa, io, &loop, .{
        .local = switch (server) {
            .ip4 => try .parseIp4("0.0.0.0", 0),
            .ip6 => try .parseIp6("::", 0),
        },
        .role = .{ .client = &tls },
        .idle_timeout_ns = idle_timeout_ns,
        .handler = .{ .ctx = &scan, .connected = Scan.onConnected, .closed = Scan.onClosed },
    });
    defer endpoint.deinit();

    _ = try endpoint.connect(server);
    while (scan.result == null) try loop.run(.once);

    // Lets the endpoint's completions finish.
    endpoint.stop();
    try loop.run(.until_done);

    return switch (scan.result.?) {
        .connected => .{ .key = tls.presentedKey().? },
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

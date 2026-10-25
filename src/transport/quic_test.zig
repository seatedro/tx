//! Loopback tests for quic.zig: a client and a server on two UDP sockets on
//! 127.0.0.1, driven by one single-threaded loop.
const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const Ed25519 = std.crypto.sign.Ed25519;
const crypto = @import("crypto");
const c = @import("c");
const quic = @import("quic.zig");

const Socket = Io.net.Socket;

/// One endpoint: a socket and, once established, its connection.
const Peer = struct {
    socket: Socket,
    conn: ?*quic.Connection = null,

    fn bind(io: Io) !Peer {
        const addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        return .{ .socket = try addr.bind(io, .{ .mode = .dgram }) };
    }

    fn deinit(self: *Peer, io: Io) void {
        if (self.conn) |conn| conn.deinit();
        self.socket.close(io);
    }

    /// Receive at most one datagram, waiting up to `wait_ms`.
    fn poll(self: *Peer, io: Io, buf: []u8, wait_ms: i64) !?Io.net.IncomingMessage {
        const timeout: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(wait_ms), .clock = .awake } };
        return self.socket.receiveTimeout(io, buf, timeout) catch |err| switch (err) {
            error.Timeout => null,
            else => err,
        };
    }
};

/// Echoes everything received on a stream back on the same stream, and
/// finishes it once the peer has.
const Echo = struct {
    stream_id: ?i64 = null,
    /// Everything received. ngtcp2 keeps pointers into what it has sent
    /// until it is acknowledged, so this buffer is preallocated and never
    /// moves or shrinks.
    received: []u8,
    received_len: usize = 0,
    sent: usize = 0,
    peer_finished: bool = false,
    finished: bool = false,

    fn onData(ctx: ?*anyopaque, conn: *quic.Connection, stream_id: i64, data: []const u8, fin: bool) void {
        const self: *Echo = @ptrCast(@alignCast(ctx.?));
        self.stream_id = stream_id;
        @memcpy(self.received[self.received_len..][0..data.len], data);
        self.received_len += data.len;
        conn.consume(stream_id, data.len) catch @panic("consume");
        if (fin) self.peer_finished = true;
    }

    fn flush(self: *Echo, conn: *quic.Connection, socket: *Socket, io: Io, buf: []u8) !void {
        while (true) {
            const stream_id = self.stream_id orelse return flushPlain(conn, socket, io, buf);
            if (self.finished) return flushPlain(conn, socket, io, buf);
            const w = try conn.sendStream(buf, stream_id, self.received[self.sent..self.received_len], self.peer_finished);
            self.sent += w.consumed;
            if (self.peer_finished and self.sent == self.received_len and w.datagram != null) self.finished = true;
            const d = w.datagram orelse return;
            try socket.send(io, &d.to, buf[0..d.len]);
        }
    }
};

/// Sends `payload` on one stream once the handshake completes, and collects
/// what comes back.
const Sender = struct {
    gpa: std.mem.Allocator,
    payload: []const u8,
    stream_id: ?i64 = null,
    sent: usize = 0,
    fin_sent: bool = false,
    received: std.ArrayList(u8) = .empty,
    done: bool = false,

    fn onData(ctx: ?*anyopaque, conn: *quic.Connection, stream_id: i64, data: []const u8, fin: bool) void {
        const self: *Sender = @ptrCast(@alignCast(ctx.?));
        self.received.appendSlice(self.gpa, data) catch @panic("OOM");
        conn.consume(stream_id, data.len) catch @panic("consume");
        if (fin) self.done = true;
    }

    fn flush(self: *Sender, conn: *quic.Connection, socket: *Socket, io: Io, buf: []u8) !void {
        if (self.stream_id == null and conn.isHandshakeComplete()) self.stream_id = try conn.openBidiStream();
        while (true) {
            const stream_id = self.stream_id orelse return flushPlain(conn, socket, io, buf);
            if (self.fin_sent) return flushPlain(conn, socket, io, buf);
            const w = try conn.sendStream(buf, stream_id, self.payload[self.sent..], true);
            self.sent += w.consumed;
            if (self.sent == self.payload.len and w.datagram != null) self.fin_sent = true;
            const d = w.datagram orelse return;
            try socket.send(io, &d.to, buf[0..d.len]);
        }
    }
};

fn flushPlain(conn: *quic.Connection, socket: *Socket, io: Io, buf: []u8) !void {
    while (try conn.send(buf)) |d| try socket.send(io, &d.to, buf[0..d.len]);
}

test "a client pinning the server's key connects, and a stream echoes both ways" {
    const io = testing.io;
    const gpa = testing.allocator;
    crypto.init(io);

    const identity = Ed25519.KeyPair.generate(io);
    var server_tls = try quic.Server.init(identity);
    defer server_tls.deinit();
    var client_tls = try quic.Client.init(identity.public_key.toBytes());
    defer client_tls.deinit();

    var server: Peer = try .bind(io);
    defer server.deinit(io);
    var client: Peer = try .bind(io);
    defer client.deinit(io);

    const payload = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i *% 31);

    const echo_buf = try gpa.alloc(u8, payload.len);
    defer gpa.free(echo_buf);
    var echo: Echo = .{ .received = echo_buf };
    var sender: Sender = .{ .gpa = gpa, .payload = payload };
    defer sender.received.deinit(gpa);

    const mlkem_before = c.tx_tls_mlkem_exchanges();
    client.conn = try .connect(gpa, io, &client_tls, client.socket.address, server.socket.address, .{
        .handler = .{ .ctx = &sender, .streamData = Sender.onData },
    });

    var buf: [quic.max_datagram_size]u8 = undefined;
    var rbuf: [65536]u8 = undefined;
    const deadline = Io.Clock.awake.now(io).nanoseconds + 10 * std.time.ns_per_s;
    while (!sender.done) {
        if (Io.Clock.awake.now(io).nanoseconds > deadline) return error.TestTimedOut;

        try sender.flush(client.conn.?, &client.socket, io, &buf);
        if (server.conn) |conn| try echo.flush(conn, &server.socket, io, &buf);

        while (try server.poll(io, &rbuf, 1)) |msg| {
            if (server.conn) |conn| {
                try conn.receive(msg.from, msg.data);
            } else {
                server.conn = try .accept(gpa, io, &server_tls, server.socket.address, msg.from, msg.data, .{
                    .handler = .{ .ctx = &echo, .streamData = Echo.onData },
                });
            }
        }
        while (try client.poll(io, &rbuf, 1)) |msg| try client.conn.?.receive(msg.from, msg.data);

        try client.conn.?.handleExpiry();
        if (server.conn) |conn| try conn.handleExpiry();
    }

    try testing.expect(client.conn.?.isHandshakeComplete());
    try testing.expectEqualSlices(u8, payload, sender.received.items);
    // Both ends count the hybrid post-quantum key exchange.
    try testing.expect(c.tx_tls_mlkem_exchanges() >= mlkem_before + 2);
}

test "a client pinning another key refuses the server" {
    const io = testing.io;
    const gpa = testing.allocator;
    crypto.init(io);

    const identity = Ed25519.KeyPair.generate(io);
    const other = Ed25519.KeyPair.generate(io);
    var server_tls = try quic.Server.init(identity);
    defer server_tls.deinit();
    var client_tls = try quic.Client.init(other.public_key.toBytes());
    defer client_tls.deinit();

    var server: Peer = try .bind(io);
    defer server.deinit(io);
    var client: Peer = try .bind(io);
    defer client.deinit(io);

    client.conn = try .connect(gpa, io, &client_tls, client.socket.address, server.socket.address, .{});

    var buf: [quic.max_datagram_size]u8 = undefined;
    var rbuf: [65536]u8 = undefined;
    const deadline = Io.Clock.awake.now(io).nanoseconds + 5 * std.time.ns_per_s;
    const result: anyerror!void = loop: while (true) {
        if (Io.Clock.awake.now(io).nanoseconds > deadline) return error.TestTimedOut;
        try flushPlain(client.conn.?, &client.socket, io, &buf);
        if (server.conn) |conn| flushPlain(conn, &server.socket, io, &buf) catch {};
        while (try server.poll(io, &rbuf, 1)) |msg| {
            if (server.conn) |conn| {
                conn.receive(msg.from, msg.data) catch {};
            } else {
                server.conn = try .accept(gpa, io, &server_tls, server.socket.address, msg.from, msg.data, .{});
            }
        }
        while (try client.poll(io, &rbuf, 1)) |msg| {
            client.conn.?.receive(msg.from, msg.data) catch |err| break :loop err;
        }
    };
    try testing.expectError(error.HandshakeFailed, result);
    try testing.expect(!client.conn.?.isHandshakeComplete());
}

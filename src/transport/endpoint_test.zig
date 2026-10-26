//! Endpoints on one libxev loop over 127.0.0.1.
const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const Ed25519 = std.crypto.sign.Ed25519;
const xev = @import("xev");
const crypto = @import("crypto");
const quic = @import("quic.zig");
const endpoint = @import("endpoint.zig");

const Endpoint = endpoint.Endpoint;
const Conn = endpoint.Conn;
const Stream = endpoint.Stream;
const CloseReason = endpoint.CloseReason;

const gpa = testing.allocator;
const timeout_ms = 10_000;

fn loopback() !Io.net.IpAddress {
    return Io.net.IpAddress.parseIp4("127.0.0.1", 0);
}

fn nowMs() i64 {
    return Io.Clock.awake.now(testing.io).toMilliseconds();
}

/// A loop with a 10 ms tick, so that `runUntil` can check its deadline.
const Harness = struct {
    loop: xev.Loop,
    tick: xev.Timer,
    tick_c: xev.Completion = .{},
    ticking: bool = true,

    fn init(h: *Harness) !void {
        h.* = .{ .loop = try .init(.{}), .tick = try .init() };
        h.tick.run(&h.loop, &h.tick_c, 10, Harness, h, onTick);
    }

    fn onTick(h_: ?*Harness, _: *xev.Loop, _: *xev.Completion, _: xev.Timer.RunError!void) xev.CallbackAction {
        const h = h_.?;
        if (h.ticking) h.tick.run(&h.loop, &h.tick_c, 10, Harness, h, onTick);
        return .disarm;
    }

    fn runUntil(h: *Harness, ctx: anytype, comptime done: fn (@TypeOf(ctx)) bool) !void {
        const deadline = nowMs() + timeout_ms;
        while (!done(ctx)) {
            if (nowMs() > deadline) return error.Timeout;
            try h.loop.run(.once);
        }
    }

    fn runFor(h: *Harness, ms: i64) !void {
        const end = nowMs() + ms;
        while (nowMs() < end) try h.loop.run(.once);
    }

    /// Stops the endpoints and runs the loop until nothing is active.
    fn finish(h: *Harness, endpoints: []const *Endpoint) !void {
        for (endpoints) |e| e.stop();
        h.ticking = false;
        try h.loop.run(.until_done);
        for (endpoints) |e| e.deinit();
        h.tick.deinit();
        h.loop.deinit();
    }
};

const Keys = struct {
    server: quic.Server,
    client: quic.Client,

    fn init(pin_other: bool) !Keys {
        crypto.init(testing.io);
        const identity = Ed25519.KeyPair.generate(testing.io);
        const pinned = if (pin_other) Ed25519.KeyPair.generate(testing.io).public_key else identity.public_key;
        var server = try quic.Server.init(identity);
        errdefer server.deinit();
        return .{ .server = server, .client = try quic.Client.init(.{ .keys = &.{pinned.toBytes()} }) };
    }

    fn deinit(k: *Keys) void {
        k.server.deinit();
        k.client.deinit();
    }
};

/// Echoes stream data back on the same stream and finishes it after the
/// peer does. Counts closes.
const EchoServer = struct {
    closed: u32 = 0,
    last_reason: ?CloseReason = null,

    fn handler(s: *EchoServer) endpoint.Handler {
        return .{ .ctx = s, .data = onData, .closed = onClosed };
    }

    fn onData(_: ?*anyopaque, stream: *Stream, bytes: []const u8, fin: bool) void {
        stream.write(bytes) catch @panic("OOM");
        stream.consume(bytes.len);
        if (fin) stream.finish();
    }

    fn onClosed(ctx: ?*anyopaque, _: *Conn, reason: CloseReason) void {
        const s: *EchoServer = @ptrCast(@alignCast(ctx.?));
        s.closed += 1;
        s.last_reason = reason;
    }
};

/// Sends `payload` on one stream once connected and collects what comes
/// back.
const Sender = struct {
    payload: []const u8,
    received: std.ArrayList(u8) = .empty,
    done: bool = false,
    connected: bool = false,
    conn: ?*Conn = null,
    stream: ?*Stream = null,
    reason: ?CloseReason = null,

    fn handler(s: *Sender) endpoint.Handler {
        return .{ .ctx = s, .connected = onConnected, .data = onData, .closed = onClosed };
    }

    fn deinit(s: *Sender) void {
        s.received.deinit(gpa);
    }

    fn onConnected(ctx: ?*anyopaque, conn: *Conn) void {
        const s: *Sender = @ptrCast(@alignCast(ctx.?));
        s.connected = true;
        s.conn = conn;
        if (s.payload.len == 0) return;
        const stream = conn.openStream(.bidi) catch @panic("stream");
        s.stream = stream;
        stream.write(s.payload) catch @panic("OOM");
        stream.finish();
    }

    fn onData(ctx: ?*anyopaque, stream: *Stream, bytes: []const u8, fin: bool) void {
        const s: *Sender = @ptrCast(@alignCast(ctx.?));
        s.received.appendSlice(gpa, bytes) catch @panic("OOM");
        stream.consume(bytes.len);
        if (fin) s.done = true;
    }

    fn onClosed(ctx: ?*anyopaque, conn: *Conn, reason: CloseReason) void {
        const s: *Sender = @ptrCast(@alignCast(ctx.?));
        s.reason = reason;
        if (s.conn == conn) s.conn = null;
        s.stream = null;
    }

    fn isDone(s: *Sender) bool {
        return s.done;
    }

    fn isConnected(s: *Sender) bool {
        return s.connected;
    }

    fn isClosed(s: *Sender) bool {
        return s.reason != null;
    }
};

fn pattern(buf: []u8, seed: u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% seed);
}

test "a client and a server echo 8 MiB on a stream" {
    var keys: Keys = try .init(false);
    defer keys.deinit();
    var h: Harness = undefined;
    try h.init();

    var echo: EchoServer = .{};
    var server: Endpoint = undefined;
    try server.init(gpa, testing.io, &h.loop, .{ .local = try loopback(), .role = .{ .server = &keys.server }, .handler = echo.handler() });

    const payload = try gpa.alloc(u8, 8 << 20);
    defer gpa.free(payload);
    pattern(payload, 0);
    var sender: Sender = .{ .payload = payload };
    defer sender.deinit();
    var client: Endpoint = undefined;
    try client.init(gpa, testing.io, &h.loop, .{ .local = try loopback(), .role = .{ .client = &keys.client }, .handler = sender.handler() });
    _ = try client.connect(server.local);

    try h.runUntil(&sender, Sender.isDone);
    try testing.expectEqualSlices(u8, payload, sender.received.items);
    try h.finish(&.{ &client, &server });
}

test "a server serves several clients at once" {
    var keys: Keys = try .init(false);
    defer keys.deinit();
    var h: Harness = undefined;
    try h.init();

    var echo: EchoServer = .{};
    var server: Endpoint = undefined;
    try server.init(gpa, testing.io, &h.loop, .{ .local = try loopback(), .role = .{ .server = &keys.server }, .handler = echo.handler() });

    const n = 4;
    var payloads: [n][]u8 = undefined;
    var senders: [n]Sender = undefined;
    var clients: [n]Endpoint = undefined;
    for (0..n) |i| {
        payloads[i] = try gpa.alloc(u8, 256 * 1024 + i * 1000);
        pattern(payloads[i], @intCast(i));
        senders[i] = .{ .payload = payloads[i] };
        try clients[i].init(gpa, testing.io, &h.loop, .{ .local = try loopback(), .role = .{ .client = &keys.client }, .handler = senders[i].handler() });
        _ = try clients[i].connect(server.local);
    }
    defer for (0..n) |i| {
        senders[i].deinit();
        gpa.free(payloads[i]);
    };

    const All = struct {
        fn done(s: *[n]Sender) bool {
            for (s) |*sender| if (!sender.done) return false;
            return true;
        }
    };
    try h.runUntil(&senders, All.done);
    for (0..n) |i| try testing.expectEqualSlices(u8, payloads[i], senders[i].received.items);
    var endpoints: [n + 1]*Endpoint = undefined;
    for (0..n) |i| endpoints[i] = &clients[i];
    endpoints[n] = &server;
    try h.finish(&endpoints);
}

/// Records stream data without consuming it until `consuming` is set.
const SlowReader = struct {
    received: usize = 0,
    unconsumed: usize = 0,
    stream: ?*Stream = null,
    consuming: bool = false,
    fin: bool = false,

    fn onData(ctx: ?*anyopaque, stream: *Stream, bytes: []const u8, fin: bool) void {
        const r: *SlowReader = @ptrCast(@alignCast(ctx.?));
        r.stream = stream;
        r.received += bytes.len;
        if (r.consuming) stream.consume(bytes.len) else r.unconsumed += bytes.len;
        if (fin) r.fin = true;
    }

    fn isFinished(r: *SlowReader) bool {
        return r.fin;
    }
};

test "flow control holds a writer until the reader consumes" {
    var keys: Keys = try .init(false);
    defer keys.deinit();
    var h: Harness = undefined;
    try h.init();

    const window = 64 * 1024;
    var reader: SlowReader = .{};
    var server: Endpoint = undefined;
    try server.init(gpa, testing.io, &h.loop, .{
        .local = try loopback(),
        .role = .{ .server = &keys.server },
        .handler = .{ .ctx = &reader, .data = SlowReader.onData },
        .stream_window = window,
        .connection_window = 2 * window,
    });

    const payload = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(payload);
    pattern(payload, 7);
    var sender: Sender = .{ .payload = payload };
    defer sender.deinit();
    var client: Endpoint = undefined;
    try client.init(gpa, testing.io, &h.loop, .{ .local = try loopback(), .role = .{ .client = &keys.client }, .handler = sender.handler() });
    _ = try client.connect(server.local);

    try h.runUntil(&sender, Sender.isConnected);
    try h.runFor(300);
    try testing.expect(reader.received <= window);
    try testing.expect(sender.stream.?.buffered() >= payload.len - window);

    reader.consuming = true;
    reader.stream.?.consume(reader.unconsumed);
    try h.runUntil(&reader, SlowReader.isFinished);
    try testing.expectEqual(payload.len, reader.received);
    try h.finish(&.{ &client, &server });
}

test "a client pinning another key fails the handshake" {
    var keys: Keys = try .init(true);
    defer keys.deinit();
    var h: Harness = undefined;
    try h.init();

    var echo: EchoServer = .{};
    var server: Endpoint = undefined;
    try server.init(gpa, testing.io, &h.loop, .{ .local = try loopback(), .role = .{ .server = &keys.server }, .handler = echo.handler() });
    var sender: Sender = .{ .payload = "" };
    defer sender.deinit();
    var client: Endpoint = undefined;
    try client.init(gpa, testing.io, &h.loop, .{ .local = try loopback(), .role = .{ .client = &keys.client }, .handler = sender.handler() });
    _ = try client.connect(server.local);

    try h.runUntil(&sender, Sender.isClosed);
    try testing.expectEqual(CloseReason.handshake_failed, sender.reason.?);
    try testing.expect(!sender.connected);
    try h.finish(&.{ &client, &server });
}

test "closing a connection reports the code to the peer" {
    var keys: Keys = try .init(false);
    defer keys.deinit();
    var h: Harness = undefined;
    try h.init();

    var echo: EchoServer = .{};
    var server: Endpoint = undefined;
    try server.init(gpa, testing.io, &h.loop, .{ .local = try loopback(), .role = .{ .server = &keys.server }, .handler = echo.handler() });
    var sender: Sender = .{ .payload = "" };
    defer sender.deinit();
    var client: Endpoint = undefined;
    try client.init(gpa, testing.io, &h.loop, .{ .local = try loopback(), .role = .{ .client = &keys.client }, .handler = sender.handler() });
    _ = try client.connect(server.local);

    try h.runUntil(&sender, Sender.isConnected);
    sender.conn.?.close(7);
    try testing.expectEqual(CloseReason.local, sender.reason.?);
    const Closed = struct {
        fn done(s: *EchoServer) bool {
            return s.closed > 0;
        }
    };
    try h.runUntil(&echo, Closed.done);
    try testing.expectEqual(CloseReason{ .peer = .{ .application = 7 } }, echo.last_reason.?);
    try h.finish(&.{ &client, &server });
}

test "an idle connection times out on both ends" {
    var keys: Keys = try .init(false);
    defer keys.deinit();
    var h: Harness = undefined;
    try h.init();

    const idle = 300 * std.time.ns_per_ms;
    var echo: EchoServer = .{};
    var server: Endpoint = undefined;
    try server.init(gpa, testing.io, &h.loop, .{ .local = try loopback(), .role = .{ .server = &keys.server }, .handler = echo.handler(), .idle_timeout_ns = idle });
    var sender: Sender = .{ .payload = "" };
    defer sender.deinit();
    var client: Endpoint = undefined;
    try client.init(gpa, testing.io, &h.loop, .{ .local = try loopback(), .role = .{ .client = &keys.client }, .handler = sender.handler(), .idle_timeout_ns = idle });
    _ = try client.connect(server.local);

    const Both = struct {
        fn done(ctx: struct { *Sender, *EchoServer }) bool {
            return ctx[0].reason != null and ctx[1].closed > 0;
        }
    };
    try h.runUntil(.{ &sender, &echo }, Both.done);
    try testing.expectEqual(CloseReason.idle_timeout, sender.reason.?);
    try testing.expectEqual(CloseReason.idle_timeout, echo.last_reason.?);
    try h.finish(&.{ &client, &server });
}

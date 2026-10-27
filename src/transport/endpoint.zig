//! QUIC connections on a libxev loop.
//!
//! An `Endpoint` owns one UDP socket and the connections on it. It routes
//! received datagrams, runs ngtcp2's timers, and keeps the bytes written to
//! each stream until the peer acknowledges them, since ngtcp2 holds pointers
//! into them for retransmission (`quic.Connection.sendStream`).
//!
//! Everything runs on the loop's thread. Callbacks run inside an endpoint
//! event; writes made from them are sent when the event ends. Writes made
//! outside an event are sent before `Stream.write` returns.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const PosixAddress = Io.Threaded.PosixAddress;
const xev = @import("xev");
const c = @import("c");
const quic = @import("quic.zig");

const log = std.log.scoped(.endpoint);

pub const Role = union(enum) {
    server: *const quic.Server,
    client: *const quic.Client,
};

pub const CloseReason = union(enum) {
    /// `Conn.close` or `Endpoint.stop`.
    local,
    /// The peer sent CONNECTION_CLOSE.
    peer: quic.Connection.CloseCode,
    idle_timeout,
    /// The TLS handshake failed, for example on a server key the client
    /// doesn't accept.
    handshake_failed,
    /// Any other ngtcp2 error.
    failed,
};

pub const Handler = struct {
    ctx: ?*anyopaque = null,
    /// The handshake completed.
    connected: ?*const fn (ctx: ?*anyopaque, conn: *Conn) void = null,
    /// The peer opened `stream`.
    streamOpened: ?*const fn (ctx: ?*anyopaque, stream: *Stream) void = null,
    /// `bytes` is valid until the callback returns. The peer's flow control
    /// window shrinks by `bytes.len` until `Stream.consume` returns it.
    data: ?*const fn (ctx: ?*anyopaque, stream: *Stream, bytes: []const u8, fin: bool) void = null,
    /// The peer acknowledged data, lowering `Stream.buffered`.
    acked: ?*const fn (ctx: ?*anyopaque, stream: *Stream) void = null,
    /// The peer reset its sending side of `stream`.
    reset: ?*const fn (ctx: ?*anyopaque, stream: *Stream, app_error_code: u64) void = null,
    /// `stream` is freed when the callback returns.
    streamClosed: ?*const fn (ctx: ?*anyopaque, stream: *Stream) void = null,
    /// `conn` is freed when the callback returns. Its streams were closed
    /// first.
    closed: ?*const fn (ctx: ?*anyopaque, conn: *Conn, reason: CloseReason) void = null,
};

pub const Options = struct {
    /// A specific address: connections use it as their local path address.
    /// Port 0 picks one; see `Endpoint.local`.
    local: IpAddress,
    role: Role,
    handler: Handler = .{},
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
    /// Client only. See `quic.Connection.Options`.
    handshake_timeout_ns: ?u64 = null,
    keep_alive_ns: ?u64 = null,
    stream_window: u64 = 8 << 20,
    connection_window: u64 = 32 << 20,
    /// SO_RCVBUF. Datagrams that arrive while the loop is busy wait here.
    receive_buffer: c_int = 4 << 20,
};

/// The length of the connection IDs the endpoint issues. ngtcp2 issues new
/// ones at the length of the first.
const cid_len = 16;

pub const Endpoint = struct {
    gpa: Allocator,
    io: Io,
    loop: *xev.Loop,
    options: Options,
    udp: xev.UDP,
    /// The bound address, with the port the kernel picked.
    local: IpAddress,
    conns: std.ArrayList(*Conn) = .empty,
    /// Server only: connection IDs to connections.
    routes: std.AutoHashMapUnmanaged(Cid, *Conn) = .empty,

    /// The pending receive. Large enough for any UDP datagram.
    recv_c: xev.Completion = .{},
    recv_state: xev.UDP.State = undefined,
    recv_buf: [65536]u8 = undefined,

    /// Fires at the earliest ngtcp2 expiry of any connection.
    timer: xev.Timer,
    timer_c: xev.Completion = .{},
    timer_cancel_c: xev.Completion = .{},

    /// Cancel the receive and the timer in `stop`.
    stop_c: [2]xev.Completion = .{ .{}, .{} },

    /// Each outgoing packet is written here, then sent before the next.
    out: [quic.max_datagram_size]u8 = undefined,
    /// Nesting of endpoint events, so that flushing and freeing happen once,
    /// when the outermost ends.
    depth: u32 = 0,
    stopping: bool = false,

    /// Binds the socket and starts receiving. The endpoint must not move
    /// while the loop runs, since its completions point into it.
    pub fn init(self: *Endpoint, gpa: Allocator, io: Io, loop: *xev.Loop, options: Options) !void {
        const udp = try xev.UDP.init(options.local);
        errdefer _ = std.c.close(udp.fd);
        try udp.bind(options.local);
        try std.posix.setsockopt(udp.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, &std.mem.toBytes(options.receive_buffer));

        // Read back the address to learn the port when `local` asked for 0.
        var bound: PosixAddress = undefined;
        var bound_len: std.posix.socklen_t = @sizeOf(PosixAddress);
        if (std.c.getsockname(udp.fd, &bound.any, &bound_len) != 0) return error.Unexpected;

        self.* = .{
            .gpa = gpa,
            .io = io,
            .loop = loop,
            .options = options,
            .udp = udp,
            .local = Io.Threaded.addressFromPosix(&bound),
            .timer = try .init(),
        };
        self.receive();
    }

    /// Call after `stop` once the loop has no active completions.
    pub fn deinit(self: *Endpoint) void {
        std.debug.assert(self.conns.items.len == 0);
        self.conns.deinit(self.gpa);
        self.routes.deinit(self.gpa);
        self.timer.deinit();
        _ = std.c.close(self.udp.fd);
        self.* = undefined;
    }

    /// Closes every connection and cancels the endpoint's completions.
    pub fn stop(self: *Endpoint) void {
        self.begin();
        defer self.end();
        self.stopping = true;
        for (self.conns.items) |conn| conn.close(0);

        // The loop finishes once these complete. `end` won't re-arm the
        // timer while stopping.
        self.cancel(&self.stop_c[0], &self.recv_c);
        self.cancel(&self.stop_c[1], &self.timer_c);
    }

    /// Whether a stopped endpoint's completions have finished, so `deinit`
    /// can run.
    pub fn isStopped(self: *const Endpoint) bool {
        if (!self.stopping or self.conns.items.len > 0) return false;
        const completions = [_]*const xev.Completion{ &self.recv_c, &self.timer_c, &self.timer_cancel_c, &self.stop_c[0], &self.stop_c[1] };
        for (completions) |comp| if (comp.state() == .active) return false;
        return true;
    }

    /// Client only: start a connection to `remote`. `Handler.connected` runs
    /// once the handshake completes.
    pub fn connect(self: *Endpoint, remote: IpAddress) !*Conn {
        self.begin();
        defer self.end();
        std.debug.assert(self.options.role == .client and self.conns.items.len == 0);

        const conn = try self.gpa.create(Conn);
        errdefer self.gpa.destroy(conn);
        conn.* = .{ .endpoint = self, .remote = remote };
        conn.quic = try quic.Connection.connect(self.gpa, self.io, self.options.role.client, self.local, remote, self.connectionOptions(conn));
        errdefer conn.quic.deinit();
        try self.conns.append(self.gpa, conn);

        // `end` sends the first Initial packet.
        conn.flush_pending = true;
        return conn;
    }

    fn connectionOptions(self: *Endpoint, conn: *Conn) quic.Connection.Options {
        return .{
            .handler = .{
                .ctx = conn,
                .handshakeCompleted = Conn.onHandshake,
                .streamData = Conn.onStreamData,
                .streamAcked = Conn.onStreamAcked,
                .streamOpened = Conn.onStreamOpened,
                .streamReset = Conn.onStreamReset,
                .streamClosed = Conn.onStreamClosed,
                .connectionIdIssued = Conn.onConnectionIdIssued,
                .connectionIdRetired = Conn.onConnectionIdRetired,
            },
            .idle_timeout_ns = self.options.idle_timeout_ns,
            .handshake_timeout_ns = self.options.handshake_timeout_ns,
            .keep_alive_ns = self.options.keep_alive_ns,
            .stream_window = self.options.stream_window,
            .connection_window = self.options.connection_window,
        };
    }

    /// Cancels `target` if it is pending, unless a cancel is already queued.
    fn cancel(self: *Endpoint, cancel_c: *xev.Completion, target: *xev.Completion) void {
        if (target.state() != .active or cancel_c.state() == .active) return;
        cancel_c.* = .{ .op = .{ .cancel = .{ .c = target } } };
        self.loop.add(cancel_c);
    }

    /// Starts an event. Every entry point into the endpoint (a datagram,
    /// the timer, a call from the app) runs between `begin` and `end`.
    fn begin(self: *Endpoint) void {
        self.depth += 1;
    }

    /// Ends an event. The outermost end sends what connections have to
    /// send, frees what closed, and re-arms the timer.
    fn end(self: *Endpoint) void {
        self.depth -= 1;
        if (self.depth > 0) return;

        for (self.conns.items) |conn| {
            if (conn.flush_pending and conn.closing == null) self.flush(conn);
        }
        self.reap();

        // Sending and receiving move ngtcp2's expiry. The timer is set
        // again after every event.
        if (!self.stopping) self.armTimer();
    }

    fn receive(self: *Endpoint) void {
        self.udp.read(self.loop, &self.recv_c, &self.recv_state, .{ .slice = &self.recv_buf }, Endpoint, self, onReceive);
    }

    fn onReceive(
        self_: ?*Endpoint,
        _: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        from: IpAddress,
        _: xev.UDP,
        _: xev.ReadBuffer,
        result: xev.ReadError!usize,
    ) xev.CallbackAction {
        const self = self_.?;

        // A failed receive is retried, except after `stop` cancels it.
        const n = result catch |err| {
            if (err != error.Canceled) log.warn("receive failed: {t}", .{err});
            return if (self.stopping) .disarm else .rearm;
        };

        self.begin();
        defer self.end();
        self.dispatch(from, self.recv_buf[0..n]);
        return if (self.stopping) .disarm else .rearm;
    }

    /// Hands a datagram to its connection. On a server, a datagram for no
    /// known connection may start a new one.
    fn dispatch(self: *Endpoint, from: IpAddress, packet: []const u8) void {
        // A client has one connection, and every datagram is for it.
        const conn = switch (self.options.role) {
            .client => if (self.conns.items.len > 0) self.conns.items[0] else return,
            .server => self.route(packet) orelse return self.accept(from, packet),
        };
        if (conn.closing != null) return;

        conn.quic.receive(from, packet) catch |err| return conn.fail(err);

        // Replies go to where the peer last sent from. A client that changes
        // address keeps its connection.
        conn.remote = from;
        conn.flush_pending = true;
    }

    /// Finds the connection by the packet's destination connection ID.
    fn route(self: *Endpoint, packet: []const u8) ?*Conn {
        // Short header packets don't carry the ID's length. It is the length
        // this endpoint issues.
        var vc: c.ngtcp2_version_cid = undefined;
        if (c.ngtcp2_pkt_decode_version_cid(&vc, packet.ptr, packet.len, cid_len) != 0) return null;
        return self.routes.get(.init(vc.dcid[0..vc.dcidlen]));
    }

    fn accept(self: *Endpoint, from: IpAddress, packet: []const u8) void {
        if (self.stopping) return;

        var vc: c.ngtcp2_version_cid = undefined;
        if (c.ngtcp2_pkt_decode_version_cid(&vc, packet.ptr, packet.len, cid_len) != 0) return;

        const conn = self.gpa.create(Conn) catch return;
        conn.* = .{ .endpoint = self, .remote = from };
        self.conns.append(self.gpa, conn) catch {
            self.gpa.destroy(conn);
            return;
        };
        conn.quic = quic.Connection.accept(self.gpa, self.io, self.options.role.server, self.local, from, packet, self.connectionOptions(conn)) catch {
            // Not an Initial packet, or not a valid one. ngtcp2's callbacks
            // may have added routes before it failed.
            _ = self.conns.pop();
            self.removeRoutes(conn);
            self.gpa.destroy(conn);
            return;
        };
        // The client addresses its Initial packets to the ID it chose until
        // it learns ours.
        self.addRoute(vc.dcid[0..vc.dcidlen], conn);

        // Then the IDs the connection issued.
        var ids: [quic.Connection.max_connection_ids]c.ngtcp2_cid = undefined;
        for (conn.quic.connectionIds(&ids)) |*cid| self.addRoute(cid.data[0..cid.datalen], conn);
        conn.flush_pending = true;
    }

    fn addRoute(self: *Endpoint, cid: []const u8, conn: *Conn) void {
        if (self.options.role != .server) return;
        self.routes.put(self.gpa, .init(cid), conn) catch log.warn("can't route a connection ID", .{});
    }

    fn removeRoutes(self: *Endpoint, conn: *Conn) void {
        var it = self.routes.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == conn) {
                // Removing invalidates the iterator. Start over; a connection
                // has a handful of IDs.
                self.routes.removeByPtr(entry.key_ptr);
                it = self.routes.iterator();
            }
        }
    }

    /// Sends everything the connection has to send: each stream's queued
    /// bytes, then ACKs and other frames.
    fn flush(self: *Endpoint, conn: *Conn) void {
        conn.flush_pending = false;

        var streams = conn.streams.valueIterator();
        stream: while (streams.next()) |stream_ptr| {
            const stream = stream_ptr.*;

            // One packet per iteration, until the stream has nothing left
            // or can't send more.
            while (!stream.closed) {
                // `unsent` stops at a chunk boundary. FIN goes with the
                // chunk that reaches the end of the written bytes.
                const data = stream.send.unsent();
                const fin = stream.fin and !stream.fin_sent and stream.send.sent + data.len == stream.send.end;
                if (data.len == 0 and !fin) continue :stream;

                const w = conn.quic.sendStream(&self.out, stream.id, data, fin) catch |err| switch (err) {
                    // The stream was reset or stopped. Its queued data is
                    // dropped.
                    error.StreamClosed => {
                        stream.send.sent = stream.send.end;
                        stream.fin_sent = true;
                        continue :stream;
                    },
                    else => return conn.fail(err),
                };
                stream.send.sent += w.consumed;
                if (w.fin) stream.fin_sent = true;

                // Nothing to send: congestion control is holding packets.
                const d = w.datagram orelse return;
                self.sendDatagram(d);

                // Flow control blocks this stream. Others may still send.
                if (w.blocked or (w.consumed == 0 and !w.fin)) continue :stream;
            }
        }

        // Packets without stream data: ACKs, flow control updates, PINGs.
        while (true) {
            const d = conn.quic.send(&self.out) catch |err| return conn.fail(err);
            self.sendDatagram(d orelse return);
        }
    }

    fn sendDatagram(self: *Endpoint, d: quic.Datagram) void {
        var to: PosixAddress = undefined;
        const to_len = Io.Threaded.addressToPosix(&d.to, &to);
        // The socket is blocking on io_uring; MSG_DONTWAIT drops a datagram
        // the kernel can't queue, which QUIC retransmits.
        while (true) {
            const rc = std.c.sendto(self.udp.fd, &self.out, d.len, std.posix.MSG.DONTWAIT, &to.any, to_len);
            switch (std.posix.errno(rc)) {
                .SUCCESS, .AGAIN, .NOBUFS => return,
                .INTR => continue,
                else => |err| return log.warn("send failed: {t}", .{err}),
            }
        }
    }

    /// Frees closed streams and closed connections, calling the handler for
    /// each first.
    fn reap(self: *Endpoint) void {
        var i: usize = 0;
        while (i < self.conns.items.len) {
            const conn = self.conns.items[i];
            conn.reapStreams();

            const reason = conn.closing orelse {
                i += 1;
                continue;
            };

            // A closing connection's streams close with it.
            _ = self.conns.orderedRemove(i);
            self.removeRoutes(conn);
            var streams = conn.streams.valueIterator();
            while (streams.next()) |stream| {
                if (self.options.handler.streamClosed) |f| f(self.options.handler.ctx, stream.*);
                stream.*.deinit();
            }
            conn.streams.deinit(self.gpa);

            if (self.options.handler.closed) |f| f(self.options.handler.ctx, conn, reason);
            conn.quic.deinit();
            self.gpa.destroy(conn);
        }
    }

    /// Sets the timer to the earliest expiry of any connection.
    fn armTimer(self: *Endpoint) void {
        var next: ?u64 = null;
        for (self.conns.items) |conn| {
            const ns = conn.quic.timeout() orelse continue;
            next = @min(next orelse ns, ns);
        }
        const ns = next orelse return;

        // libxev timers take milliseconds. Rounding up avoids firing before
        // the expiry and finding nothing to do.
        const ms = std.math.divCeil(u64, ns, std.time.ns_per_ms) catch unreachable;
        self.timer.reset(self.loop, &self.timer_c, &self.timer_cancel_c, ms, Endpoint, self, onTimer);
    }

    fn onTimer(self_: ?*Endpoint, _: *xev.Loop, _: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
        const self = self_.?;
        // A reset cancels the previous timer; `end` re-arms it.
        result catch {};

        self.begin();
        defer self.end();
        if (self.stopping) return .disarm;

        // Each connection checks its own expiry and does nothing if it
        // hasn't passed.
        for (self.conns.items) |conn| {
            if (conn.closing != null) continue;
            conn.quic.handleExpiry() catch |err| {
                conn.fail(err);
                continue;
            };
            conn.flush_pending = true;
        }
        return .disarm;
    }
};

pub const Conn = struct {
    endpoint: *Endpoint,
    quic: *quic.Connection = undefined,
    remote: IpAddress,
    streams: std.AutoHashMapUnmanaged(i64, *Stream) = .empty,
    /// For the app.
    context: ?*anyopaque = null,
    established: bool = false,
    flush_pending: bool = false,
    /// Set when the connection is done. It is freed when the event ends.
    closing: ?CloseReason = null,

    pub const StreamKind = enum { bidi, uni };

    pub fn openStream(conn: *Conn, kind: StreamKind) !*Stream {
        const id = switch (kind) {
            .bidi => try conn.quic.openBidiStream(),
            .uni => try conn.quic.openUniStream(),
        };
        return conn.addStream(id);
    }

    /// Sends CONNECTION_CLOSE with an application error code.
    pub fn close(conn: *Conn, app_error_code: u64) void {
        if (conn.closing != null) return;

        const e = conn.endpoint;
        e.begin();
        defer e.end();

        // One CONNECTION_CLOSE, best effort. A peer that misses it times
        // out.
        if (conn.quic.writeClose(&e.out, .{ .application = app_error_code })) |d| {
            if (d) |datagram| e.sendDatagram(datagram);
        } else |_| {}
        conn.closing = .local;
    }

    /// Closes the connection after an ngtcp2 error.
    fn fail(conn: *Conn, err: quic.Error) void {
        const e = conn.endpoint;
        conn.closing = switch (err) {
            error.Closed => .{ .peer = conn.quic.peerCloseCode() },
            error.IdleTimeout => .idle_timeout,
            error.HandshakeFailed => .handshake_failed,
            else => .failed,
        };

        // After a peer's close or an idle timeout there is no one to tell.
        switch (err) {
            error.Closed, error.IdleTimeout => {},
            // Tell the peer why.
            else => if (conn.quic.writeClose(&e.out, .{ .transport = conn.quic.errorCode() })) |d| {
                if (d) |datagram| e.sendDatagram(datagram);
            } else |_| {},
        }
    }

    fn addStream(conn: *Conn, id: i64) !*Stream {
        const gpa = conn.endpoint.gpa;
        const stream = try gpa.create(Stream);
        errdefer gpa.destroy(stream);
        stream.* = .{ .conn = conn, .id = id };
        try conn.streams.put(gpa, id, stream);
        return stream;
    }

    /// Streams ngtcp2 closed during the event, freed once nothing iterates
    /// `streams`.
    fn reapStreams(conn: *Conn) void {
        const handler = conn.endpoint.options.handler;

        // Removing invalidates the iterator. Each removal starts the scan
        // over.
        var again = true;
        while (again) {
            again = false;
            var it = conn.streams.iterator();
            while (it.next()) |entry| {
                const stream = entry.value_ptr.*;
                if (!stream.closed) continue;
                conn.streams.removeByPtr(entry.key_ptr);
                if (handler.streamClosed) |f| f(handler.ctx, stream);
                stream.deinit();
                again = true;
                break;
            }
        }
    }

    fn fromCtx(ctx: ?*anyopaque) *Conn {
        return @ptrCast(@alignCast(ctx.?));
    }

    fn onHandshake(ctx: ?*anyopaque, _: *quic.Connection) void {
        const conn = fromCtx(ctx);
        conn.established = true;
        const handler = conn.endpoint.options.handler;
        if (handler.connected) |f| f(handler.ctx, conn);
    }

    fn onStreamOpened(ctx: ?*anyopaque, _: *quic.Connection, id: i64) void {
        const conn = fromCtx(ctx);
        const stream = conn.addStream(id) catch return log.warn("can't track stream {d}", .{id});
        const handler = conn.endpoint.options.handler;
        if (handler.streamOpened) |f| f(handler.ctx, stream);
    }

    fn onStreamData(ctx: ?*anyopaque, qc: *quic.Connection, id: i64, bytes: []const u8, fin: bool) void {
        const conn = fromCtx(ctx);
        const stream = conn.streams.get(id) orelse return;

        // Without a data handler the bytes are dropped, and their credit is
        // returned so the peer isn't blocked.
        const handler = conn.endpoint.options.handler;
        if (handler.data) |f| f(handler.ctx, stream, bytes, fin) else qc.consume(id, bytes.len) catch {};
    }

    fn onStreamAcked(ctx: ?*anyopaque, _: *quic.Connection, id: i64, offset: u64, len: u64) void {
        const conn = fromCtx(ctx);
        const stream = conn.streams.get(id) orelse return;
        stream.send.ack(conn.endpoint.gpa, offset, len);
        const handler = conn.endpoint.options.handler;
        if (handler.acked) |f| f(handler.ctx, stream);
    }

    fn onStreamReset(ctx: ?*anyopaque, _: *quic.Connection, id: i64, code: u64) void {
        const conn = fromCtx(ctx);
        const stream = conn.streams.get(id) orelse return;
        const handler = conn.endpoint.options.handler;
        if (handler.reset) |f| f(handler.ctx, stream, code);
    }

    /// This can run while `flush` iterates `streams`. The stream is marked
    /// here and freed by `reap` when the event ends.
    fn onStreamClosed(ctx: ?*anyopaque, _: *quic.Connection, id: i64) void {
        const conn = fromCtx(ctx);
        if (conn.streams.get(id)) |stream| stream.closed = true;
    }

    fn onConnectionIdIssued(ctx: ?*anyopaque, _: *quic.Connection, cid: []const u8) void {
        const conn = fromCtx(ctx);
        conn.endpoint.addRoute(cid, conn);
    }

    fn onConnectionIdRetired(ctx: ?*anyopaque, _: *quic.Connection, cid: []const u8) void {
        const conn = fromCtx(ctx);
        _ = conn.endpoint.routes.remove(.init(cid));
    }
};

pub const Stream = struct {
    conn: *Conn,
    id: i64,
    /// For the app.
    context: ?*anyopaque = null,
    send: SendQueue = .{},
    /// `finish` was called.
    fin: bool = false,
    fin_sent: bool = false,
    /// ngtcp2 discarded the stream. It is freed when the event ends.
    closed: bool = false,

    /// Queues a copy of `bytes`. The copy is freed as the peer acknowledges
    /// it.
    pub fn write(stream: *Stream, bytes: []const u8) Allocator.Error!void {
        std.debug.assert(!stream.fin);

        // Writes to a closed stream or connection are dropped.
        if (stream.closed or stream.conn.closing != null) return;
        try stream.send.append(stream.conn.endpoint.gpa, bytes);
        stream.requestFlush();
    }

    /// Sends FIN after the queued bytes.
    pub fn finish(stream: *Stream) void {
        stream.fin = true;
        stream.requestFlush();
    }

    /// Bytes queued and not yet acknowledged.
    pub fn buffered(stream: *const Stream) u64 {
        return stream.send.end - stream.send.acked;
    }

    /// Returns `n` received bytes to the peer's flow control window.
    pub fn consume(stream: *Stream, n: usize) void {
        if (stream.closed or stream.conn.closing != null) return;
        stream.conn.quic.consume(stream.id, n) catch {};
        stream.requestFlush();
    }

    /// Aborts both directions with RESET_STREAM and STOP_SENDING.
    pub fn reset(stream: *Stream, app_error_code: u64) void {
        if (stream.closed or stream.conn.closing != null) return;
        stream.conn.quic.resetStream(stream.id, app_error_code) catch {};
        stream.requestFlush();
    }

    /// Marks the connection for flushing. Outside an event, the empty event
    /// flushes it now; inside one, the outermost `end` does.
    fn requestFlush(stream: *Stream) void {
        const e = stream.conn.endpoint;
        stream.conn.flush_pending = true;
        e.begin();
        e.end();
    }

    fn deinit(stream: *Stream) void {
        const gpa = stream.conn.endpoint.gpa;
        stream.send.deinit(gpa);
        gpa.destroy(stream);
    }
};

/// Bytes written to a stream, in fixed-size chunks that never move, so the
/// pointers ngtcp2 keeps stay valid. Offsets are stream offsets.
const SendQueue = struct {
    chunks: std.ArrayList(*[chunk_len]u8) = .empty,

    // Stream offsets, in order: base <= acked <= sent <= end.

    /// The offset of the first byte of `chunks.items[0]`.
    base: u64 = 0,
    /// Bytes before this are acknowledged.
    acked: u64 = 0,
    /// Bytes before this were passed to ngtcp2.
    sent: u64 = 0,
    /// The offset after the last byte written.
    end: u64 = 0,

    const chunk_len = 16 * 1024;

    fn append(q: *SendQueue, gpa: Allocator, bytes: []const u8) Allocator.Error!void {
        var rest = bytes;
        while (rest.len > 0) {
            // Bytes held in the chunks, acknowledged or not.
            const used: usize = @intCast(q.end - q.base);

            // The last chunk is full, or there is none.
            if (used == q.chunks.items.len * chunk_len) {
                const chunk = try gpa.create([chunk_len]u8);
                errdefer gpa.destroy(chunk);
                try q.chunks.append(gpa, chunk);
            }

            // Fill the last chunk.
            const chunk = q.chunks.items[used / chunk_len];
            const off = used % chunk_len;
            const n = @min(rest.len, chunk_len - off);
            @memcpy(chunk[off..][0..n], rest[0..n]);
            q.end += n;
            rest = rest[n..];
        }
    }

    /// The unsent bytes in the chunk holding `sent`.
    fn unsent(q: *const SendQueue) []const u8 {
        if (q.sent == q.end) return &.{};

        // `sent` as a position in the chunks.
        const rel: usize = @intCast(q.sent - q.base);
        const off = rel % chunk_len;
        const n: usize = @intCast(@min(chunk_len - off, q.end - q.sent));
        return q.chunks.items[rel / chunk_len][off..][0..n];
    }

    /// ngtcp2 reports acknowledgments as a growing contiguous prefix of the
    /// stream (`ngtcp2_rtb.c`, `acked_stream_data_offset`).
    fn ack(q: *SendQueue, gpa: Allocator, offset: u64, len: u64) void {
        std.debug.assert(offset == q.acked);
        q.acked = offset + len;

        // Free the chunks that are now fully acknowledged.
        while (q.chunks.items.len > 0 and q.acked >= q.base + chunk_len) {
            gpa.destroy(q.chunks.orderedRemove(0));
            q.base += chunk_len;
        }
    }

    fn deinit(q: *SendQueue, gpa: Allocator) void {
        for (q.chunks.items) |chunk| gpa.destroy(chunk);
        q.chunks.deinit(gpa);
    }
};

/// A connection ID as a hash map key.
const Cid = struct {
    len: u8,
    data: [c.NGTCP2_MAX_CIDLEN]u8,

    /// The unused bytes are zeroed. Equal IDs then hash equally.
    fn init(bytes: []const u8) Cid {
        var cid: Cid = .{ .len = @intCast(bytes.len), .data = @splat(0) };
        @memcpy(cid.data[0..bytes.len], bytes);
        return cid;
    }
};

test {
    _ = @import("endpoint_test.zig");
}

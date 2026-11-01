const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const PosixAddress = Io.Threaded.PosixAddress;
const xev = @import("xev");
const c = @import("c");
const quic = @import("quic.zig");
const pending = @import("pending.zig");

const log = std.log.scoped(.endpoint);

pub const Role = union(enum) {
    server: *const quic.Server,
    client: *const quic.Client,
};

pub const CloseReason = union(enum) {
    local,
    peer: quic.Connection.CloseCode,
    idle_timeout,
    handshake_failed,
    failed,
};

/// Callbacks run inside the endpoint. Stream data they write goes out after
/// they return, and connections they close are freed then. streamClosed and
/// closed run as the outermost call ends. Calls made from them flush and free
/// at once, as calls from outside the endpoint do.
pub const Handler = struct {
    ctx: ?*anyopaque = null,
    connected: ?*const fn (ctx: ?*anyopaque, conn: *Conn) void = null,
    streamOpened: ?*const fn (ctx: ?*anyopaque, stream: *Stream) void = null,
    /// The peer can't send past the stream's window until bytes are passed to
    /// Stream.consume. Without this handler, the endpoint consumes them.
    data: ?*const fn (ctx: ?*anyopaque, stream: *Stream, bytes: []const u8, fin: bool) void = null,
    /// The peer acknowledged more of the stream. Stream.buffered is updated
    /// before this runs.
    acked: ?*const fn (ctx: ?*anyopaque, stream: *Stream) void = null,
    reset: ?*const fn (ctx: ?*anyopaque, stream: *Stream, app_error_code: u64) void = null,
    /// The stream is freed when this returns.
    streamClosed: ?*const fn (ctx: ?*anyopaque, stream: *Stream) void = null,
    /// Runs after streamClosed for each of the connection's streams. conn is
    /// freed when this returns.
    closed: ?*const fn (ctx: ?*anyopaque, conn: *Conn, reason: CloseReason) void = null,
    /// The connection is still pending at the end of limits.timeout_ns. The
    /// endpoint closes it expired_grace_ns later unless it is admitted.
    pendingExpired: ?*const fn (ctx: ?*anyopaque, conn: *Conn) void = null,
};

/// role and pending must outlive the Endpoint. idle_timeout_ns through
/// connection_window go to quic.Connection.Options.
pub const Options = struct {
    local: IpAddress,
    role: Role,
    handler: Handler = .{},
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
    handshake_timeout_ns: ?u64 = null,
    keep_alive_ns: ?u64 = null,
    stream_window: u64 = 8 << 20,
    connection_window: u64 = 32 << 20,
    /// SO_RCVBUF, in bytes. Linux caps it at net.core.rmem_max.
    receive_buffer: c_int = 4 << 20,
    pending: ?*pending.Pending = null,
};

pub const expired_grace_ns = std.time.ns_per_s;

/// The length of the connection IDs a server's connections issue, chosen in
/// quic.Connection.accept. Short-header packets don't encode the length.
const cid_len = 16;

pub const Endpoint = struct {
    gpa: Allocator,
    io: Io,
    loop: *xev.Loop,
    options: Options,
    udp: xev.UDP,
    local: IpAddress,
    conns: std.ArrayList(*Conn) = .empty,
    routes: std.AutoHashMapUnmanaged(Cid, *Conn) = .empty,

    recv_c: xev.Completion = .{},
    recv_state: xev.UDP.State = undefined,
    recv_buf: [65536]u8 = undefined,

    timer: xev.Timer,
    timer_c: xev.Completion = .{},
    timer_cancel_c: xev.Completion = .{},

    stop_c: [2]xev.Completion = .{ .{}, .{} },

    out: [quic.max_datagram_size]u8 = undefined,
    depth: u32 = 0,
    stopping: bool = false,

    /// Binds options.local and starts receiving. The loop keeps pointers into
    /// the Endpoint, which must not move.
    pub fn init(self: *Endpoint, gpa: Allocator, io: Io, loop: *xev.Loop, options: Options) !void {
        const udp = try xev.UDP.init(options.local);
        errdefer _ = std.c.close(udp.fd);

        // xev's UDP.bind sets SO_REUSEPORT, which lets two sockets bind one
        // port. A plain bind reports a port in use as AddressInUse.
        var addr: PosixAddress = undefined;
        const addr_len = Io.Threaded.addressToPosix(&options.local, &addr);
        if (std.c.bind(udp.fd, &addr.any, addr_len) != 0) return switch (std.posix.errno(-1)) {
            .ADDRINUSE => error.AddressInUse,
            .ADDRNOTAVAIL => error.AddressUnavailable,
            .ACCES => error.AccessDenied,
            else => |e| std.posix.unexpectedErrno(e),
        };
        try std.posix.setsockopt(udp.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, &std.mem.toBytes(options.receive_buffer));

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

    /// Call once isStopped returns true.
    pub fn deinit(self: *Endpoint) void {
        std.debug.assert(self.conns.items.len == 0);
        self.conns.deinit(self.gpa);
        self.routes.deinit(self.gpa);
        self.timer.deinit();
        _ = std.c.close(self.udp.fd);
        self.* = undefined;
    }

    pub fn stop(self: *Endpoint) void {
        self.begin();
        defer self.end();
        self.stopping = true;
        for (self.conns.items) |conn| conn.close(0);

        self.cancel(&self.stop_c[0], &self.recv_c);
        self.cancel(&self.stop_c[1], &self.timer_c);
    }

    pub fn isStopped(self: *const Endpoint) bool {
        if (!self.stopping or self.conns.items.len > 0) return false;
        const completions = [_]*const xev.Completion{ &self.recv_c, &self.timer_c, &self.timer_cancel_c, &self.stop_c[0], &self.stop_c[1] };
        for (completions) |comp| if (comp.state() == .active) return false;
        return true;
    }

    pub fn connect(self: *Endpoint, remote: IpAddress) !*Conn {
        self.begin();
        defer self.end();
        std.debug.assert(self.options.role == .client and self.conns.items.len == 0);

        const conn = try self.gpa.create(Conn);
        errdefer self.gpa.destroy(conn);
        conn.* = .{ .endpoint = self, .remote = remote, .received_at = Io.Clock.boot.now(self.io) };
        conn.quic = try quic.Connection.connect(self.gpa, self.io, self.options.role.client, self.local, remote, self.connectionOptions(conn));
        errdefer conn.quic.deinit();
        try self.conns.append(self.gpa, conn);

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

    fn cancel(self: *Endpoint, cancel_c: *xev.Completion, target: *xev.Completion) void {
        if (target.state() != .active or cancel_c.state() == .active) return;
        cancel_c.* = .{ .op = .{ .cancel = .{ .c = target } } };
        self.loop.add(cancel_c);
    }

    // begin and end bracket each entry into the endpoint. The outermost end
    // flushes, frees closed connections and streams, and re-arms the timer.
    // ngtcp2 forbids its write calls inside its callbacks, and handlers up the
    // stack may still hold a Conn or Stream.
    fn begin(self: *Endpoint) void {
        self.depth += 1;
    }

    fn end(self: *Endpoint) void {
        self.depth -= 1;
        if (self.depth > 0) return;

        for (self.conns.items) |conn| {
            if (conn.flush_pending and conn.closing == null) self.flush(conn);
        }
        self.reap();

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

        const n = result catch |err| {
            if (err != error.Canceled) log.warn("receive failed: {t}", .{err});
            return if (self.stopping) .disarm else .rearm;
        };

        self.begin();
        defer self.end();
        self.dispatch(from, self.recv_buf[0..n]);
        return if (self.stopping) .disarm else .rearm;
    }

    fn dispatch(self: *Endpoint, from: IpAddress, packet: []const u8) void {
        const conn = switch (self.options.role) {
            .client => if (self.conns.items.len > 0) self.conns.items[0] else return,
            .server => self.route(packet) orelse return self.accept(from, packet),
        };
        if (conn.closing != null) return;

        conn.quic.receive(from, packet) catch |err| return conn.fail(err);
        conn.received_at = Io.Clock.boot.now(self.io);

        conn.remote = from;
        conn.flush_pending = true;
    }

    fn route(self: *Endpoint, packet: []const u8) ?*Conn {
        var vc: c.ngtcp2_version_cid = undefined;
        if (c.ngtcp2_pkt_decode_version_cid(&vc, packet.ptr, packet.len, cid_len) != 0) return null;
        return self.routes.get(.init(vc.dcid[0..vc.dcidlen]));
    }

    fn accept(self: *Endpoint, from: IpAddress, packet: []const u8) void {
        if (self.stopping) return;

        var vc: c.ngtcp2_version_cid = undefined;
        if (c.ngtcp2_pkt_decode_version_cid(&vc, packet.ptr, packet.len, cid_len) != 0) return;
        const hd = quic.initialHeader(packet) orelse return;

        var retry: ?quic.Retry = null;
        var source: ?pending.Source = null;
        if (self.options.pending) |p| {
            switch (quic.checkRetryToken(self.io, &p.retry_secret, &hd, from)) {
                .none => {},
                .valid => |r| retry = r,
                .invalid => return,
            }
            source = .of(from);
            switch (p.check(source.?, retry != null)) {
                .accept => {},
                .retry => return self.sendRetry(p, &hd, from),
                .drop => return,
            }
            p.add(source.?) catch return;
        }

        const conn = self.gpa.create(Conn) catch return self.releasePending(source);
        conn.* = .{ .endpoint = self, .remote = from, .received_at = Io.Clock.boot.now(self.io) };
        if (source) |src| conn.pending = .{
            .source = src,
            .deadline = Io.Clock.awake.now(self.io).addDuration(.fromNanoseconds(self.options.pending.?.limits.timeout_ns)),
        };
        self.conns.append(self.gpa, conn) catch {
            self.gpa.destroy(conn);
            return self.releasePending(source);
        };
        conn.quic = quic.Connection.accept(self.gpa, self.io, self.options.role.server, self.local, from, packet, retry, self.connectionOptions(conn)) catch {
            _ = self.conns.pop();
            self.removeRoutes(conn);
            self.gpa.destroy(conn);
            return self.releasePending(source);
        };
        // The client sends to the DCID it chose until it learns the server's
        // connection ID.
        self.addRoute(vc.dcid[0..vc.dcidlen], conn);

        var ids: [quic.Connection.max_connection_ids]c.ngtcp2_cid = undefined;
        for (conn.quic.connectionIds(&ids)) |*cid| self.addRoute(cid.data[0..cid.datalen], conn);
        conn.flush_pending = true;
    }

    fn releasePending(self: *Endpoint, source: ?pending.Source) void {
        if (source) |src| self.options.pending.?.remove(src);
    }

    fn sendRetry(self: *Endpoint, p: *pending.Pending, hd: *const c.ngtcp2_pkt_hd, to: IpAddress) void {
        const len = quic.writeRetry(self.io, &self.out, &p.retry_secret, hd, to) catch return;
        self.sendDatagram(.{ .len = len, .to = to });
        p.retries += 1;
    }

    fn addRoute(self: *Endpoint, cid: []const u8, conn: *Conn) void {
        if (self.options.role != .server) return;
        self.routes.put(self.gpa, .init(cid), conn) catch log.warn("can't route a connection ID", .{});
    }

    fn removeRoutes(self: *Endpoint, conn: *Conn) void {
        var it = self.routes.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == conn) {
                // Removing invalidates the iterator.
                self.routes.removeByPtr(entry.key_ptr);
                it = self.routes.iterator();
            }
        }
    }

    fn flush(self: *Endpoint, conn: *Conn) void {
        conn.flush_pending = false;

        var streams = conn.streams.valueIterator();
        stream: while (streams.next()) |stream_ptr| {
            const stream = stream_ptr.*;

            while (!stream.closed) {
                const data = stream.send.unsent();
                const fin = stream.fin and !stream.fin_sent and stream.send.sent + data.len == stream.send.end;
                if (data.len == 0 and !fin) continue :stream;

                const w = conn.quic.sendStream(&self.out, stream.id, data, fin) catch |err| switch (err) {
                    error.StreamClosed => {
                        stream.send.sent = stream.send.end;
                        stream.fin_sent = true;
                        continue :stream;
                    },
                    else => return conn.fail(err),
                };
                stream.send.sent += w.consumed;
                if (w.fin) stream.fin_sent = true;

                const d = w.datagram orelse return;
                self.sendDatagram(d);

                if (w.blocked or (w.consumed == 0 and !w.fin)) continue :stream;
            }
        }

        while (true) {
            const d = conn.quic.send(&self.out) catch |err| return conn.fail(err);
            self.sendDatagram(d orelse return);
        }
    }

    /// d must have been written into out. xev makes the socket blocking on
    /// io_uring, and MSG_DONTWAIT keeps sendto from waiting. QUIC loss
    /// recovery covers a datagram dropped on EAGAIN or ENOBUFS.
    fn sendDatagram(self: *Endpoint, d: quic.Datagram) void {
        var to: PosixAddress = undefined;
        const to_len = Io.Threaded.addressToPosix(&d.to, &to);
        while (true) {
            const rc = std.c.sendto(self.udp.fd, &self.out, d.len, std.posix.MSG.DONTWAIT, &to.any, to_len);
            switch (std.posix.errno(rc)) {
                .SUCCESS, .AGAIN, .NOBUFS => return,
                .INTR => continue,
                else => |err| return log.warn("send failed: {t}", .{err}),
            }
        }
    }

    fn reap(self: *Endpoint) void {
        var i: usize = 0;
        while (i < self.conns.items.len) {
            const conn = self.conns.items[i];
            conn.reapStreams();

            const reason = conn.closing orelse {
                i += 1;
                continue;
            };

            _ = self.conns.orderedRemove(i);
            self.removeRoutes(conn);
            var streams = conn.streams.valueIterator();
            while (streams.next()) |stream| {
                if (self.options.handler.streamClosed) |f| f(self.options.handler.ctx, stream.*);
                stream.*.deinit();
            }
            conn.streams.deinit(self.gpa);

            if (self.options.handler.closed) |f| f(self.options.handler.ctx, conn, reason);
            conn.admit();
            conn.quic.deinit();
            self.gpa.destroy(conn);
        }
    }

    fn armTimer(self: *Endpoint) void {
        var next: ?u64 = null;
        const now = Io.Clock.awake.now(self.io);
        for (self.conns.items) |conn| {
            if (conn.quic.timeout()) |ns| next = @min(next orelse ns, ns);
            if (conn.pending) |p| {
                const ns: u64 = @intCast(@max(0, now.durationTo(p.deadline).nanoseconds));
                next = @min(next orelse ns, ns);
            }
        }
        const ns = next orelse return;

        // Rounding up keeps the timer from firing before the deadline.
        const ms = std.math.divCeil(u64, ns, std.time.ns_per_ms) catch unreachable;
        self.timer.reset(self.loop, &self.timer_c, &self.timer_cancel_c, ms, Endpoint, self, onTimer);
    }

    fn onTimer(self_: ?*Endpoint, _: *xev.Loop, _: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
        const self = self_.?;
        result catch {};

        self.begin();
        defer self.end();
        if (self.stopping) return .disarm;

        const now = Io.Clock.awake.now(self.io);
        for (self.conns.items) |conn| {
            if (conn.closing != null) continue;

            // The first deadline runs pendingExpired and starts the grace
            // period. The second closes the connection.
            if (conn.pending) |*p| if (now.nanoseconds >= p.deadline.nanoseconds) {
                if (p.expired) {
                    conn.close(0);
                    continue;
                }
                p.expired = true;
                p.deadline = now.addDuration(.fromNanoseconds(expired_grace_ns));
                if (self.options.handler.pendingExpired) |f| f(self.options.handler.ctx, conn);
            };
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
    context: ?*anyopaque = null,
    established: bool = false,
    flush_pending: bool = false,
    closing: ?CloseReason = null,
    received_at: Io.Timestamp,
    pending: ?Pending = null,

    const Pending = struct {
        source: pending.Source,
        deadline: Io.Timestamp,
        expired: bool = false,
    };

    pub fn admit(conn: *Conn) void {
        const p = conn.pending orelse return;
        conn.pending = null;
        conn.endpoint.options.pending.?.remove(p.source);
    }

    pub const StreamKind = enum { bidi, uni };

    pub fn openStream(conn: *Conn, kind: StreamKind) !*Stream {
        const id = switch (kind) {
            .bidi => try conn.quic.openBidiStream(),
            .uni => try conn.quic.openUniStream(),
        };
        return conn.addStream(id);
    }

    /// Time since the latest datagram from the peer, or since the connection
    /// began. The boot clock keeps counting while the machine sleeps.
    pub fn silence(conn: *const Conn) Io.Duration {
        return conn.received_at.durationTo(Io.Clock.boot.now(conn.endpoint.io));
    }

    /// Sends CONNECTION_CLOSE with app_error_code. When called outside
    /// endpoint callbacks, close runs Handler.closed and frees conn before
    /// returning.
    pub fn close(conn: *Conn, app_error_code: u64) void {
        if (conn.closing != null) return;

        const e = conn.endpoint;
        e.begin();
        defer e.end();

        if (conn.quic.writeClose(&e.out, .{ .application = app_error_code })) |d| {
            if (d) |datagram| e.sendDatagram(datagram);
        } else |_| {}
        conn.closing = .local;
    }

    fn fail(conn: *Conn, err: quic.Error) void {
        const e = conn.endpoint;
        conn.closing = switch (err) {
            error.Closed => .{ .peer = conn.quic.peerCloseCode() },
            error.IdleTimeout => .idle_timeout,
            error.HandshakeFailed => .handshake_failed,
            else => .failed,
        };

        // A connection that is closing, draining or idle sends no
        // CONNECTION_CLOSE (RFC 9000 sections 10.1 and 10.2).
        switch (err) {
            error.Closed, error.IdleTimeout => {},
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

    fn reapStreams(conn: *Conn) void {
        const handler = conn.endpoint.options.handler;

        var again = true;
        while (again) {
            again = false;
            var it = conn.streams.iterator();
            while (it.next()) |entry| {
                const stream = entry.value_ptr.*;
                if (!stream.closed) continue;
                // Removing invalidates the iterator.
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

/// A stream of a Conn. Calls on it made outside endpoint callbacks flush at
/// once, and a failed flush can close and free the connection and its streams
/// before the call returns.
pub const Stream = struct {
    conn: *Conn,
    id: i64,
    context: ?*anyopaque = null,
    send: SendQueue = .{},
    fin: bool = false,
    fin_sent: bool = false,
    closed: bool = false,

    /// Writes to a closed stream or connection are dropped. finish must not
    /// have been called.
    pub fn write(stream: *Stream, bytes: []const u8) Allocator.Error!void {
        std.debug.assert(!stream.fin);

        if (stream.closed or stream.conn.closing != null) return;
        try stream.send.append(stream.conn.endpoint.gpa, bytes);
        stream.requestFlush();
    }

    pub fn finish(stream: *Stream) void {
        stream.fin = true;
        stream.requestFlush();
    }

    pub fn buffered(stream: *const Stream) u64 {
        return stream.send.end - stream.send.acked;
    }

    pub fn consume(stream: *Stream, n: usize) void {
        if (stream.closed or stream.conn.closing != null) return;
        stream.conn.quic.consume(stream.id, n) catch {};
        stream.requestFlush();
    }

    pub fn reset(stream: *Stream, app_error_code: u64) void {
        if (stream.closed or stream.conn.closing != null) return;
        stream.conn.quic.resetStream(stream.id, app_error_code) catch {};
        stream.requestFlush();
    }

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

const SendQueue = struct {
    chunks: std.ArrayList(*[chunk_len]u8) = .empty,

    // Stream offsets, with base <= acked <= sent <= end.
    base: u64 = 0,
    acked: u64 = 0,
    sent: u64 = 0,
    end: u64 = 0,

    const chunk_len = 16 * 1024;

    fn append(q: *SendQueue, gpa: Allocator, bytes: []const u8) Allocator.Error!void {
        var rest = bytes;
        while (rest.len > 0) {
            const used: usize = @intCast(q.end - q.base);

            if (used == q.chunks.items.len * chunk_len) {
                const chunk = try gpa.create([chunk_len]u8);
                errdefer gpa.destroy(chunk);
                try q.chunks.append(gpa, chunk);
            }

            const chunk = q.chunks.items[used / chunk_len];
            const off = used % chunk_len;
            const n = @min(rest.len, chunk_len - off);
            @memcpy(chunk[off..][0..n], rest[0..n]);
            q.end += n;
            rest = rest[n..];
        }
    }

    fn unsent(q: *const SendQueue) []const u8 {
        if (q.sent == q.end) return &.{};

        const rel: usize = @intCast(q.sent - q.base);
        const off = rel % chunk_len;
        const n: usize = @intCast(@min(chunk_len - off, q.end - q.sent));
        return q.chunks.items[rel / chunk_len][off..][0..n];
    }

    fn ack(q: *SendQueue, gpa: Allocator, offset: u64, len: u64) void {
        // ngtcp2 reports acknowledgements as a growing prefix of the stream.
        std.debug.assert(offset == q.acked);
        q.acked = offset + len;

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

const Cid = struct {
    len: u8,
    data: [c.NGTCP2_MAX_CIDLEN]u8,

    fn init(bytes: []const u8) Cid {
        var cid: Cid = .{ .len = @intCast(bytes.len), .data = @splat(0) };
        @memcpy(cid.data[0..bytes.len], bytes);
        return cid;
    }
};

test {
    _ = @import("endpoint_test.zig");
}

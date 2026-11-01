//! One QUIC connection on ngtcp2, with TLS from tls.c. The caller owns the
//! socket. It passes received datagrams to Connection.receive and sends the
//! datagrams that send, sendStream and writeClose write into its buffer.
//! endpoint.zig is that caller in tx, and quic_test.zig drives connections
//! over plain sockets.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const PosixAddress = Io.Threaded.PosixAddress;
const Ed25519 = std.crypto.sign.Ed25519;
const crypto = @import("crypto");
const c = @import("c");

/// ngtcp2 errors as Connection sorts them. Closed means the connection is
/// closing or draining. IdleTimeout includes a handshake timeout.
pub const Error = error{
    OutOfMemory,
    NotInitial,
    HandshakeFailed,
    Closed,
    IdleTimeout,
    StreamLimit,
    StreamClosed,
    Quic,
};

/// The ALPN of every connection. A server refuses a client that doesn't offer
/// it.
pub const alpn: []const u8 = c.TX_TLS_ALPN;

/// ngtcp2 writes no datagram larger than its default max_tx_udp_payload_size,
/// 1500 - 48 bytes. Buffers passed to send, sendStream and writeClose hold at
/// least this much.
pub const max_datagram_size = 1452;

/// The server's TLS identity, shared by every connection it accepts.
pub const Server = struct {
    tls: *c.tx_tls_server,
    /// Derives the stateless reset tokens for the connection IDs the server
    /// issues.
    reset_secret: [32]u8,

    /// tls.c keeps its own copy of the key pair.
    pub fn init(identity: Ed25519.KeyPair) Error!Server {
        var secret_key = identity.secret_key.toBytes();
        defer std.crypto.secureZero(u8, &secret_key);
        const public_key = identity.public_key.toBytes();
        const tls = c.tx_tls_server_new(&secret_key, &public_key, @intFromBool(crypto.has_hardware_aes)) orelse
            return error.OutOfMemory;
        var server: Server = .{ .tls = tls, .reset_secret = undefined };
        crypto.random(&server.reset_secret);
        return server;
    }

    pub fn deinit(self: *Server) void {
        c.tx_tls_server_free(self.tls);
        std.crypto.secureZero(u8, &self.reset_secret);
    }
};

/// TLS settings for outgoing connections. Every connection made from one
/// Client shares the record of which key the server presented.
pub const Client = struct {
    tls: *c.tx_tls_client,

    /// Which server keys a handshake accepts. init copies .keys.
    pub const Accept = union(enum) {
        keys: []const [32]u8,
        any,
    };

    pub fn init(accept: Accept) Error!Client {
        const keys: []const [32]u8 = switch (accept) {
            .keys => |keys| keys,
            .any => &.{},
        };
        const tls = c.tx_tls_client_new(@constCast(keys.ptr), keys.len, @intFromBool(accept == .any), @intFromBool(crypto.has_hardware_aes)) orelse
            return error.OutOfMemory;
        return .{ .tls = tls };
    }

    pub fn deinit(self: *Client) void {
        c.tx_tls_client_free(self.tls);
    }

    /// The key a server presented in the latest handshake, whether or not it
    /// was accepted. Null until a server presents one.
    pub fn presentedKey(self: *const Client) ?[32]u8 {
        var key: [32]u8 = undefined;
        if (c.tx_tls_client_presented_key(self.tls, &key) == 0) return null;
        return key;
    }
};

/// An outgoing datagram in the first len bytes of the buffer it was written
/// to.
pub const Datagram = struct {
    len: usize,
    to: IpAddress,
};

pub const RetryCheck = union(enum) {
    none,
    valid: Retry,
    /// A token that fails verification, such as an expired one or one issued
    /// to another address.
    invalid,
};

/// What Connection.accept needs from a verified Retry token. token points
/// into the received packet.
pub const Retry = struct {
    original_dcid: c.ngtcp2_cid,
    token: []const u8,
};

const retry_token_timeout_ns = 10 * std.time.ns_per_s;

/// The header of packet if it can open a new connection.
pub fn initialHeader(packet: []const u8) ?c.ngtcp2_pkt_hd {
    var hd: c.ngtcp2_pkt_hd = undefined;
    if (c.ngtcp2_accept(&hd, packet.ptr, packet.len) != 0) return null;
    return hd;
}

/// Checks the token in a client Initial against tokens writeRetry made with
/// secret for remote.
pub fn checkRetryToken(io: Io, secret: *const [32]u8, hd: *const c.ngtcp2_pkt_hd, remote: IpAddress) RetryCheck {
    // ngtcp2 tokens start with a magic byte. Tokens of other kinds count as none.
    if (hd.tokenlen == 0 or hd.token[0] != c.NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2) return .none;
    var addr: PosixAddress = undefined;
    const addr_len = Io.Threaded.addressToPosix(&remote, &addr);
    var original_dcid: c.ngtcp2_cid = undefined;
    if (c.ngtcp2_crypto_verify_retry_token2(&original_dcid, hd.token, hd.tokenlen, secret, secret.len, hd.version, @ptrCast(&addr.any), @intCast(addr_len), &hd.dcid, retry_token_timeout_ns, now(io)) != 0)
        return .invalid;
    return .{ .valid = .{ .original_dcid = original_dcid, .token = hd.token[0..hd.tokenlen] } };
}

/// Writes a Retry packet answering hd into out. Its token is valid from
/// remote for retry_token_timeout_ns.
pub fn writeRetry(io: Io, out: []u8, secret: *const [32]u8, hd: *const c.ngtcp2_pkt_hd, remote: IpAddress) Error!usize {
    var addr: PosixAddress = undefined;
    const addr_len = Io.Threaded.addressToPosix(&remote, &addr);
    const scid = randomCid(16);
    var token: [c.NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2]u8 = undefined;
    const token_len = c.ngtcp2_crypto_generate_retry_token2(&token, secret, secret.len, hd.version, @ptrCast(&addr.any), @intCast(addr_len), &scid, &hd.dcid, now(io));
    if (token_len < 0) return error.Quic;
    const n = c.ngtcp2_crypto_write_retry(out.ptr, out.len, hd.version, &hd.scid, &scid, &hd.dcid, &token, @intCast(token_len));
    if (n < 0) return error.Quic;
    return @intCast(n);
}

/// Heap-allocated. ngtcp2's user data and the TLS session's conn_ref point at
/// it.
pub const Connection = struct {
    gpa: Allocator,
    io: Io,
    conn: *c.ngtcp2_conn,
    session: *c.tx_tls_session,
    conn_ref: c.ngtcp2_crypto_conn_ref,
    local: IpAddress,
    handler: Handler,
    /// The Server's secret. Null for client connections, whose reset tokens
    /// are random.
    reset_secret: ?*const [32]u8,
    /// The ngtcp2 error behind the latest Error, for errorCode.
    last_error: c_int = 0,

    /// Callbacks run inside ngtcp2 calls. ngtcp2 forbids calling receive,
    /// send, sendStream or writeClose from them.
    pub const Handler = struct {
        ctx: ?*anyopaque = null,
        handshakeCompleted: ?*const fn (ctx: ?*anyopaque, conn: *Connection) void = null,
        /// The stream's receive window reopens as consume is called for the
        /// data.
        streamData: ?*const fn (ctx: ?*anyopaque, conn: *Connection, stream_id: i64, data: []const u8, fin: bool) void = null,
        /// The peer has acknowledged every byte of the stream before
        /// offset + len.
        streamAcked: ?*const fn (ctx: ?*anyopaque, conn: *Connection, stream_id: i64, offset: u64, len: u64) void = null,
        /// The peer opened the stream.
        streamOpened: ?*const fn (ctx: ?*anyopaque, conn: *Connection, stream_id: i64) void = null,
        /// The peer reset the stream.
        streamReset: ?*const fn (ctx: ?*anyopaque, conn: *Connection, stream_id: i64, app_error_code: u64) void = null,
        streamClosed: ?*const fn (ctx: ?*anyopaque, conn: *Connection, stream_id: i64) void = null,
        /// A new connection ID the peer may address this end by.
        connectionIdIssued: ?*const fn (ctx: ?*anyopaque, conn: *Connection, cid: []const u8) void = null,
        connectionIdRetired: ?*const fn (ctx: ?*anyopaque, conn: *Connection, cid: []const u8) void = null,
    };

    pub const Options = struct {
        handler: Handler = .{},
        server_name: ?[*:0]const u8 = null,
        idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
        /// Used by connect only. Null leaves ngtcp2 with no handshake
        /// timeout.
        handshake_timeout_ns: ?u64 = null,
        /// ngtcp2 sends a PING after this long without traffic.
        keep_alive_ns: ?u64 = null,
        /// Bytes the peer may send on a stream beyond what has been
        /// consumed.
        stream_window: u64 = 8 << 20,
        /// Bytes the peer may send across all streams beyond what has been
        /// consumed.
        connection_window: u64 = 32 << 20,
    };

    pub const CloseCode = union(enum) {
        transport: u64,
        application: u64,
    };

    /// Starts a client handshake. Its first packet comes from send.
    pub fn connect(
        gpa: Allocator,
        io: Io,
        client: *const Client,
        local: IpAddress,
        remote: IpAddress,
        options: Options,
    ) Error!*Connection {
        const self = try gpa.create(Connection);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .conn = undefined,
            .session = undefined,
            .conn_ref = .{ .get_conn = getConn, .user_data = self },
            .local = local,
            .handler = options.handler,
            .reset_secret = null,
        };

        const dcid = randomCid(16);
        const scid = randomCid(16);
        var settings = defaultSettings(io);
        if (options.handshake_timeout_ns) |ns| settings.handshake_timeout = ns;
        var params = defaultParams(options);
        var path: Path = undefined;
        path.init(local, remote);
        var callbacks = commonCallbacks();
        callbacks.client_initial = &c.ngtcp2_crypto_client_initial_cb;
        callbacks.recv_retry = &c.ngtcp2_crypto_recv_retry_cb;

        var conn: ?*c.ngtcp2_conn = null;
        try self.check(c.ngtcp2_conn_client_new_versioned(
            &conn,
            &dcid,
            &scid,
            &path.value,
            c.NGTCP2_PROTO_VER_V1,
            c.NGTCP2_CALLBACKS_VERSION,
            &callbacks,
            c.NGTCP2_SETTINGS_VERSION,
            &settings,
            c.NGTCP2_TRANSPORT_PARAMS_VERSION,
            &params,
            null,
            self,
        ));
        self.conn = conn.?;
        if (options.keep_alive_ns) |ns| c.ngtcp2_conn_set_keep_alive_timeout(self.conn, ns);
        self.session = c.tx_tls_session_new_client(client.tls, self.conn, &self.conn_ref, options.server_name) orelse {
            c.ngtcp2_conn_del(self.conn);
            return error.OutOfMemory;
        };
        return self;
    }

    /// Creates a server connection from packet, a client's first Initial, and
    /// processes the packet. retry is the client's verified Retry token.
    pub fn accept(
        gpa: Allocator,
        io: Io,
        server: *const Server,
        local: IpAddress,
        remote: IpAddress,
        packet: []const u8,
        retry: ?Retry,
        options: Options,
    ) Error!*Connection {
        var hd: c.ngtcp2_pkt_hd = undefined;
        if (c.ngtcp2_accept(&hd, packet.ptr, packet.len) != 0) return error.NotInitial;

        const self = try gpa.create(Connection);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .conn = undefined,
            .session = undefined,
            .conn_ref = .{ .get_conn = getConn, .user_data = self },
            .local = local,
            .handler = options.handler,
            .reset_secret = &server.reset_secret,
        };

        // ngtcp2 issues later connection IDs at this length, and endpoint.zig's
        // cid_len assumes it.
        const scid = randomCid(16);
        var settings = defaultSettings(io);
        var params = defaultParams(options);
        params.original_dcid = hd.dcid;
        params.original_dcid_present = 1;

        // After a Retry, original_dcid is the DCID of the client's first
        // Initial, recovered from the token. retry_scid is the SCID the Retry
        // chose, which the client sends as its DCID (RFC 9000 section 7.3).
        if (retry) |r| {
            params.original_dcid = r.original_dcid;
            params.retry_scid = hd.dcid;
            params.retry_scid_present = 1;
            settings.token = r.token.ptr;
            settings.tokenlen = r.token.len;
            settings.token_type = c.NGTCP2_TOKEN_TYPE_RETRY;
        }
        params.stateless_reset_token_present = 1;
        if (c.ngtcp2_crypto_generate_stateless_reset_token(&params.stateless_reset_token, &server.reset_secret, server.reset_secret.len, &scid) != 0)
            return error.Quic;
        var path: Path = undefined;
        path.init(local, remote);
        var callbacks = commonCallbacks();
        callbacks.recv_client_initial = &c.ngtcp2_crypto_recv_client_initial_cb;

        var conn: ?*c.ngtcp2_conn = null;
        try self.check(c.ngtcp2_conn_server_new_versioned(
            &conn,
            &hd.scid,
            &scid,
            &path.value,
            hd.version,
            c.NGTCP2_CALLBACKS_VERSION,
            &callbacks,
            c.NGTCP2_SETTINGS_VERSION,
            &settings,
            c.NGTCP2_TRANSPORT_PARAMS_VERSION,
            &params,
            null,
            self,
        ));
        self.conn = conn.?;
        if (options.keep_alive_ns) |ns| c.ngtcp2_conn_set_keep_alive_timeout(self.conn, ns);
        self.session = c.tx_tls_session_new_server(server.tls, self.conn, &self.conn_ref) orelse {
            c.ngtcp2_conn_del(self.conn);
            return error.OutOfMemory;
        };
        errdefer {
            c.ngtcp2_conn_del(self.conn);
            c.tx_tls_session_free(self.session);
        }
        try self.receive(remote, packet);
        return self;
    }

    pub fn deinit(self: *Connection) void {
        c.ngtcp2_conn_del(self.conn);
        c.tx_tls_session_free(self.session);
        self.gpa.destroy(self);
    }

    /// Processes one datagram from `from`. Handler callbacks run inside.
    pub fn receive(self: *Connection, from: IpAddress, packet: []const u8) Error!void {
        var path: Path = undefined;
        path.init(self.local, from);
        var pi = std.mem.zeroes(c.ngtcp2_pkt_info);
        try self.check(c.ngtcp2_conn_read_pkt_versioned(self.conn, &path.value, c.NGTCP2_PKT_INFO_VERSION, &pi, packet.ptr, packet.len, now(self.io)));
    }

    /// Writes the next datagram the connection has to send into buf. Null when
    /// it has nothing, or congestion control holds it back.
    pub fn send(self: *Connection, buf: []u8) Error!?Datagram {
        std.debug.assert(buf.len >= max_datagram_size);
        var ps: c.ngtcp2_path_storage = undefined;
        c.ngtcp2_path_storage_zero(&ps);
        var pi: c.ngtcp2_pkt_info = undefined;
        const n = c.ngtcp2_conn_write_pkt_versioned(self.conn, &ps.path, c.NGTCP2_PKT_INFO_VERSION, &pi, buf.ptr, buf.len, now(self.io));
        return self.datagram(n, &ps);
    }

    pub const StreamWrite = struct {
        datagram: ?Datagram,
        /// Bytes of data the datagram carries.
        consumed: usize,
        /// The datagram carries the stream's FIN.
        fin: bool = false,
        /// Flow control holds the stream. The datagram, if any, carries
        /// other frames.
        blocked: bool = false,
    };

    /// Writes a datagram carrying a prefix of data on the stream, with FIN
    /// when fin is set and all of data fits. The caller keeps sent bytes
    /// until streamAcked covers them or the stream closes. ngtcp2 retransmits
    /// from them.
    pub fn sendStream(self: *Connection, buf: []u8, stream_id: i64, data: []const u8, fin: bool) Error!StreamWrite {
        std.debug.assert(buf.len >= max_datagram_size);
        var ps: c.ngtcp2_path_storage = undefined;
        c.ngtcp2_path_storage_zero(&ps);
        var pi: c.ngtcp2_pkt_info = undefined;
        var vec: c.ngtcp2_vec = .{ .base = @constCast(data.ptr), .len = data.len };
        var datalen: c.ngtcp2_ssize = -1;
        const flags: u32 = if (fin) c.NGTCP2_WRITE_STREAM_FLAG_FIN else 0;
        const n = c.ngtcp2_conn_writev_stream_versioned(self.conn, &ps.path, c.NGTCP2_PKT_INFO_VERSION, &pi, buf.ptr, buf.len, &datalen, flags, stream_id, &vec, 1, now(self.io));

        if (n == c.NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            return .{ .datagram = try self.send(buf), .consumed = 0, .blocked = true };
        }

        const d = try self.datagram(n, &ps);
        return .{
            .datagram = d,
            .consumed = if (datalen > 0) @intCast(datalen) else 0,
            .fin = fin and d != null and datalen == data.len,
        };
    }

    /// Fails with error.StreamLimit while the peer allows no more
    /// bidirectional streams.
    pub fn openBidiStream(self: *Connection) Error!i64 {
        var stream_id: i64 = undefined;
        try self.check(c.ngtcp2_conn_open_bidi_stream(self.conn, &stream_id, null));
        return stream_id;
    }

    pub fn openUniStream(self: *Connection) Error!i64 {
        var stream_id: i64 = undefined;
        try self.check(c.ngtcp2_conn_open_uni_stream(self.conn, &stream_id, null));
        return stream_id;
    }

    pub fn isLocalStream(self: *const Connection, stream_id: i64) bool {
        return c.ngtcp2_conn_is_local_stream2(self.conn, stream_id) != 0;
    }

    /// Aborts both directions of the stream, or the one direction a
    /// unidirectional stream has.
    pub fn resetStream(self: *Connection, stream_id: i64, app_error_code: u64) Error!void {
        try self.check(c.ngtcp2_conn_shutdown_stream(self.conn, 0, stream_id, app_error_code));
    }

    /// Writes a CONNECTION_CLOSE with code. The connection sends nothing
    /// after it.
    pub fn writeClose(self: *Connection, buf: []u8, code: CloseCode) Error!?Datagram {
        std.debug.assert(buf.len >= max_datagram_size);

        var ccerr: c.ngtcp2_ccerr = undefined;
        switch (code) {
            .transport => |v| c.ngtcp2_ccerr_set_transport_error(&ccerr, v, null, 0),
            .application => |v| c.ngtcp2_ccerr_set_application_error(&ccerr, v, null, 0),
        }

        var ps: c.ngtcp2_path_storage = undefined;
        c.ngtcp2_path_storage_zero(&ps);
        var pi: c.ngtcp2_pkt_info = undefined;
        const n = c.ngtcp2_conn_write_connection_close_versioned(self.conn, &ps.path, c.NGTCP2_PKT_INFO_VERSION, &pi, buf.ptr, buf.len, &ccerr, now(self.io));
        return self.datagram(n, &ps);
    }

    /// The transport error code to close with after the latest Error.
    pub fn errorCode(self: *const Connection) u64 {
        // A TLS alert maps to CRYPTO_ERROR 0x0100 + alert (RFC 9001 section 4.8).
        if (self.last_error == c.NGTCP2_ERR_CRYPTO)
            return c.NGTCP2_CRYPTO_ERROR | @as(u64, c.ngtcp2_conn_get_tls_alert2(self.conn));
        return c.ngtcp2_err_infer_quic_transport_error_code(self.last_error);
    }

    /// The code from the peer's CONNECTION_CLOSE.
    pub fn peerCloseCode(self: *const Connection) CloseCode {
        const ccerr = c.ngtcp2_conn_get_ccerr2(self.conn);
        return switch (ccerr.*.type) {
            c.NGTCP2_CCERR_TYPE_APPLICATION => .{ .application = ccerr.*.error_code },
            else => .{ .transport = ccerr.*.error_code },
        };
    }

    /// The connection IDs this end currently answers to.
    pub fn connectionIds(self: *const Connection, buf: *[max_connection_ids]c.ngtcp2_cid) []c.ngtcp2_cid {
        std.debug.assert(c.ngtcp2_conn_get_scid2(self.conn, null) <= buf.len);
        return buf[0..c.ngtcp2_conn_get_scid2(self.conn, buf)];
    }

    /// ngtcp2 keeps at most NGTCP2_MAX_SCID_POOL_SIZE (8) connection IDs, plus
    /// one for a preferred address.
    pub const max_connection_ids = 16;

    /// Returns flow-control credit for n bytes received on the stream, to both
    /// the stream's window and the connection's.
    pub fn consume(self: *Connection, stream_id: i64, n: usize) Error!void {
        try self.check(c.ngtcp2_conn_extend_max_stream_offset(self.conn, stream_id, n));
        c.ngtcp2_conn_extend_max_offset(self.conn, n);
    }

    /// Fills out with the TLS exporter secret for label. Both ends derive the
    /// same bytes. The handshake must be complete.
    pub fn exportSecret(self: *const Connection, out: []u8, label: [*:0]const u8) void {
        std.debug.assert(self.isHandshakeComplete());
        if (c.tx_tls_session_export(self.session, out.ptr, out.len, label) != 0) unreachable;
    }

    pub fn isHandshakeComplete(self: *const Connection) bool {
        return c.ngtcp2_conn_get_handshake_completed(self.conn) != 0;
    }

    /// Nanoseconds until handleExpiry has work, or null when no timer is set.
    pub fn timeout(self: *const Connection) ?u64 {
        const expiry = c.ngtcp2_conn_get_expiry(self.conn);
        if (expiry == std.math.maxInt(u64)) return null;
        const t = now(self.io);
        return if (expiry <= t) 0 else expiry - t;
    }

    /// Runs ngtcp2's expired timers. Packets they queue go out on the next
    /// send.
    pub fn handleExpiry(self: *Connection) Error!void {
        const t = now(self.io);
        if (c.ngtcp2_conn_get_expiry(self.conn) <= t) {
            try self.check(c.ngtcp2_conn_handle_expiry(self.conn, t));
        }
    }

    fn datagram(self: *Connection, n: c.ngtcp2_ssize, ps: *c.ngtcp2_path_storage) Error!?Datagram {
        if (n < 0) try self.check(n);
        if (n == 0) return null;
        const remote: *const PosixAddress = @ptrCast(@alignCast(ps.path.remote.addr));
        return .{ .len = @intCast(n), .to = Io.Threaded.addressFromPosix(remote) };
    }

    fn check(self: *Connection, rv: anytype) Error!void {
        if (rv >= 0) return;
        const code: c_int = @intCast(rv);
        self.last_error = code;
        return switch (code) {
            c.NGTCP2_ERR_CRYPTO => error.HandshakeFailed,
            c.NGTCP2_ERR_DRAINING, c.NGTCP2_ERR_CLOSING => error.Closed,
            c.NGTCP2_ERR_IDLE_CLOSE, c.NGTCP2_ERR_HANDSHAKE_TIMEOUT => error.IdleTimeout,
            c.NGTCP2_ERR_NOMEM => error.OutOfMemory,
            c.NGTCP2_ERR_STREAM_ID_BLOCKED => error.StreamLimit,
            c.NGTCP2_ERR_STREAM_SHUT_WR, c.NGTCP2_ERR_STREAM_NOT_FOUND => error.StreamClosed,
            else => error.Quic,
        };
    }
};

/// value points into local and remote. A Path is initialized in place and
/// must not be copied.
const Path = struct {
    local: PosixAddress,
    remote: PosixAddress,
    value: c.ngtcp2_path,

    fn init(path: *Path, local: IpAddress, remote: IpAddress) void {
        const local_len = Io.Threaded.addressToPosix(&local, &path.local);
        const remote_len = Io.Threaded.addressToPosix(&remote, &path.remote);
        path.value = .{
            .local = .{ .addr = @ptrCast(&path.local.any), .addrlen = local_len },
            .remote = .{ .addr = @ptrCast(&path.remote.any), .addrlen = remote_len },
            .user_data = null,
        };
    }
};

/// ngtcp2 timestamps are nanoseconds on a monotonic clock.
fn now(io: Io) c.ngtcp2_tstamp {
    return @intCast(Io.Clock.awake.now(io).nanoseconds);
}

fn randomCid(len: usize) c.ngtcp2_cid {
    var cid = std.mem.zeroes(c.ngtcp2_cid);
    cid.datalen = len;
    crypto.random(cid.data[0..len]);
    return cid;
}

fn defaultSettings(io: Io) c.ngtcp2_settings {
    var settings: c.ngtcp2_settings = undefined;
    c.ngtcp2_settings_default_versioned(c.NGTCP2_SETTINGS_VERSION, &settings);
    settings.initial_ts = now(io);
    return settings;
}

fn defaultParams(options: Connection.Options) c.ngtcp2_transport_params {
    var params: c.ngtcp2_transport_params = undefined;
    c.ngtcp2_transport_params_default_versioned(c.NGTCP2_TRANSPORT_PARAMS_VERSION, &params);
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.initial_max_stream_data_bidi_local = options.stream_window;
    params.initial_max_stream_data_bidi_remote = options.stream_window;
    params.initial_max_stream_data_uni = options.stream_window;
    params.initial_max_data = options.connection_window;
    params.max_idle_timeout = options.idle_timeout_ns;
    return params;
}

fn commonCallbacks() c.ngtcp2_callbacks {
    var cb = std.mem.zeroes(c.ngtcp2_callbacks);
    cb.recv_crypto_data = &c.ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = &c.ngtcp2_crypto_encrypt_cb;
    cb.decrypt = &c.ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = &c.ngtcp2_crypto_hp_mask_cb;
    cb.update_key = &c.ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = &c.ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = &c.ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.version_negotiation = &c.ngtcp2_crypto_version_negotiation_cb;
    cb.get_path_challenge_data2 = &c.ngtcp2_crypto_get_path_challenge_data2_cb;
    cb.rand = &rand;
    cb.get_new_connection_id2 = &getNewConnectionId;
    cb.handshake_completed = &handshakeCompleted;
    cb.recv_stream_data = &recvStreamData;
    cb.acked_stream_data_offset = &ackedStreamData;
    cb.stream_open = &streamOpen;
    cb.stream_close = &streamClose;
    cb.stream_reset = &streamReset;
    cb.remove_connection_id = &removeConnectionId;
    return cb;
}

fn fromUserData(user_data: ?*anyopaque) *Connection {
    return @ptrCast(@alignCast(user_data.?));
}

fn getConn(ref: [*c]c.ngtcp2_crypto_conn_ref) callconv(.c) ?*c.ngtcp2_conn {
    return fromUserData(ref.*.user_data).conn;
}

fn rand(dest: [*c]u8, len: usize, _: [*c]const c.ngtcp2_rand_ctx) callconv(.c) void {
    crypto.random(dest[0..len]);
}

fn getNewConnectionId(
    _: ?*c.ngtcp2_conn,
    cid: [*c]c.ngtcp2_cid,
    token: [*c]c.ngtcp2_stateless_reset_token,
    cidlen: usize,
    user_data: ?*anyopaque,
) callconv(.c) c_int {
    const self = fromUserData(user_data);
    crypto.random(cid.*.data[0..cidlen]);
    cid.*.datalen = cidlen;
    if (self.reset_secret) |secret| {
        if (c.ngtcp2_crypto_generate_stateless_reset_token(&token.*.data, secret, secret.len, cid) != 0)
            return c.NGTCP2_ERR_CALLBACK_FAILURE;
    } else {
        crypto.random(&token.*.data);
    }

    if (self.handler.connectionIdIssued) |f| f(self.handler.ctx, self, cid.*.data[0..cidlen]);
    return 0;
}

fn handshakeCompleted(_: ?*c.ngtcp2_conn, user_data: ?*anyopaque) callconv(.c) c_int {
    const self = fromUserData(user_data);
    if (self.handler.handshakeCompleted) |f| f(self.handler.ctx, self);
    return 0;
}

fn recvStreamData(
    _: ?*c.ngtcp2_conn,
    flags: u32,
    stream_id: i64,
    _: u64,
    data: [*c]const u8,
    datalen: usize,
    user_data: ?*anyopaque,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const self = fromUserData(user_data);
    const bytes: []const u8 = if (datalen == 0) &.{} else data[0..datalen];
    const fin = flags & c.NGTCP2_STREAM_DATA_FLAG_FIN != 0;
    if (self.handler.streamData) |f| f(self.handler.ctx, self, stream_id, bytes, fin);
    return 0;
}

fn ackedStreamData(
    _: ?*c.ngtcp2_conn,
    stream_id: i64,
    offset: u64,
    datalen: u64,
    user_data: ?*anyopaque,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const self = fromUserData(user_data);
    if (self.handler.streamAcked) |f| f(self.handler.ctx, self, stream_id, offset, datalen);
    return 0;
}

fn streamOpen(_: ?*c.ngtcp2_conn, stream_id: i64, user_data: ?*anyopaque) callconv(.c) c_int {
    const self = fromUserData(user_data);
    if (self.handler.streamOpened) |f| f(self.handler.ctx, self, stream_id);
    return 0;
}

fn streamClose(
    conn: ?*c.ngtcp2_conn,
    _: u32,
    stream_id: i64,
    _: u64,
    user_data: ?*anyopaque,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const self = fromUserData(user_data);

    // ngtcp2 doesn't raise the peer's stream limit by itself. Each closed peer
    // stream lets the peer open one more. Bit 0x2 marks a unidirectional
    // stream ID (RFC 9000 section 2.1).
    if (c.ngtcp2_conn_is_local_stream2(conn, stream_id) == 0) {
        if (stream_id & 0x2 != 0) c.ngtcp2_conn_extend_max_streams_uni(conn, 1) else c.ngtcp2_conn_extend_max_streams_bidi(conn, 1);
    }

    if (self.handler.streamClosed) |f| f(self.handler.ctx, self, stream_id);
    return 0;
}

fn streamReset(
    _: ?*c.ngtcp2_conn,
    stream_id: i64,
    _: u64,
    app_error_code: u64,
    user_data: ?*anyopaque,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const self = fromUserData(user_data);
    if (self.handler.streamReset) |f| f(self.handler.ctx, self, stream_id, app_error_code);
    return 0;
}

fn removeConnectionId(_: ?*c.ngtcp2_conn, cid: [*c]const c.ngtcp2_cid, user_data: ?*anyopaque) callconv(.c) c_int {
    const self = fromUserData(user_data);
    if (self.handler.connectionIdRetired) |f| f(self.handler.ctx, self, cid.*.data[0..cid.*.datalen]);
    return 0;
}

test {
    _ = @import("quic_test.zig");
}

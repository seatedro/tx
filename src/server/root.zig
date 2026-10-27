//! txd's server: QUIC connections attached to sessions.
//!
//! A client opens one bidirectional stream and sends `Hello`, then logs in:
//! `AuthProbe` for each key it might sign with, and `AuthSignature` with
//! one the server accepts. Keys come from `authorized_keys`, for the
//! server's own user only. Once logged in, the client sends `Attach`. The
//! server answers with `HelloReply`, `AuthProbeReply`, `AuthOk` and
//! `Attached`, then streams the session's output records and applies the
//! client's `Input` and `Resize`.
//! A connection that closes leaves its session running, detached. A
//! session ends when its program exits; the attached client gets `Exit`.
//! What a session sends its client is up to the session (see
//! `session.session`). The server hands it a `Connect` describing the
//! client, the client's `Attach` or `Resume`, and its `Input` and `Resize`.
//!
//! A client that lost its connection logs in on a new one with `Resume`,
//! which the session checks against its resume key. The login completes
//! when the session answers with `Attached`.
//!
//! A logged-in client may also list the sessions (`List`), or end one
//! (`Kill`).
//!
//! Listening on a wildcard address binds each address it covers, and
//! follows addresses as they come and go (see `addresses`).
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Ed25519 = std.crypto.sign.Ed25519;
const xev = @import("xev");
const transport = @import("transport");
const proto = @import("proto");
const session = @import("session");
const term = @import("term");
const auth = @import("auth");
const addresses = @import("addresses.zig");

const Endpoint = transport.endpoint.Endpoint;
const Conn = transport.endpoint.Conn;
const Stream = transport.endpoint.Stream;
const Session = session.Session;

const log = std.log.scoped(.server);

pub const Options = struct {
    listen: IpAddress,
    identity: Ed25519.KeyPair,
    /// The account clients log in as. No other user name is accepted.
    user: []const u8,
    /// `authorized_keys` files. The first one that exists is read, at each
    /// login attempt.
    authorized_keys: []const []const u8,
    /// The environment of new sessions. `TERM` and `COLORTERM` come from the
    /// client.
    environ: *const std.process.Environ.Map,
    /// argv of the program new sessions run. See `session.pty.Options`.
    argv: []const []const u8,
    program: ?[]const u8 = null,
    cwd: std.process.Child.Cwd = .inherit,
    /// Scrollback and log limits of each session's terminal.
    terminal: session.host.Options.TerminalOptions = .{},
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
    /// Limits on connections that haven't logged in.
    pending: transport.pending.Limits = .{},
};

pub const ErrorCode = proto.ErrorCode;

/// Output buffered on a stream above which the server stops reading the
/// program's output, and below which it resumes.
const high_water = 1 << 20;
const low_water = 256 << 10;

/// The longest message body accepted from a client.
const max_message = 1 << 20;

/// The longest message body accepted before login. Login messages carry
/// a user name, a key and a signature.
const max_login_message = 16 << 10;

/// Probes and signatures a client may send before the server gives up, as
/// sshd's MaxAuthTries.
const max_login_attempts = 6;

const boundedSize = session.session.boundedSize;
const cellSize = session.session.cellSize;

/// How often a server listening on a wildcard address looks for addresses
/// that came or went.
const rescan_ms = 5000;

pub const Server = struct {
    gpa: Allocator,
    io: Io,
    loop: *xev.Loop,
    options: Options,
    tls: transport.quic.Server,
    /// Shared by the endpoints.
    pending: transport.pending.Pending,
    /// One per address listened on. They don't move.
    endpoints: std.ArrayList(*Endpoint) = .empty,
    /// Endpoints whose address went away, freed once stopped.
    retired: std.ArrayList(*Endpoint) = .empty,
    /// Set when `Options.listen` is a wildcard address.
    rescan: ?Rescan = null,
    stopping: bool = false,
    sessions: std.AutoArrayHashMapUnmanaged(u64, *Session) = .empty,
    next_id: u64 = 1,

    const Rescan = struct {
        /// `Options.listen`, with the port the first bind got if it asked
        /// for 0.
        wildcard: IpAddress,
        /// Loopback addresses for the host name, found once at startup.
        host_loopback: []IpAddress,
        timer: xev.Timer,
        c: xev.Completion = .{},
        cancel_c: xev.Completion = .{},
    };

    /// The server must not move while the loop runs.
    pub fn init(self: *Server, gpa: Allocator, io: Io, loop: *xev.Loop, options: Options) !void {
        self.* = .{
            .gpa = gpa,
            .io = io,
            .loop = loop,
            .options = options,
            .tls = try .init(options.identity),
            .pending = .init(gpa, options.pending),
        };
        errdefer self.deinit();

        if (!addresses.isWildcard(options.listen)) {
            _ = try self.listen(options.listen);
            return;
        }

        // A wildcard: each address it covers, and again as they change.
        self.rescan = .{
            .wildcard = options.listen,
            .host_loopback = try addresses.hostLoopback(gpa, io, options.listen),
            .timer = try .init(),
        };
        const in_use = try self.updateAddresses(.initial);
        // With every address taken, another server likely has the port.
        if (self.endpoints.items.len == 0) return if (in_use > 0) error.AddressInUse else error.NoAddresses;
        self.rescan.?.timer.run(loop, &self.rescan.?.c, rescan_ms, Server, self, onRescan);
    }

    /// The first bound address, with the port the kernel picked.
    pub fn address(self: *const Server) IpAddress {
        return self.endpoints.items[0].local;
    }

    /// Closes every connection and sends every session's program SIGHUP.
    /// Run the loop until it has no active completions, which takes at most
    /// `session.session.stop_grace_ms`, then call `deinit`. It kills
    /// programs still running.
    pub fn stop(self: *Server) void {
        self.stopping = true;
        for (self.endpoints.items) |e| e.stop();
        if (self.rescan) |*r| if (r.c.state() == .active) {
            r.cancel_c = .{ .op = .{ .cancel = .{ .c = &r.c } } };
            self.loop.add(&r.cancel_c);
        };
        for (self.sessions.values()) |s| s.stop();
    }

    pub fn deinit(self: *Server) void {
        for (self.sessions.values()) |s| s.destroy();
        self.sessions.deinit(self.gpa);
        for (self.endpoints.items) |e| self.destroyEndpoint(e);
        self.endpoints.deinit(self.gpa);
        for (self.retired.items) |e| self.destroyEndpoint(e);
        self.retired.deinit(self.gpa);
        if (self.rescan) |*r| {
            self.gpa.free(r.host_loopback);
            r.timer.deinit();
        }
        self.pending.deinit();
        self.tls.deinit();
        self.* = undefined;
    }

    /// Binds an endpoint to `local`.
    fn listen(self: *Server, local: IpAddress) !*Endpoint {
        const e = try self.gpa.create(Endpoint);
        errdefer self.gpa.destroy(e);
        try e.init(self.gpa, self.io, self.loop, .{
            .local = local,
            .role = .{ .server = &self.tls },
            .idle_timeout_ns = self.options.idle_timeout_ns,
            .pending = &self.pending,
            .handler = .{
                .ctx = self,
                .connected = onConnected,
                .streamOpened = onStreamOpened,
                .data = onData,
                .acked = onAcked,
                .streamClosed = onStreamClosed,
                .closed = onClosed,
                .pendingExpired = onPendingExpired,
            },
        });
        errdefer e.deinit();
        try self.endpoints.append(self.gpa, e);
        return e;
    }

    fn destroyEndpoint(self: *Server, e: *Endpoint) void {
        e.deinit();
        self.gpa.destroy(e);
    }

    /// Binds the wildcard's addresses that have no endpoint, and stops the
    /// endpoints of addresses that went away.
    /// Returns how many addresses failed to bind with `AddressInUse`.
    fn updateAddresses(self: *Server, when: enum { initial, rescan }) !usize {
        const r = &self.rescan.?;
        const found = try addresses.interfaces(self.gpa, r.wildcard);
        defer self.gpa.free(found);

        // Bound endpoints whose address is gone. Their connections can't
        // reach the server any more.
        var i: usize = 0;
        while (i < self.endpoints.items.len) {
            const e = self.endpoints.items[i];
            if (contains(found, e.local) or contains(r.host_loopback, e.local)) {
                i += 1;
                continue;
            }
            log.info("{f} went away", .{e.local});
            e.stop();
            try self.retired.append(self.gpa, e);
            _ = self.endpoints.swapRemove(i);
        }

        var in_use: usize = 0;
        for ([_][]const IpAddress{ found, r.host_loopback }) |list| for (list) |found_address| {
            if (self.endpointFor(found_address) != null) continue;

            // The lists carry the port `wildcard` had when they were made,
            // which is 0 until the first bind picks one.
            var local = found_address;
            local.setPort(r.wildcard.getPort());

            // An IPv6 address still being checked for duplicates can't be
            // bound yet. A later rescan tries again.
            const e = self.listen(local) catch |err| {
                if (err == error.AddressInUse) in_use += 1;
                if (when == .initial) log.warn("can't listen on {f}: {t}", .{ local, err });
                continue;
            };
            log.info("listening on {f}", .{e.local});

            // A port of 0 lets the first bind pick one. The others use it.
            if (r.wildcard.getPort() == 0) r.wildcard.setPort(e.local.getPort());
        };
        return in_use;
    }

    fn endpointFor(self: *const Server, local: IpAddress) ?*Endpoint {
        for (self.endpoints.items) |e| if (addresses.eql(e.local, local)) return e;
        return null;
    }

    fn contains(list: []const IpAddress, wanted: IpAddress) bool {
        for (list) |a| if (addresses.eql(a, wanted)) return true;
        return false;
    }

    fn onRescan(self_: ?*Server, _: *xev.Loop, _: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
        const self = self_.?;
        result catch return .disarm;
        if (self.stopping) return .disarm;

        _ = self.updateAddresses(.rescan) catch |err| blk: {
            log.warn("looking for addresses failed: {t}", .{err});
            break :blk 0;
        };

        // Retired endpoints are freed once the loop has finished with them.
        var i: usize = 0;
        while (i < self.retired.items.len) {
            const e = self.retired.items[i];
            if (!e.isStopped()) {
                i += 1;
                continue;
            }
            self.destroyEndpoint(e);
            _ = self.retired.swapRemove(i);
        }

        const r = &self.rescan.?;
        r.timer.run(self.loop, &r.c, rescan_ms, Server, self, onRescan);
        return .disarm;
    }

    fn fromCtx(ctx: ?*anyopaque) *Server {
        return @ptrCast(@alignCast(ctx.?));
    }

    // Endpoint callbacks. A connection's `context` is its `Client`, set once
    // the handshake completes.

    fn onConnected(ctx: ?*anyopaque, conn: *Conn) void {
        const self = fromCtx(ctx);
        const client = self.gpa.create(Client) catch return conn.close(0);
        client.* = .{ .server = self, .conn = conn, .decoder = .init(self.gpa, max_login_message) };
        conn.context = client;
    }

    /// A client uses one stream. Others are refused.
    fn onStreamOpened(_: ?*anyopaque, stream: *Stream) void {
        const client = Client.of(stream.conn) orelse return stream.reset(0);
        if (client.stream != null) return stream.reset(0);
        client.stream = stream;
        stream.context = client;
    }

    fn onData(_: ?*anyopaque, stream: *Stream, bytes: []const u8, fin: bool) void {
        // Credit is returned at once. Input the program isn't reading
        // queues in the host.
        stream.consume(bytes.len);

        const client = Client.of(stream.conn) orelse return;
        if (client.stream != stream) return;

        client.decoder.feed(bytes);
        while (true) {
            const message = client.decoder.next() catch return client.fail(.protocol, "malformed message");
            client.handle(message orelse break);
            // `handle` may have closed the connection, or sent `Error` and
            // finished the stream.
            if (stream.conn.closing != null or stream.fin) return;
        }

        // The client finished its side: it is gone.
        if (fin) stream.conn.close(0);
    }

    /// The client's stream drained. Resume a paused session once it is
    /// below `low_water`.
    fn onAcked(_: ?*anyopaque, stream: *Stream) void {
        const client = Client.of(stream.conn) orelse return;
        const s = client.session orelse return;
        if (stream.buffered() <= low_water) s.drained();
    }

    fn onStreamClosed(_: ?*anyopaque, stream: *Stream) void {
        const client = Client.of(stream.conn) orelse return;
        if (client.stream == stream) client.stream = null;
    }

    /// The session, if any, keeps running detached.
    fn onClosed(_: ?*anyopaque, conn: *Conn, _: transport.endpoint.CloseReason) void {
        const client = Client.of(conn) orelse return;
        client.destroy();
        conn.context = null;
    }

    /// A client that hasn't logged in in time. The endpoint closes the
    /// connection shortly after.
    fn onPendingExpired(_: ?*anyopaque, conn: *Conn) void {
        const client = Client.of(conn) orelse return;
        log.info("{f} didn't log in in time", .{conn.remote});
        client.fail(.auth, "login timed out");
    }

    /// Whether `key_blob` may log in as `user`.
    fn accepts(self: *Server, user: []const u8, key_blob: []const u8) bool {
        if (!std.mem.eql(u8, user, self.options.user)) return false;

        // Ed25519 and RSA keys.
        const key = auth.ssh.PublicKey.parse(key_blob) catch return false;

        const match = auth.authorized_keys.check(self.io, self.gpa, self.options.authorized_keys, &key) catch |err| {
            log.warn("reading authorized_keys failed: {t}", .{err});
            return false;
        };
        return switch (match) {
            .allowed => true,
            .absent => false,
            .restricted => {
                log.info("refused key {s}: its authorized_keys line has options, which tx doesn't implement yet", .{auth.Fingerprint.ofBlob(key.blob()).slice()});
                return false;
            },
        };
    }

    /// The sessions in order of ID. Owned by the caller.
    fn sortedSessions(self: *const Server, gpa: Allocator) ![]*Session {
        const sessions = try gpa.dupe(*Session, self.sessions.values());
        std.mem.sort(*Session, sessions, {}, struct {
            fn lessThan(_: void, a: *Session, b: *Session) bool {
                return a.id < b.id;
            }
        }.lessThan);
        return sessions;
    }

    fn startSession(self: *Server, hello: *const Hello) !*Session {
        // The server's environment, plus what describes the client's
        // terminal and the session's ID.
        var environ = try self.options.environ.clone(self.gpa);
        defer environ.deinit();
        try environ.put("TERM", hello.term.items);
        if (hello.colorterm.items.len > 0) try environ.put("COLORTERM", hello.colorterm.items);
        var id_buf: [20]u8 = undefined;
        try environ.put("TX_SESSION_ID", std.fmt.bufPrint(&id_buf, "{d}", .{self.next_id}) catch unreachable);

        try self.sessions.ensureUnusedCapacity(self.gpa, 1);
        const s = try Session.create(self.gpa, self.io, self.loop, .{
            .id = self.next_id,
            .argv = self.options.argv,
            .program = self.options.program,
            .environ = &environ,
            .cwd = self.options.cwd,
            .size = hello.size,
            .terminal = self.options.terminal,
            .ended = .{ .context = self, .call = onSessionEnded },
        });
        self.sessions.putAssumeCapacity(s.id, s);
        self.next_id += 1;
        return s;
    }

    /// The ID can't be attached to from now on. The session frees itself.
    fn onSessionEnded(ctx: ?*anyopaque, s: *Session) void {
        _ = fromCtx(ctx).sessions.swapRemove(s.id);
    }
};

/// What a client said in `Hello`, copied out of the decoder's buffer.
const Hello = struct {
    term: std.ArrayList(u8) = .empty,
    colorterm: std.ArrayList(u8) = .empty,
    size: term.log.Resize = undefined,

    fn deinit(h: *Hello, gpa: Allocator) void {
        h.term.deinit(gpa);
        h.colorterm.deinit(gpa);
    }
};

/// One connection's state.
const Client = struct {
    server: *Server,
    conn: *Conn,
    stream: ?*Stream = null,
    decoder: proto.Decoder,
    hello: ?Hello = null,
    logged_in: bool = false,
    /// Probes and signatures received.
    login_attempts: u32 = 0,
    session: ?*Session = null,
    /// The highest seq the client reported written to its terminal.
    acked: ?u64 = null,

    fn of(conn: *Conn) ?*Client {
        return @ptrCast(@alignCast(conn.context orelse return null));
    }

    fn destroy(client: *Client) void {
        const gpa = client.server.gpa;
        if (client.session) |s| s.disconnect();
        client.decoder.deinit();
        if (client.hello) |*h| h.deinit(gpa);
        gpa.destroy(client);
    }

    /// Hello, then the login, then Attach, then Input, Resize, Ack and
    /// Detach. Unknown message types are ignored, for newer clients.
    fn handle(client: *Client, message: proto.Message) void {
        // Before login, a client can say hello, log in and leave.
        if (!client.logged_in) switch (message) {
            .hello, .auth_probe, .auth_signature, .@"resume", .detach, .unknown => {},
            else => return client.fail(.protocol, "not logged in"),
        };

        switch (message) {
            .hello => |m| client.onHello(m),
            .auth_probe => |m| client.onAuthProbe(m),
            .auth_signature => |m| client.onAuthSignature(m),
            .attach => |m| client.onAttach(m),
            .@"resume" => |m| client.onResume(m),
            .list => client.onList(),
            .kill => |m| client.onKill(m),
            .input, .resize => if (client.session) |s| s.handle(message),
            .ack => |m| client.acked = m.seq,
            .detach => client.conn.close(0),
            .unknown => {},
            else => client.fail(.protocol, "unexpected message"),
        }
    }

    fn onHello(client: *Client, m: proto.Hello) void {
        if (client.hello != null) return client.fail(.protocol, "second hello");
        if (m.revision != proto.revision) return client.fail(.revision, "unsupported protocol revision");

        // Copied: the decoder's buffer is reused for the next message.
        const gpa = client.server.gpa;
        var hello: Hello = .{ .size = boundedSize(m.cols, m.rows, cellSize(m.cell_width_px, m.cell_height_px)) orelse
            .{ .cols = 80, .rows = 24 } };
        hello.term.appendSlice(gpa, m.term) catch return client.fail(.protocol, "out of memory");
        hello.colorterm.appendSlice(gpa, m.colorterm orelse "") catch return client.fail(.protocol, "out of memory");
        client.hello = hello;
        client.send(.{ .hello_reply = .{ .revision = proto.revision } });
    }

    fn onAuthProbe(client: *Client, m: proto.AuthProbe) void {
        if (!client.startLoginAttempt()) return;
        client.send(.{ .auth_probe_reply = .{ .key = m.key, .accepted = client.server.accepts(m.user, m.key) } });
    }

    fn onAuthSignature(client: *Client, m: proto.AuthSignature) void {
        if (!client.startLoginAttempt()) return;
        const server = client.server;

        // `accepts` checked the user name and the key's type.
        if (!server.accepts(m.user, m.key)) return client.fail(.auth, "login refused");
        const key = auth.ssh.PublicKey.parse(m.key) catch unreachable;
        const fingerprint = auth.Fingerprint.ofBlob(key.blob());

        // The transcript as the server sees the connection. A signature
        // made for another connection or server doesn't match it.
        var transcript: auth.login.Transcript = .{
            .exporter = undefined,
            .host_key = server.options.identity.public_key.toBytes(),
            .user = m.user,
            .alpn = transport.quic.alpn,
            .revision = proto.revision,
        };
        client.conn.quic.exportSecret(&transcript.exporter, auth.login.exporter_label);

        transcript.verify(&key, m.signature) catch {
            log.info("bad signature from {f} for {s} with key {s}", .{ client.conn.remote, m.user, fingerprint.slice() });
            return client.fail(.auth, "login refused");
        };

        log.info("{f} logged in as {s} with key {s}", .{ client.conn.remote, m.user, fingerprint.slice() });
        client.logged_in = true;
        client.conn.admit();
        client.decoder.max_body_len = max_message;
        client.send(.{ .auth_ok = .{} });
    }

    /// Counts a probe or signature. False if the client has used up its
    /// attempts, or is logged in already.
    fn startLoginAttempt(client: *Client) bool {
        if (client.hello == null) {
            client.fail(.protocol, "login before hello");
            return false;
        }
        if (client.logged_in) {
            client.fail(.protocol, "second login");
            return false;
        }

        client.login_attempts += 1;
        if (client.login_attempts > max_login_attempts) {
            client.fail(.auth, "too many login attempts");
            return false;
        }
        return true;
    }

    fn onAttach(client: *Client, m: proto.Attach) void {
        const hello = &(client.hello orelse return client.fail(.protocol, "attach before hello"));
        if (client.session != null) return client.fail(.protocol, "second attach");

        // An ID reattaches, and so does `reuse` with one detached session.
        // Otherwise a new session starts, and its output goes to the client
        // from the first record.
        const server = client.server;
        const existing = if (m.session_id) |id|
            server.sessions.get(id) orelse return client.fail(.no_session, "no such session")
        else if (m.reuse)
            client.onlyDetached() catch return
        else
            null;
        const s = existing orelse server.startSession(hello) catch |err| {
            log.warn("starting a session failed: {t}", .{err});
            return client.fail(.spawn, "can't start the session");
        };
        client.connectTo(s, null, .{ .attach = m });
    }

    /// The detached session, if there is exactly one. With several, sends
    /// `Error` naming them.
    fn onlyDetached(client: *Client) error{Refused}!?*Session {
        const gpa = client.server.gpa;
        const sessions = client.server.sortedSessions(gpa) catch {
            client.fail(.protocol, "out of memory");
            return error.Refused;
        };
        defer gpa.free(sessions);

        var found: ?*Session = null;
        var count: usize = 0;
        var buf: [256]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        w.writeAll("sessions") catch {};
        for (sessions) |s| {
            if (s.attached()) continue;
            found = s;
            count += 1;
            // A message too long for the buffer is cut short.
            w.print("{s} {d}", .{ if (count > 1) "," else "", s.id }) catch {};
        }
        if (count <= 1) return found;

        w.writeAll(" are detached") catch {};
        client.fail(.several_detached, w.buffered());
        return error.Refused;
    }

    fn onList(client: *Client) void {
        const server = client.server;
        const sessions = server.sortedSessions(server.gpa) catch return client.fail(.protocol, "out of memory");
        defer server.gpa.free(sessions);
        for (sessions) |s| client.send(.{ .session_info = s.info() });
        client.send(.{ .list_end = .{} });
    }

    fn onKill(client: *Client, m: proto.Kill) void {
        const s = client.server.sessions.get(m.session_id) orelse return client.fail(.no_session, "no such session");
        log.info("{f} killed session {d}", .{ client.conn.remote, s.id });
        s.kill();
        client.send(.{ .killed = .{ .session_id = s.id } });
    }

    /// Logs in with a proof of the session's resume key, which the session
    /// checks.
    fn onResume(client: *Client, m: proto.Resume) void {
        if (!client.startLoginAttempt()) return;

        // A session that doesn't exist and a proof that doesn't match get
        // the same answer.
        const s = client.server.sessions.get(m.session_id) orelse return client.fail(.auth, "can't resume the session");
        var exporter: [auth.resume_.exporter_len]u8 = undefined;
        client.conn.quic.exportSecret(&exporter, auth.resume_.exporter_label);
        client.connectTo(s, &exporter, .{ .@"resume" = m });
    }

    /// Hands the client to `s`, with `first`. The session answers on the
    /// client's link.
    fn connectTo(client: *Client, s: *Session, resume_exporter: ?[]const u8, first: session.session.First) void {
        const hello = &client.hello.?;
        var remote_buf: [64]u8 = undefined;
        const remote = std.fmt.bufPrint(&remote_buf, "{f}", .{client.conn.remote}) catch "";
        s.connect(client.link(), .{
            .remote = remote,
            .cols = hello.size.cols,
            .rows = hello.size.rows,
            .cell_width_px = if (hello.size.cell_size_px) |c| c.width else null,
            .cell_height_px = if (hello.size.cell_size_px) |c| c.height else null,
            .resume_exporter = resume_exporter,
        }, first);
    }

    fn link(client: *Client) session.session.Link {
        return .{ .context = client, .vtable = &link_vtable };
    }

    const link_vtable: session.session.Link.VTable = .{
        .send = linkSend,
        .finish = linkFinish,
        .congested = linkCongested,
        .detached = linkDetached,
    };

    fn fromLink(context: *anyopaque) *Client {
        return @ptrCast(@alignCast(context));
    }

    fn linkSend(context: *anyopaque, message: proto.Message) void {
        const client = fromLink(context);
        if (message == .attached) {
            client.session = client.server.sessions.get(message.attached.session_id);

            // A resume's login completes when the session accepts its proof.
            if (!client.logged_in) {
                client.logged_in = true;
                client.conn.admit();
                client.decoder.max_body_len = max_message;
            }
        }
        client.send(message);
    }

    fn linkFinish(context: *anyopaque) void {
        if (fromLink(context).stream) |stream| stream.finish();
    }

    /// The stream copies what it's given. A client that doesn't take it
    /// would grow it without bound.
    fn linkCongested(context: *anyopaque) bool {
        const stream = fromLink(context).stream orelse return false;
        return stream.buffered() > high_water;
    }

    fn linkDetached(context: *anyopaque) void {
        fromLink(context).session = null;
    }

    /// Encodes `message` onto the stream, which copies it. A failure closes
    /// the connection.
    fn send(client: *Client, message: proto.Message) void {
        const stream = client.stream orelse return;
        // Nothing follows `Error` or `Exit`.
        if (stream.fin) return;
        const gpa = client.server.gpa;
        const buf = gpa.alloc(u8, proto.encodedLen(message)) catch return client.conn.close(0);
        defer gpa.free(buf);
        var w: Io.Writer = .fixed(buf);
        proto.encode(&w, message) catch unreachable;
        stream.write(buf) catch client.conn.close(0);
    }

    /// Sends `Error` and finishes the stream. The client closes the
    /// connection after reading it.
    fn fail(client: *Client, code: ErrorCode, message: []const u8) void {
        client.send(.{ .@"error" = .{ .code = @backingInt(code), .message = message } });
        if (client.stream) |stream| stream.finish();
    }
};

test {
    _ = addresses;
    // Analyzes the crypto module, whose exports the linked C code needs.
    _ = &transport.crypto.init;
}

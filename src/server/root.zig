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
//!
//! Attaching to a running session resizes it to the client's terminal and
//! sends `Rebuild`, bytes generated from the primary terminal's state (see
//! `term.rebuild`). Output records follow from the next seq. The log may
//! have dropped its start by then.
//!
//! A client that lost its connection logs in on a new one with `Resume`,
//! which proves it holds the session's resume key (see `auth.resume_`).
//! The output continues from the first record the client hasn't
//! written, or the client gets a repaint when the log no longer holds it.
//! A client whose session is attached elsewhere gets `Error`, with
//! `attached_elsewhere`.
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
const Host = session.Host;

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

/// The most rebuild bytes sent in one message. Well below the client's
/// message limit.
const rebuild_part = 256 << 10;

/// The longest message body accepted before login. Login messages carry
/// a user name, a key and a signature.
const max_login_message = 16 << 10;

/// Probes and signatures a client may send before the server gives up, as
/// sshd's MaxAuthTries.
const max_login_attempts = 6;

/// Bounds on a client's terminal size. libghostty-vt asserts on zero, and
/// the size sets how much memory the primary terminal allocates.
const max_cols = 1024;
const max_rows = 1024;

/// A client's size within bounds, or null to ignore it.
fn boundedSize(cols: u16, rows: u16, cell: ?term.log.Resize.CellSize) ?term.log.Resize {
    if (cols == 0 or rows == 0) return null;
    return .{ .cols = @min(cols, max_cols), .rows = @min(rows, max_rows), .cell_size_px = cell };
}

/// How long `Server.stop` gives a program to exit after SIGHUP. Programs
/// still running then are killed by `Server.deinit`.
const stop_grace_ms = 1000;

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
    /// `stop_grace_ms`, then call `deinit`. It kills programs still running.
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
        if (s.paused and stream.buffered() <= low_water) s.resume_();
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

        const s = try self.gpa.create(Session);
        errdefer self.gpa.destroy(s);
        var wake: xev.Async = try .init();
        errdefer wake.deinit();
        var grace: xev.Timer = try .init();
        errdefer grace.deinit();
        var kill_timer: xev.Timer = try .init();
        errdefer kill_timer.deinit();

        // The host's thread can notify as soon as it starts. `wake` has to
        // exist first.
        s.* = .{
            .server = self,
            .id = self.next_id,
            .host = undefined,
            .started = Io.Clock.boot.now(self.io),
            .wake = wake,
            .grace = grace,
            .kill_timer = kill_timer,
        };
        s.host = try Host.create(self.gpa, self.io, .{
            .argv = self.options.argv,
            .program = self.options.program,
            .environ = &environ,
            .cwd = self.options.cwd,
            .size = hello.size,
            .terminal = self.options.terminal,
            .notify = Session.onHostNotify,
            .context = s,
        });
        errdefer s.host.destroy();

        try self.sessions.put(self.gpa, s.id, s);
        self.next_id += 1;

        // A notification sent before this is kept by the Async.
        s.wake.wait(self.loop, &s.wake_c, Session, s, Session.onWake);
        return s;
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
        if (client.session) |s| s.detach();
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
            .input => |m| if (client.session) |s| {
                s.input(m.bytes);
                s.input_offset += m.bytes.len;
            },
            .resize => |m| if (client.session) |s| {
                if (boundedSize(m.cols, m.rows, cellSize(m.cell_width_px, m.cell_height_px))) |size| s.resize(size);
            },
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
        if (existing) |s| return client.attachTo(s, .{ .rebuild = .attach }, .attached);

        const s = server.startSession(hello) catch |err| {
            log.warn("starting a session failed: {t}", .{err});
            return client.fail(.spawn, "can't start the session");
        };
        client.attachTo(s, .new, .attached);
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
            if (s.client != null) continue;
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
        const now = Io.Clock.boot.now(server.io);
        for (sessions) |s| {
            var from_buf: [64]u8 = undefined;
            const from = if (s.client) |c| std.fmt.bufPrint(&from_buf, "{f}", .{c.conn.remote}) catch null else null;
            const t = &s.host.primary.terminal;
            client.send(.{ .session_info = .{
                .session_id = s.id,
                .cols = t.cols,
                .rows = t.rows,
                .running_s = @intCast(@divTrunc(s.started.durationTo(now).nanoseconds, std.time.ns_per_s)),
                .attached_from = from,
                .title = t.getTitle(),
            } });
        }
        client.send(.{ .list_end = .{} });
    }

    fn onKill(client: *Client, m: proto.Kill) void {
        const s = client.server.sessions.get(m.session_id) orelse return client.fail(.no_session, "no such session");
        log.info("{f} killed session {d}", .{ client.conn.remote, s.id });
        s.kill();
        client.send(.{ .killed = .{ .session_id = s.id } });
    }

    /// Logs in with a proof of the session's resume key, and attaches.
    fn onResume(client: *Client, m: proto.Resume) void {
        if (!client.startLoginAttempt()) return;
        const hello = &client.hello.?;

        // A session that doesn't exist and a proof that doesn't match get
        // the same answer.
        const s = client.server.sessions.get(m.session_id) orelse return client.fail(.auth, "can't resume the session");
        var exporter: [auth.resume_.exporter_len]u8 = undefined;
        client.conn.quic.exportSecret(&exporter, auth.resume_.exporter_label);
        if (!auth.resume_.verify(&s.resume_key, &exporter, s.id, m.proof)) {
            log.info("{f} failed to resume session {d}", .{ client.conn.remote, s.id });
            return client.fail(.auth, "can't resume the session");
        }

        log.info("{f} resumed session {d}", .{ client.conn.remote, s.id });
        client.logged_in = true;
        client.conn.admit();
        client.decoder.max_body_len = max_message;

        const seq = m.next_seq orelse return client.attachTo(s, .{ .rebuild = .repaint }, .resumed);
        client.attachTo(s, if (s.canContinue(seq, hello.size)) .{ .continue_from = seq } else .{ .rebuild = .repaint }, .resumed);
    }

    const Start = union(enum) {
        /// A session started for this client. Its output goes from the
        /// first record.
        new,
        /// Output from the session's next record, after a rebuild.
        rebuild: term.rebuild.Kind,
        /// Output from `seq`, which the log holds.
        continue_from: u64,
    };

    /// `.resumed` keeps counting the client's input from where its last
    /// connection left off.
    fn attachTo(client: *Client, s: *Session, start: Start, how: enum { attached, resumed }) void {
        const hello = &client.hello.?;

        // One client at a time: the newer attach wins. The other client is
        // told, so that it doesn't resume. When it is this client's own
        // connection that was lost, nobody reads the error.
        if (s.client) |other| {
            s.detach();
            other.fail(.attached_elsewhere, "the session was attached elsewhere");
        }

        s.attach(client);
        if (how == .attached) s.input_offset = 0;
        client.send(.{ .attached = .{ .session_id = s.id, .resume_key = &s.resume_key, .input_offset = s.input_offset } });
        switch (start) {
            .new => {},
            .rebuild => |kind| s.rebuild_pending = kind,
            .continue_from => |seq| s.next_seq = seq,
        }

        // A running session is resized to the client's terminal. The
        // program redraws at that size, in output that follows.
        if (start != .new) {
            const t = &s.host.primary.terminal;
            if (t.cols != hello.size.cols or t.rows != hello.size.rows) s.resize(hello.size);
        }
        s.pump();
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

/// Null unless both are present.
fn cellSize(width: ?u32, height: ?u32) ?term.log.Resize.CellSize {
    return .{ .width = width orelse return null, .height = height orelse return null };
}

const Session = struct {
    server: *Server,
    id: u64,
    host: *Host,
    client: ?*Client = null,
    /// The next log seq to send to `client`.
    next_seq: u64 = 0,
    /// `client` gets a rebuild of this kind before any output.
    rebuild_pending: ?term.rebuild.Kind = null,
    /// Proves a client was the last to attach (see `auth.resume_`).
    resume_key: [auth.resume_.key_len]u8 = undefined,
    /// Bytes of input from the client since it attached, counted across
    /// its resumes.
    input_offset: u64 = 0,
    /// Output processing stopped because the client's stream holds
    /// `high_water` bytes. The host's thread stops reading the pty once its
    /// queue fills.
    paused: bool = false,
    /// Notified by the host's thread.
    wake: xev.Async,
    wake_c: xev.Completion = .{},
    grace: xev.Timer,
    grace_c: xev.Completion = .{},
    /// `Server.stop` was called and the grace period is over.
    grace_over: bool = false,
    /// Sends SIGKILL after `kill`.
    kill_timer: xev.Timer,
    kill_c: xev.Completion = .{},
    /// On `Io.Clock.boot`.
    started: Io.Timestamp,
    /// The program exited and the session left `Server.sessions`.
    ended: bool = false,

    fn attach(s: *Session, client: *Client) void {
        s.client = client;
        client.session = s;
        s.next_seq = 0;
        s.server.io.random(&s.resume_key);

        // The client's terminal answers queries now.
        s.host.answer_queries = false;
    }

    fn detach(s: *Session) void {
        if (s.client) |client| client.session = null;
        s.client = null;
        s.rebuild_pending = null;
        s.host.answer_queries = true;

        // No stream is backed up now. Output keeps flowing while detached.
        s.resume_();
    }

    fn input(s: *Session, bytes: []const u8) void {
        s.host.sendInput(bytes) catch log.warn("session {d}: input dropped", .{s.id});
    }

    fn resize(s: *Session, size: term.log.Resize) void {
        s.host.resize(size) catch |err| log.warn("session {d}: resize failed: {t}", .{ s.id, err });
    }

    /// Sends the client the rebuild it is owed, then the log records it
    /// hasn't seen. Resize records are skipped: the client's terminal is
    /// already at the size it asked for.
    fn pump(s: *Session) void {
        const client = s.client orelse return;
        const stream = client.stream orelse return;
        if (s.rebuild_pending) |kind| {
            s.sendRebuild(client, kind);
            // The output ends inside a long sequence. The next output may
            // finish it.
            if (s.rebuild_pending != null) return;
        }

        // The log dropped records the client hasn't been sent.
        var it = s.host.primary.log.iterator(s.next_seq) catch {
            return client.fail(.log_trimmed, "the client fell behind the session's log");
        };

        while (it.next()) |record| {
            switch (record.payload) {
                .output => |bytes| client.send(.{ .output = .{ .seq = record.seq, .bytes = bytes } }),
                .resize => {},
            }
            s.next_seq = record.seq + 1;
        }

        // The stream copies what it's given. A client that doesn't
        // acknowledge would grow it without bound.
        if (stream.buffered() > high_water) s.paused = true;
    }

    /// True if the log holds `seq` and the output since was written at
    /// `size`.
    fn canContinue(s: *const Session, seq: u64, size: term.log.Resize) bool {
        var it = s.host.primary.log.iterator(seq) catch return false;
        while (it.next()) |record| switch (record.payload) {
            .output => {},
            .resize => |r| if (r.cols != size.cols or r.rows != size.rows) return false,
        };
        return true;
    }

    /// Sends `Rebuild` for the primary's state, in parts, and continues
    /// from the log's next record.
    fn sendRebuild(s: *Session, client: *Client, kind: term.rebuild.Kind) void {
        const gpa = s.server.gpa;
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        s.host.primary.rebuild(&out.writer, kind) catch |err| switch (err) {
            error.Unfinished => return,
            error.WriteFailed => {
                log.warn("session {d}: rebuild failed: out of memory", .{s.id});
                return client.conn.close(0);
            },
        };
        s.rebuild_pending = null;
        s.next_seq = s.host.primary.log.nextSeq();

        var rest = out.written();
        while (rest.len > 0) {
            const part = rest[0..@min(rest.len, rebuild_part)];
            client.send(.{ .rebuild = .{ .seq = s.next_seq, .bytes = part } });
            rest = rest[part.len..];
        }
    }

    fn resume_(s: *Session) void {
        if (!s.paused) return;
        s.paused = false;
        s.process();
    }

    /// Logs the host's queued output, sends it to the client, and ends the
    /// session once the program has exited and its output is sent.
    fn process(s: *Session) void {
        if (s.paused or s.ended) return;

        s.host.processOutput() catch |err| log.warn("session {d}: output dropped: {t}", .{ s.id, err });
        s.pump();

        if (s.host.finished) s.reap();
    }

    /// Runs on the host's thread.
    fn onHostNotify(context: ?*anyopaque) void {
        const s: *Session = @ptrCast(@alignCast(context.?));
        s.wake.notify() catch |err| log.warn("session {d}: wakeup failed: {t}", .{ s.id, err });
    }

    fn onWake(s_: ?*Session, _: *xev.Loop, _: *xev.Completion, result: xev.Async.WaitError!void) xev.CallbackAction {
        const s = s_.?;
        result catch |err| log.warn("session {d}: wakeup failed: {t}", .{ s.id, err });

        // After the grace period, the session is left for `Server.deinit`.
        if (!s.grace_over) s.process();

        // Disarming is what lets the loop finish after `Server.stop`.
        if (s.ended or s.grace_over) {
            s.freeIfEnded();
            return .disarm;
        }
        return .rearm;
    }

    fn reap(s: *Session) void {
        const t = s.host.reap() catch |err| {
            log.warn("session {d}: wait failed: {t}", .{ s.id, err });
            return s.end(.{ .status = 255 });
        };

        // A signal is reported as a shell reports it, 128 plus its number,
        // and by name.
        s.end(switch (t) {
            .exited => |code| .{ .status = code },
            .signal => |sig| .{ .status = 128 +| @as(u8, @truncate(@backingInt(sig))), .signal = @tagName(sig) },
            else => .{ .status = 255 },
        });
    }

    /// The `wake` callback frees the session.
    fn end(s: *Session, exit: proto.Exit) void {
        if (s.client) |client| {
            client.send(.{ .exit = exit });
            if (client.stream) |stream| stream.finish();
            client.session = null;
        }
        s.client = null;

        // The ID can't be attached to from now on.
        _ = s.server.sessions.swapRemove(s.id);
        s.ended = true;

        // `end` may run outside `onWake`, from `resume_`. The notification
        // makes `onWake` run and free the session.
        s.wake.notify() catch {};
    }

    /// Sends the program SIGHUP. A program that exits within the grace
    /// period ends its session as usual.
    fn stop(s: *Session) void {
        if (s.ended) return;

        // Only the program gets it. Its jobs get SIGHUP from the shell, or
        // from the terminal closing in `Host.destroy`.
        s.host.pty.kill(.HUP) catch {};
        s.grace.run(s.server.loop, &s.grace_c, stop_grace_ms, Session, s, onGraceOver);
    }

    /// Sends the program SIGHUP, and SIGKILL if it is still running after
    /// the grace period.
    fn kill(s: *Session) void {
        if (s.ended or s.kill_c.state() == .active) return;
        s.host.pty.kill(.HUP) catch {};
        s.kill_timer.run(s.server.loop, &s.kill_c, stop_grace_ms, Session, s, onKillTimer);
    }

    fn onKillTimer(s_: ?*Session, _: *xev.Loop, _: *xev.Completion, _: xev.Timer.RunError!void) xev.CallbackAction {
        const s = s_.?;
        if (!s.ended) s.host.pty.kill(.KILL) catch {};
        s.freeIfEnded();
        return .disarm;
    }

    fn onGraceOver(s_: ?*Session, _: *xev.Loop, _: *xev.Completion, _: xev.Timer.RunError!void) xev.CallbackAction {
        const s = s_.?;
        s.grace_over = true;
        // Ends the `wake` wait. The loop can then finish.
        s.wake.notify() catch {};
        s.freeIfEnded();
        return .disarm;
    }

    /// Frees an ended session once no completion holds a pointer to it.
    /// Sessions still in `Server.sessions` are freed by `Server.deinit`.
    fn freeIfEnded(s: *Session) void {
        if (s.ended and s.wake_c.state() == .dead and s.grace_c.state() == .dead and s.kill_c.state() == .dead) s.destroy();
    }

    fn destroy(s: *Session) void {
        // First, since the host's thread notifies `wake` until it is joined.
        s.host.destroy();
        s.wake.deinit();
        s.grace.deinit();
        s.kill_timer.deinit();
        s.server.gpa.destroy(s);
    }
};

test {
    _ = addresses;
    // Analyzes the crypto module, whose exports the linked C code needs.
    _ = &transport.crypto.init;
}

//! txd's server: QUIC connections attached to sessions.
//!
//! A client opens one bidirectional stream and sends `Hello`, then logs in:
//! `AuthProbe` for each key it might sign with, and `AuthSignature` with
//! one the server accepts. Keys come from `authorized_keys`, for the
//! server's own user only. Once logged in, the client sends `Attach`. The
//! server answers with `HelloReply`, `AuthProbeReply` and `AuthOk`.
//!
//! Each session runs in a process of its own (see `session.process`),
//! listening on a socket in the runtime directory (see `runtime_dir`). An
//! attach starts one, or connects to one, and hands it a `Connect`
//! describing the client and the client's `Attach` or `Resume`. From then
//! on the server relays: the client's `Input` and `Resize` to the session,
//! and what the session sends, `Attached`, `Rebuild`, `Output` and `Exit`,
//! to the client. The session process outlives the server, and a new
//! server finds it in the runtime directory.
//!
//! A connection that closes leaves its session running, detached. A
//! session ends when its program exits; the attached client gets `Exit`.
//! A session process that ends without `Exit` gets the client `Error`
//! with `session_lost`.
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
const posix = std.posix;
const Ed25519 = std.crypto.sign.Ed25519;
const xev = @import("xev");
const transport = @import("transport");
const proto = @import("proto");
const session = @import("session");
const term = @import("term");
const auth = @import("auth");
const addresses = @import("addresses.zig");
pub const runtime_dir = @import("runtime_dir.zig");

const Endpoint = transport.endpoint.Endpoint;
const Conn = transport.endpoint.Conn;
const Stream = transport.endpoint.Stream;
const Channel = session.Channel;
const unix = session.unix;

const log = std.log.scoped(.server);

pub const Options = struct {
    listen: IpAddress,
    identity: Ed25519.KeyPair,
    /// The account clients log in as. No other user name is accepted.
    user: []const u8,
    /// `authorized_keys` files. The first one that exists is read, at each
    /// login attempt.
    authorized_keys: []const []const u8,
    /// Where the session processes listen. See `runtime_dir`.
    runtime_dir: []const u8,
    /// txd's executable, as an absolute path, which runs the session
    /// processes.
    session_exe: []const u8,
    /// Where the session processes log. Null is txd's stderr.
    session_log: ?posix.fd_t = null,
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
/// session's channel, and below which it resumes.
const high_water = 1 << 20;
const low_water = 256 << 10;

/// How long the sessions have to answer a `List`.
const query_timeout_ms = 1000;

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
    /// No session started by this server has an ID below it.
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

    /// The server must not move while the loop runs. Ignores SIGPIPE: a
    /// session process that ends would otherwise end txd at the next write
    /// to it.
    pub fn init(self: *Server, gpa: Allocator, io: Io, loop: *xev.Loop, options: Options) !void {
        unix.ignoreSigpipe();
        try runtime_dir.prepare(io, options.runtime_dir);
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

    /// Closes every connection. The sessions keep running, detached. Run
    /// the loop until it has no active completions, then call `deinit`.
    pub fn stop(self: *Server) void {
        self.stopping = true;
        for (self.endpoints.items) |e| e.stop();
        if (self.rescan) |*r| if (r.c.state() == .active) {
            r.cancel_c = .{ .op = .{ .cancel = .{ .c = &r.c } } };
            self.loop.add(&r.cancel_c);
        };
    }

    pub fn deinit(self: *Server) void {
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
        const client = Client.of(stream.conn) orelse return stream.consume(bytes.len);
        if (client.stream != stream) return stream.consume(bytes.len);

        // Credit is returned at once while the session's channel keeps up,
        // and once it drains otherwise.
        if (client.upstream != null and client.upstream.?.congested()) {
            client.held += bytes.len;
        } else stream.consume(bytes.len);

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

    /// The client's stream drained. Read the session's channel again once
    /// it is below `low_water`.
    fn onAcked(_: ?*anyopaque, stream: *Stream) void {
        const client = Client.of(stream.conn) orelse return;
        const u = client.upstream orelse return;
        if (u.paused and stream.buffered() <= low_water) u.resumeReading();
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

    /// The socket of session `id`, in `buf`.
    fn socketPath(self: *const Server, buf: []u8, id: u64) error{NameTooLong}![]const u8 {
        return runtime_dir.socketPath(buf, self.options.runtime_dir, id);
    }

    /// Connects to session `id`. Null if there is no such session; the
    /// socket of a process that ended is removed.
    fn connectSession(self: *Server, id: u64) ?posix.fd_t {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = self.socketPath(&buf, id) catch return null;
        return unix.connect(path) catch |err| {
            switch (err) {
                error.ConnectionRefused => runtime_dir.remove(self.options.runtime_dir, id),
                error.FileNotFound => {},
                else => log.warn("can't reach session {d}: {t}", .{ id, err }),
            }
            return null;
        };
    }

    /// The sessions in the runtime directory, in order of ID. Owned by the
    /// caller.
    fn sessionIds(self: *Server) ![]u64 {
        return runtime_dir.ids(self.gpa, self.io, self.options.runtime_dir);
    }

    /// An ID no session in the runtime directory has, above those this
    /// server started.
    fn newId(self: *Server) !u64 {
        const ids = try self.sessionIds();
        defer self.gpa.free(ids);
        if (ids.len > 0) self.next_id = @max(self.next_id, ids[ids.len - 1] + 1);
        const id = self.next_id;
        self.next_id += 1;
        return id;
    }

    /// Starts a session process for the client that said `hello`, and
    /// returns the channel to it, with `Start` sent.
    fn startSession(self: *Server, hello: *const Hello, handler: session.channel.Handler) !*Channel {
        const id = try self.newId();
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // The server's environment, plus what describes the client's
        // terminal and the session's ID.
        var environ = try self.options.environ.clone(arena);
        try environ.put("TERM", hello.term.items);
        if (hello.colorterm.items.len > 0) try environ.put("COLORTERM", hello.colorterm.items);
        try environ.put("TX_SESSION_ID", try std.fmt.allocPrint(arena, "{d}", .{id}));

        // Lists of NUL-terminated items.
        var environ_list: std.ArrayList(u8) = .empty;
        var it = environ.iterator();
        while (it.next()) |entry| try environ_list.print(arena, "{s}={s}\x00", .{ entry.key_ptr.*, entry.value_ptr.* });
        var argv_list: std.ArrayList(u8) = .empty;
        for (self.options.argv) |arg| try argv_list.print(arena, "{s}\x00", .{arg});

        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const socket_path = try self.socketPath(&path_buf, id);

        const fds = try unix.pair();
        defer unix.close(fds[1]);
        errdefer unix.close(fds[0]);
        try session.spawn.spawn(self.gpa, self.options.session_exe, fds[1], self.options.session_log);

        const ch = try Channel.create(self.gpa, self.loop, fds[0], handler);
        const t = self.options.terminal;
        ch.send(.{ .start = .{
            .session_id = id,
            .socket_path = socket_path,
            .argv = argv_list.items,
            .program = self.options.program,
            .cwd = switch (self.options.cwd) {
                .path => |path| path,
                else => null,
            },
            .environ = environ_list.items,
            .cols = hello.size.cols,
            .rows = hello.size.rows,
            .cell_width_px = if (hello.size.cell_size_px) |cell| cell.width else null,
            .cell_height_px = if (hello.size.cell_size_px) |cell| cell.height else null,
            .max_scrollback_bytes = t.max_scrollback_bytes,
            .max_scrollback_lines = t.max_scrollback_lines,
            .kitty_image_storage_limit = t.kitty_image_storage_limit,
            .log_capacity = t.log_capacity,
            .internal_revision = proto.internal_revision,
        } });
        log.info("started session {d}", .{id});
        return ch;
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
    /// The channel to the session the client attached to, or is attaching
    /// to.
    upstream: ?*Channel = null,
    /// From the session's `Attached`.
    session_id: ?u64 = null,
    /// A `List`, or an `Attach` with `reuse`, waiting for the sessions'
    /// answers.
    query: ?*Query = null,
    /// Stream bytes not yet consumed. The client's input waits while the
    /// session's channel is congested.
    held: usize = 0,
    /// The highest seq the client reported written to its terminal.
    acked: ?u64 = null,

    fn of(conn: *Conn) ?*Client {
        return @ptrCast(@alignCast(conn.context orelse return null));
    }

    fn destroy(client: *Client) void {
        const gpa = client.server.gpa;
        // The session sees its channel close, and detaches.
        if (client.upstream) |u| u.close();
        if (client.query) |q| q.abandon();
        client.decoder.deinit();
        if (client.hello) |*h| h.deinit(gpa);
        gpa.destroy(client);
    }

    /// Hello, then the login, then Attach, then Input, Resize, Ack and
    /// Detach. Unknown message types are ignored, for newer clients. txd's
    /// own messages are refused.
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
            .list => client.startQuery(.list),
            .kill => |m| client.onKill(m),
            .input, .resize => if (client.upstream) |u| u.send(message),
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
        client.completeLogin();
        client.send(.{ .auth_ok = .{} });
    }

    fn completeLogin(client: *Client) void {
        client.logged_in = true;
        client.conn.admit();
        client.decoder.max_body_len = max_message;
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
        if (client.hello == null) return client.fail(.protocol, "attach before hello");
        if (client.upstream != null or client.query != null) return client.fail(.protocol, "second attach");

        // An ID reattaches, and so does `reuse` with one detached session,
        // once the sessions have answered. Otherwise a new session starts,
        // and its output goes to the client from the first record.
        if (m.session_id) |id| {
            const fd = client.server.connectSession(id) orelse return client.fail(.no_session, "no such session");
            return client.connectTo(fd, null, .{ .attach = m });
        }
        if (m.reuse) return client.startQuery(.reuse);
        client.startNew();
    }

    fn startNew(client: *Client) void {
        const ch = client.server.startSession(&client.hello.?, client.upstreamHandler()) catch |err| {
            log.warn("starting a session failed: {t}", .{err});
            return client.fail(.spawn, "can't start the session");
        };
        client.upstream = ch;
        client.sendConnect(null, .{ .attach = .{} });
    }

    /// Logs in with a proof of the session's resume key, which the session
    /// checks.
    fn onResume(client: *Client, m: proto.Resume) void {
        if (!client.startLoginAttempt()) return;
        if (client.upstream != null) return client.fail(.protocol, "second attach");

        // A session that doesn't exist and a proof that doesn't match get
        // the same answer.
        const fd = client.server.connectSession(m.session_id) orelse return client.fail(.auth, "can't resume the session");
        var exporter: [auth.resume_.exporter_len]u8 = undefined;
        client.conn.quic.exportSecret(&exporter, auth.resume_.exporter_label);
        client.connectTo(fd, &exporter, .{ .@"resume" = m });
    }

    /// Hands the client to the session on `fd`, with `first`. The session
    /// answers on the channel.
    fn connectTo(client: *Client, fd: posix.fd_t, resume_exporter: ?[]const u8, first: session.session.First) void {
        client.upstream = Channel.create(client.server.gpa, client.server.loop, fd, client.upstreamHandler()) catch {
            unix.close(fd);
            return client.fail(.protocol, "out of memory");
        };
        client.sendConnect(resume_exporter, first);
    }

    fn sendConnect(client: *Client, resume_exporter: ?[]const u8, first: session.session.First) void {
        const u = client.upstream.?;
        const hello = &client.hello.?;
        var remote_buf: [64]u8 = undefined;
        const remote = std.fmt.bufPrint(&remote_buf, "{f}", .{client.conn.remote}) catch "";
        u.send(.{ .connect = .{
            .remote = remote,
            .cols = hello.size.cols,
            .rows = hello.size.rows,
            .cell_width_px = if (hello.size.cell_size_px) |c| c.width else null,
            .cell_height_px = if (hello.size.cell_size_px) |c| c.height else null,
            .resume_exporter = resume_exporter,
            .internal_revision = proto.internal_revision,
        } });
        u.send(switch (first) {
            .attach => |m| .{ .attach = m },
            .@"resume" => |m| .{ .@"resume" = m },
        });
    }

    fn onKill(client: *Client, m: proto.Kill) void {
        const fd = client.server.connectSession(m.session_id) orelse return client.fail(.no_session, "no such session");
        // The session's answer isn't needed: it ends.
        const ch = Channel.create(client.server.gpa, client.server.loop, fd, ignored_handler) catch {
            unix.close(fd);
            return client.fail(.protocol, "out of memory");
        };
        ch.send(.{ .kill = .{ .session_id = m.session_id } });
        ch.finish();
        log.info("{f} killed session {d}", .{ client.conn.remote, m.session_id });
        client.send(.{ .killed = .{ .session_id = m.session_id } });
    }

    const ignored_handler: session.channel.Handler = .{
        .context = undefined,
        .received = struct {
            fn f(_: *anyopaque, _: *Channel, _: proto.Decoder.Raw) void {}
        }.f,
        .closed = struct {
            fn f(_: *anyopaque, _: *Channel) void {}
        }.f,
    };

    fn startQuery(client: *Client, purpose: Query.Purpose) void {
        if (client.query != null) return client.fail(.protocol, "a list is in progress");
        const q = Query.start(client, purpose) catch |err| {
            log.warn("listing the sessions failed: {t}", .{err});
            return client.fail(.protocol, "can't list the sessions");
        };
        // With no session to ask, this reports at once.
        client.query = q;
        q.reportIfDone();
    }

    /// The sessions answered `List`, in order of ID.
    fn onQueryDone(client: *Client, q: *Query) void {
        client.query = null;
        switch (q.purpose) {
            .list => {
                for (q.answers.items) |a| if (a.reply) |reply| client.forward(reply);
                client.send(.{ .list_end = .{} });
            },
            .reuse => client.reuseDetached(q),
        }
    }

    /// Attaches the detached session if there is exactly one, and starts
    /// one if there is none. With several, sends `Error` naming them.
    fn reuseDetached(client: *Client, q: *const Query) void {
        var found: ?u64 = null;
        var count: usize = 0;
        var buf: [256]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        w.writeAll("sessions") catch {};
        for (q.answers.items) |a| {
            const info = a.info() orelse continue;
            if (info.attached_from != null) continue;
            found = a.id;
            count += 1;
            // A message too long for the buffer is cut short.
            w.print("{s} {d}", .{ if (count > 1) "," else "", a.id }) catch {};
        }

        if (count > 1) {
            w.writeAll(" are detached") catch {};
            return client.fail(.several_detached, w.buffered());
        }
        const id = found orelse return client.startNew();
        const fd = client.server.connectSession(id) orelse return client.startNew();
        client.connectTo(fd, null, .{ .attach = .{} });
    }

    fn upstreamHandler(client: *Client) session.channel.Handler {
        return .{ .context = client, .received = onUpstream, .drained = onUpstreamDrained, .closed = onUpstreamClosed };
    }

    fn fromContext(context: *anyopaque) *Client {
        return @ptrCast(@alignCast(context));
    }

    /// A message from the session, forwarded as it is. `Started` is the
    /// server's alone.
    fn onUpstream(context: *anyopaque, u: *Channel, raw: proto.Decoder.Raw) void {
        const client = fromContext(context);
        switch (raw.type_id) {
            proto.messages.Started.type_id => return,
            proto.Attached.type_id => {
                const m = proto.Attached.decode(raw.body) catch return client.fail(.protocol, "malformed message from the session");
                client.session_id = m.session_id;
                // A resume's login completes when the session accepts its
                // proof.
                if (!client.logged_in) client.completeLogin();
            },
            else => {},
        }
        client.forward(raw.bytes);

        // Nothing follows `Exit` or `Error`. The client leaves once it has
        // read it.
        if (raw.type_id == proto.Exit.type_id or raw.type_id == proto.Error.type_id) {
            client.upstream = null;
            u.close();
            if (client.stream) |stream| stream.finish();
            return;
        }

        // The stream copies what it's given. A client that doesn't take it
        // would grow it without bound. The session stops when its channel
        // backs up.
        if (client.stream) |stream| if (stream.buffered() > high_water) u.pauseReading();
    }

    /// The session's channel has room. The client may send more input.
    fn onUpstreamDrained(context: *anyopaque, _: *Channel) void {
        const client = fromContext(context);
        const stream = client.stream orelse return;
        stream.consume(client.held);
        client.held = 0;
    }

    /// The session's process ended before the program did.
    fn onUpstreamClosed(context: *anyopaque, _: *Channel) void {
        const client = fromContext(context);
        client.upstream = null;
        if (client.session_id) |id| log.info("session {d}'s process ended before its program", .{id});
        client.fail(.session_lost, "the session's process ended");
    }

    /// Writes encoded messages to the stream, which copies them. A failure
    /// closes the connection.
    fn forward(client: *Client, bytes: []const u8) void {
        const stream = client.stream orelse return;
        // Nothing follows `Error` or `Exit`.
        if (stream.fin) return;
        stream.write(bytes) catch client.conn.close(0);
    }

    /// Encodes `message` onto the stream, which copies it. A failure closes
    /// the connection.
    fn send(client: *Client, message: proto.Message) void {
        const stream = client.stream orelse return;
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

/// A `List` sent to every session, and their answers. Sessions that don't
/// answer within `query_timeout_ms` are left out. The query frees itself
/// once its timer has ended.
const Query = struct {
    server: *Server,
    /// Null once the client has gone.
    client: ?*Client,
    purpose: Purpose,
    /// One for each session, in order of ID.
    answers: std.ArrayList(Answer) = .empty,
    /// Answers still to come.
    waiting: usize = 0,
    reported: bool = false,
    timer: xev.Timer,
    timer_c: xev.Completion = .{},
    cancel_c: xev.Completion = .{},

    const Purpose = enum { list, reuse };

    const Answer = struct {
        query: *Query,
        id: u64,
        /// Null once answered.
        channel: ?*Channel,
        /// The `SessionInfo`, as the session sent it, and where its body
        /// starts.
        reply: ?[]u8 = null,
        body_start: usize = 0,

        fn info(a: *const Answer) ?proto.SessionInfo {
            const reply = a.reply orelse return null;
            return proto.SessionInfo.decode(reply[a.body_start..]) catch null;
        }
    };

    /// Asks the sessions. Call `reportIfDone` next.
    fn start(client: *Client, purpose: Purpose) !*Query {
        const server = client.server;
        const ids = try server.sessionIds();
        defer server.gpa.free(ids);

        const q = try server.gpa.create(Query);
        q.* = .{ .server = server, .client = client, .purpose = purpose, .timer = try .init() };
        // `Answer`s point to their query, so the list doesn't grow after.
        try q.answers.ensureTotalCapacity(server.gpa, ids.len);
        for (ids) |id| {
            const fd = server.connectSession(id) orelse continue;
            q.answers.appendAssumeCapacity(.{ .query = q, .id = id, .channel = null });
            const a = &q.answers.items[q.answers.items.len - 1];
            a.channel = Channel.create(server.gpa, server.loop, fd, .{ .context = a, .received = onReceived, .closed = onClosed }) catch {
                unix.close(fd);
                _ = q.answers.pop();
                continue;
            };
            a.channel.?.send(.{ .list = .{} });
            q.waiting += 1;
        }

        q.timer.run(server.loop, &q.timer_c, query_timeout_ms, Query, q, onTimer);
        return q;
    }

    fn of(context: *anyopaque) *Answer {
        return @ptrCast(@alignCast(context));
    }

    fn onReceived(context: *anyopaque, ch: *Channel, raw: proto.Decoder.Raw) void {
        const a = of(context);
        if (raw.type_id == proto.SessionInfo.type_id) {
            a.reply = a.query.server.gpa.dupe(u8, raw.bytes) catch null;
            a.body_start = raw.bytes.len - raw.body.len;
        }
        a.channel = null;
        ch.close();
        a.query.answered();
    }

    fn onClosed(context: *anyopaque, _: *Channel) void {
        const a = of(context);
        a.channel = null;
        a.query.answered();
    }

    fn answered(q: *Query) void {
        q.waiting -= 1;
        q.reportIfDone();
    }

    fn reportIfDone(q: *Query) void {
        if (q.waiting > 0 or q.reported) return;
        q.report();
        // The timer's callback frees the query.
        q.timer.cancel(q.server.loop, &q.timer_c, &q.cancel_c, Query, q, onCanceled);
    }

    /// Hands the answers to the client, and closes the channels of the
    /// sessions that haven't answered.
    fn report(q: *Query) void {
        q.reported = true;
        for (q.answers.items) |*a| if (a.channel) |ch| {
            a.channel = null;
            ch.close();
        };
        if (q.client) |client| client.onQueryDone(q);
    }

    /// The client went away.
    fn abandon(q: *Query) void {
        q.client = null;
        if (!q.reported) q.report();
    }

    fn onTimer(q_: ?*Query, _: *xev.Loop, _: *xev.Completion, _: xev.Timer.RunError!void) xev.CallbackAction {
        const q = q_.?;
        if (!q.reported) q.report();
        if (q.cancel_c.state() == .dead) q.destroy();
        return .disarm;
    }

    fn onCanceled(q_: ?*Query, _: *xev.Loop, _: *xev.Completion, _: xev.Timer.CancelError!void) xev.CallbackAction {
        const q = q_.?;
        if (q.timer_c.state() == .dead) q.destroy();
        return .disarm;
    }

    fn destroy(q: *Query) void {
        const gpa = q.server.gpa;
        for (q.answers.items) |a| if (a.reply) |reply| gpa.free(reply);
        q.answers.deinit(gpa);
        q.timer.deinit();
        gpa.destroy(q);
    }
};

test {
    _ = addresses;
    // Analyzes the crypto module, whose exports the linked C code needs.
    _ = &transport.crypto.init;
}

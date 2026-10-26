//! tx-session's server: QUIC connections attached to sessions.
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
//! Revision 0 replays a session's log from seq 0 on attach, so a session
//! whose log has been trimmed can't be reattached yet.
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
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
};

/// Error codes sent in `proto.Error`.
pub const ErrorCode = enum(u32) {
    protocol = 1,
    revision = 2,
    no_session = 3,
    log_trimmed = 4,
    spawn = 5,
    /// The login failed. The message doesn't say why.
    auth = 6,
};

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

pub const Server = struct {
    gpa: Allocator,
    io: Io,
    loop: *xev.Loop,
    options: Options,
    tls: transport.quic.Server,
    endpoint: Endpoint,
    sessions: std.AutoArrayHashMapUnmanaged(u64, *Session) = .empty,
    next_id: u64 = 1,

    /// The server must not move while the loop runs.
    pub fn init(self: *Server, gpa: Allocator, io: Io, loop: *xev.Loop, options: Options) !void {
        self.* = .{
            .gpa = gpa,
            .io = io,
            .loop = loop,
            .options = options,
            .tls = try .init(options.identity),
            .endpoint = undefined,
        };
        errdefer self.tls.deinit();
        try self.endpoint.init(gpa, io, loop, .{
            .local = options.listen,
            .role = .{ .server = &self.tls },
            .idle_timeout_ns = options.idle_timeout_ns,
            .handler = .{
                .ctx = self,
                .connected = onConnected,
                .streamOpened = onStreamOpened,
                .data = onData,
                .acked = onAcked,
                .streamClosed = onStreamClosed,
                .closed = onClosed,
            },
        });
    }

    /// The bound address, with the port the kernel picked.
    pub fn address(self: *const Server) IpAddress {
        return self.endpoint.local;
    }

    /// Closes every connection and sends every session's program SIGHUP.
    /// Run the loop until it has no active completions, which takes at most
    /// `stop_grace_ms`, then call `deinit`. It kills programs still running.
    pub fn stop(self: *Server) void {
        self.endpoint.stop();
        for (self.sessions.values()) |s| s.stop();
    }

    pub fn deinit(self: *Server) void {
        for (self.sessions.values()) |s| s.destroy();
        self.sessions.deinit(self.gpa);
        self.endpoint.deinit();
        self.tls.deinit();
        self.* = undefined;
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

    /// Whether `key_blob` may log in as `user`.
    fn accepts(self: *Server, user: []const u8, key_blob: []const u8) bool {
        if (!std.mem.eql(u8, user, self.options.user)) return false;

        // Only Ed25519 keys for now.
        const key = auth.ssh.parseKeyBlob(key_blob) catch return false;

        const match = auth.authorized_keys.check(self.io, self.gpa, self.options.authorized_keys, key) catch |err| {
            log.warn("reading authorized_keys failed: {t}", .{err});
            return false;
        };
        return switch (match) {
            .allowed => true,
            .absent => false,
            .restricted => {
                log.info("refused key {s}: its authorized_keys line has options, which tx doesn't implement yet", .{auth.Fingerprint.init(key).slice()});
                return false;
            },
        };
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

        // The host's thread can notify as soon as it starts. `wake` has to
        // exist first.
        s.* = .{ .server = self, .id = self.next_id, .host = undefined, .wake = wake, .grace = grace };
        s.host = try Host.create(self.gpa, self.io, .{
            .argv = self.options.argv,
            .program = self.options.program,
            .environ = &environ,
            .cwd = self.options.cwd,
            .size = hello.size,
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
            .hello, .auth_probe, .auth_signature, .detach, .unknown => {},
            else => return client.fail(.protocol, "not logged in"),
        };

        switch (message) {
            .hello => |m| client.onHello(m),
            .auth_probe => |m| client.onAuthProbe(m),
            .auth_signature => |m| client.onAuthSignature(m),
            .attach => |m| client.onAttach(m),
            .input => |m| if (client.session) |s| s.input(m.bytes),
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
        const key = auth.ssh.parseKeyBlob(m.key) catch unreachable;

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

        transcript.verify(key, m.signature) catch {
            log.info("bad signature from {f} for {s} with key {s}", .{ client.conn.remote, m.user, auth.Fingerprint.init(key).slice() });
            return client.fail(.auth, "login refused");
        };

        log.info("{f} logged in as {s} with key {s}", .{ client.conn.remote, m.user, auth.Fingerprint.init(key).slice() });
        client.logged_in = true;
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

        // An ID reattaches. Without one, a new session starts.
        const server = client.server;
        const s = if (m.session_id) |id|
            server.sessions.get(id) orelse return client.fail(.no_session, "no such session")
        else
            server.startSession(hello) catch |err| {
                log.warn("starting a session failed: {t}", .{err});
                return client.fail(.spawn, "can't start the session");
            };

        // The client rebuilds the screen by replaying the log from seq 0.
        if (s.host.primary.log.firstSeq() != 0) return client.fail(.log_trimmed, "the session's output is no longer in its log");

        // One client at a time: the newer attach wins.
        if (s.client) |other| other.conn.close(0);

        s.attach(client);
        client.send(.{ .attached = .{ .session_id = s.id } });
        s.pump();

        // The replay is the output as the program wrote it at the old size.
        // Resizing afterwards makes the program redraw at the client's.
        const t = &s.host.primary.terminal;
        if (t.cols != hello.size.cols or t.rows != hello.size.rows) s.resize(hello.size);
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
    /// The program exited and the session left `Server.sessions`.
    ended: bool = false,

    fn attach(s: *Session, client: *Client) void {
        s.client = client;
        client.session = s;

        // Replay from the start of the log.
        s.next_seq = 0;

        // The client's terminal answers queries now.
        s.host.answer_queries = false;
    }

    fn detach(s: *Session) void {
        if (s.client) |client| client.session = null;
        s.client = null;
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

    /// Sends the client the log records it hasn't seen. Resize records are
    /// skipped: the client's terminal is already at the size it asked for.
    fn pump(s: *Session) void {
        const client = s.client orelse return;
        const stream = client.stream orelse return;
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
        if (s.ended and s.wake_c.state() == .dead and s.grace_c.state() == .dead) s.destroy();
    }

    fn destroy(s: *Session) void {
        // First, since the host's thread notifies `wake` until it is joined.
        s.host.destroy();
        s.wake.deinit();
        s.grace.deinit();
        s.server.gpa.destroy(s);
    }
};

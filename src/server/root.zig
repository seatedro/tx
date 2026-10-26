//! tx-session's server: QUIC connections attached to sessions.
//!
//! A client opens one bidirectional stream and sends `Hello`, then `Attach`.
//! The server answers with `HelloReply` and `Attached`, then streams the
//! session's output records and applies the client's `Input` and `Resize`.
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

const Endpoint = transport.endpoint.Endpoint;
const Conn = transport.endpoint.Conn;
const Stream = transport.endpoint.Stream;
const Host = session.Host;

const log = std.log.scoped(.server);

pub const Options = struct {
    listen: IpAddress,
    identity: Ed25519.KeyPair,
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
};

/// Output buffered on a stream above which the server stops reading the
/// program's output, and below which it resumes.
const high_water = 1 << 20;
const low_water = 256 << 10;

/// The longest message body accepted from a client.
const max_message = 1 << 20;

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

    fn onConnected(ctx: ?*anyopaque, conn: *Conn) void {
        const self = fromCtx(ctx);
        const client = self.gpa.create(Client) catch return conn.close(0);
        client.* = .{ .server = self, .conn = conn, .decoder = .init(self.gpa, max_message) };
        conn.context = client;
    }

    fn onStreamOpened(_: ?*anyopaque, stream: *Stream) void {
        const client = Client.of(stream.conn) orelse return stream.reset(0);
        if (client.stream != null) return stream.reset(0);
        client.stream = stream;
        stream.context = client;
    }

    fn onData(_: ?*anyopaque, stream: *Stream, bytes: []const u8, fin: bool) void {
        stream.consume(bytes.len);
        const client = Client.of(stream.conn) orelse return;
        if (client.stream != stream) return;
        client.decoder.feed(bytes);
        while (true) {
            const message = client.decoder.next() catch return client.fail(.protocol, "malformed message");
            client.handle(message orelse break);
            // `handle` may have closed the connection.
            if (stream.conn.closing != null) return;
        }
        if (fin) stream.conn.close(0);
    }

    fn onAcked(_: ?*anyopaque, stream: *Stream) void {
        const client = Client.of(stream.conn) orelse return;
        const s = client.session orelse return;
        if (s.paused and stream.buffered() <= low_water) s.resume_();
    }

    fn onStreamClosed(_: ?*anyopaque, stream: *Stream) void {
        const client = Client.of(stream.conn) orelse return;
        if (client.stream == stream) client.stream = null;
    }

    fn onClosed(_: ?*anyopaque, conn: *Conn, _: transport.endpoint.CloseReason) void {
        const client = Client.of(conn) orelse return;
        client.destroy();
        conn.context = null;
    }

    fn startSession(self: *Server, hello: *const Hello) !*Session {
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
        // The host's thread can notify as soon as it starts, so `wake` is
        // set up first.
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

    fn handle(client: *Client, message: proto.Message) void {
        switch (message) {
            .hello => |m| client.onHello(m),
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
        const gpa = client.server.gpa;
        var hello: Hello = .{ .size = boundedSize(m.cols, m.rows, cellSize(m.cell_width_px, m.cell_height_px)) orelse
            .{ .cols = 80, .rows = 24 } };
        hello.term.appendSlice(gpa, m.term) catch return client.fail(.protocol, "out of memory");
        hello.colorterm.appendSlice(gpa, m.colorterm orelse "") catch return client.fail(.protocol, "out of memory");
        client.hello = hello;
        client.send(.{ .hello_reply = .{ .revision = proto.revision } });
    }

    fn onAttach(client: *Client, m: proto.Attach) void {
        const hello = &(client.hello orelse return client.fail(.protocol, "attach before hello"));
        if (client.session != null) return client.fail(.protocol, "second attach");
        const server = client.server;
        const s = if (m.session_id) |id|
            server.sessions.get(id) orelse return client.fail(.no_session, "no such session")
        else
            server.startSession(hello) catch |err| {
                log.warn("starting a session failed: {t}", .{err});
                return client.fail(.spawn, "can't start the session");
            };
        if (s.host.primary.log.firstSeq() != 0) return client.fail(.log_trimmed, "the session's output is no longer in its log");
        // One client at a time: the newer attach wins.
        if (s.client) |other| other.conn.close(0);
        s.attach(client);
        client.send(.{ .attached = .{ .session_id = s.id } });
        s.pump();
        const t = &s.host.primary.terminal;
        if (t.cols != hello.size.cols or t.rows != hello.size.rows) s.resize(hello.size);
    }

    fn send(client: *Client, message: proto.Message) void {
        const stream = client.stream orelse return;
        const gpa = client.server.gpa;
        const buf = gpa.alloc(u8, proto.encodedLen(message)) catch return client.conn.close(0);
        defer gpa.free(buf);
        var w: Io.Writer = .fixed(buf);
        proto.encode(&w, message) catch unreachable;
        stream.write(buf) catch client.conn.close(0);
    }

    fn fail(client: *Client, code: ErrorCode, message: []const u8) void {
        client.send(.{ .@"error" = .{ .code = @backingInt(code), .message = message } });
        if (client.stream) |stream| stream.finish();
    }
};

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
        s.next_seq = 0;
        s.host.answer_queries = false;
    }

    fn detach(s: *Session) void {
        if (s.client) |client| client.session = null;
        s.client = null;
        s.host.answer_queries = true;
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
        if (stream.buffered() > high_water) s.paused = true;
    }

    fn resume_(s: *Session) void {
        if (!s.paused) return;
        s.paused = false;
        s.process();
    }

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
        if (!s.grace_over) s.process();
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
        _ = s.server.sessions.swapRemove(s.id);
        s.ended = true;
        s.wake.notify() catch {};
    }

    /// Sends the program SIGHUP. A program that exits within the grace
    /// period ends its session as usual.
    fn stop(s: *Session) void {
        if (s.ended) return;
        s.host.pty.kill(.HUP) catch {};
        s.grace.run(s.server.loop, &s.grace_c, stop_grace_ms, Session, s, onGraceOver);
    }

    fn onGraceOver(s_: ?*Session, _: *xev.Loop, _: *xev.Completion, _: xev.Timer.RunError!void) xev.CallbackAction {
        const s = s_.?;
        s.grace_over = true;
        // Ends the `wake` wait, so the loop can finish.
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
        s.host.destroy();
        s.wake.deinit();
        s.grace.deinit();
        s.server.gpa.destroy(s);
    }
};

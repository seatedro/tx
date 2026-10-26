//! tx-session and tx end to end in one process. The server and each client
//! run on their own thread and loop. A pseudo-terminal pair stands in for
//! the user's terminal: the client uses the slave, and the test types into
//! and reads from the master.
const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const Io = std.Io;
const posix = std.posix;
const c = std.c;
const Ed25519 = std.crypto.sign.Ed25519;
const xev = @import("xev");
const transport = @import("transport");
const server_pkg = @import("server");
const client = @import("client");
const term = @import("term");
const proto = @import("proto");

const gpa = testing.allocator;
const timeout_ms = 10_000;

fn nowMs() i64 {
    return Io.Clock.awake.now(testing.io).toMilliseconds();
}

/// The server's loop on a thread. io_uring cancels a thread's pending
/// requests when the thread exits, so the thread lives as long as the
/// server, and the test runs code on it through `call`.
const ServerThread = struct {
    loop: xev.Loop,
    server: server_pkg.Server,
    wake: xev.Async,
    wake_c: xev.Completion = .{},
    thread: std.Thread = undefined,
    pending: std.atomic.Value(?*Request) = .init(null),
    stopping: bool = false,

    const Request = struct {
        run: *const fn (req: *Request, st: *ServerThread) void,
        done: std.atomic.Value(bool) = .init(false),
    };

    fn init(st: *ServerThread, options: server_pkg.Options) !void {
        st.* = .{ .loop = try .init(.{}), .server = undefined, .wake = try .init() };
        try st.server.init(gpa, testing.io, &st.loop, options);
        st.wake.wait(&st.loop, &st.wake_c, ServerThread, st, onWake);
        st.thread = try std.Thread.spawn(.{}, run, .{st});
    }

    fn run(st: *ServerThread) void {
        st.loop.run(.until_done) catch |err| std.debug.panic("server loop: {t}", .{err});
    }

    fn onWake(st_: ?*ServerThread, _: *xev.Loop, _: *xev.Completion, _: xev.Async.WaitError!void) xev.CallbackAction {
        const st = st_.?;
        if (st.pending.swap(null, .acq_rel)) |req| {
            req.run(req, st);
            req.done.store(true, .release);
        }
        return if (st.stopping) .disarm else .rearm;
    }

    /// Runs `req` on the server thread and waits for it.
    fn call(st: *ServerThread, req: *Request) void {
        st.pending.store(req, .release);
        st.wake.notify() catch {};
        while (!req.done.load(.acquire)) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    }

    fn deinit(st: *ServerThread) void {
        var req: Request = .{ .run = stop };
        st.call(&req);
        st.thread.join();
        st.server.deinit();
        st.wake.deinit();
        st.loop.deinit();
    }

    fn stop(_: *Request, st: *ServerThread) void {
        st.stopping = true;
        st.server.stop();
    }
};

/// The state dump of a session's primary terminal, taken on the server
/// thread. Null once the session has ended.
fn primaryDump(st: *ServerThread, session_id: u64) !?[]u8 {
    const Dump = struct {
        req: ServerThread.Request = .{ .run = run },
        session_id: u64,
        result: anyerror!?[]u8 = null,

        fn run(req: *ServerThread.Request, server_thread: *ServerThread) void {
            const d: *@This() = @fieldParentPtr("req", req);
            const s = server_thread.server.sessions.get(d.session_id) orelse return;
            d.result = if (term.state.dumpAlloc(gpa, &s.host.primary.terminal)) |dump| dump else |err| err;
        }
    };
    var d: Dump = .{ .session_id = session_id };
    st.call(&d.req);
    return d.result;
}

/// A pseudo-terminal pair at 80x24.
const TestPty = struct {
    master: posix.fd_t,
    slave: posix.fd_t,
    output: std.ArrayList(u8) = .empty,

    extern "c" fn posix_openpt(flags: posix.O) c_int;
    extern "c" fn grantpt(fd: posix.fd_t) c_int;
    extern "c" fn unlockpt(fd: posix.fd_t) c_int;
    extern "c" fn ptsname_r(fd: posix.fd_t, buf: [*]u8, len: usize) c_int;
    extern "c" fn ioctl(fd: posix.fd_t, request: c_ulong, ...) c_int;

    fn open() !TestPty {
        const master = posix_openpt(.{ .ACCMODE = .RDWR, .NOCTTY = true });
        if (master == -1) return error.OpenPtyFailed;
        errdefer _ = c.close(master);
        if (grantpt(master) != 0 or unlockpt(master) != 0) return error.OpenPtyFailed;
        var name: [128]u8 = undefined;
        if (ptsname_r(master, &name, name.len) != 0) return error.OpenPtyFailed;
        const len = std.mem.indexOfScalar(u8, &name, 0).?;
        const slave = c.open(name[0..len :0], .{ .ACCMODE = .RDWR, .NOCTTY = true });
        if (slave == -1) return error.OpenPtyFailed;
        var ws: posix.winsize = .{ .row = 24, .col = 80, .xpixel = 0, .ypixel = 0 };
        // std.c has no TIOCSWINSZ for macOS.
        const tiocswinsz: c_ulong = if (builtin.os.tag.isDarwin()) 0x80087467 else c.T.IOCSWINSZ;
        _ = ioctl(master, tiocswinsz, @intFromPtr(&ws));
        return .{ .master = master, .slave = slave };
    }

    fn close(p: *TestPty) void {
        _ = c.close(p.master);
        _ = c.close(p.slave);
        p.output.deinit(gpa);
    }

    fn type_(p: *TestPty, bytes: []const u8) !void {
        if (c.write(p.master, bytes.ptr, bytes.len) != bytes.len) return error.WriteFailed;
    }

    /// Reads what the client wrote to its terminal until it contains
    /// `needle`.
    fn readUntil(p: *TestPty, needle: []const u8) !void {
        const deadline = nowMs() + timeout_ms;
        while (std.mem.indexOf(u8, p.output.items, needle) == null) {
            const remaining = deadline - nowMs();
            if (remaining <= 0) {
                std.debug.print("expected \"{f}\" in \"{f}\"\n", .{ std.zig.fmtString(needle), std.zig.fmtString(p.output.items) });
                return error.Timeout;
            }
            var fds = [_]posix.pollfd{.{ .fd = p.master, .events = posix.POLL.IN, .revents = 0 }};
            if (c.poll(&fds, 1, @intCast(remaining)) != 1) continue;
            var buf: [4096]u8 = undefined;
            const n = c.read(p.master, &buf, buf.len);
            if (n <= 0) return error.ReadFailed;
            try p.output.appendSlice(gpa, buf[0..@intCast(n)]);
        }
    }
};

/// `client.session.run` on a thread.
const ClientThread = struct {
    options: client.session.Options,
    result: ?anyerror!client.session.Outcome = null,
    thread: std.Thread = undefined,

    fn start(ct: *ClientThread) !void {
        ct.thread = try std.Thread.spawn(.{}, run, .{ct});
    }

    fn run(ct: *ClientThread) void {
        ct.result = client.session.run(gpa, testing.io, ct.options);
    }

    fn join(ct: *ClientThread) !client.session.Outcome {
        ct.thread.join();
        return ct.result.?;
    }
};

/// A terminal fed `bytes` ends in the session's primary terminal's state.
fn expectMatchesPrimary(st: *ServerThread, session_id: u64, bytes: []const u8) !void {
    const want = (try primaryDump(st, session_id)) orelse return error.NoSession;
    defer gpa.free(want);
    const stand_in: *term.Primary = try .create(gpa, testing.io, .{ .cols = 80, .rows = 24 });
    defer stand_in.destroy();
    try stand_in.output(bytes);
    const got = try term.state.dumpAlloc(gpa, &stand_in.terminal);
    defer gpa.free(got);
    try testing.expectEqualStrings(want, got);
}

test "a session runs, detaches, reattaches and exits through tx-session and tx" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    try environ.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");

    var st: ServerThread = undefined;
    try st.init(.{
        .listen = try .parseIp4("127.0.0.1", 0),
        .identity = Ed25519.KeyPair.generate(testing.io),
        .environ = &environ,
        .argv = &.{
            "/bin/sh", "-c",
            \\printf 'hello \033[1mbold\033[m\r\n'
            \\i=0; while [ $i -lt 40 ]; do printf 'line %d\r\n' $i; i=$((i + 1)); done
            \\printf 'term=%s\r\n' "$TERM"
            \\printf 'ready\r\n'
            \\read -r a
            \\printf 'got %s\r\n' "$a"
            \\read -r b
            \\exit 3
        },
    });
    defer st.deinit();
    const pinned = st.server.options.identity.public_key.toBytes();

    // A new session.
    var first: TestPty = try .open();
    defer first.close();
    var a: ClientThread = .{ .options = .{
        .server = st.server.address(),
        .pinned = pinned,
        .in_fd = first.slave,
        .out_fd = first.slave,
        .term = "xterm-256color",
    } };
    try a.start();
    try first.readUntil("ready");
    try testing.expect(std.mem.indexOf(u8, first.output.items, "term=xterm-256color") != null);
    try first.type_("abc\r");
    try first.readUntil("got abc");

    // `~.` detaches. The session keeps running.
    try first.type_("~.");
    const detached = try a.join();
    const session_id = detached.detached.?;
    try expectMatchesPrimary(&st, session_id, first.output.items);

    // Reattach from another terminal: the log is replayed into it.
    var second: TestPty = try .open();
    defer second.close();
    var b: ClientThread = .{ .options = .{
        .server = st.server.address(),
        .pinned = pinned,
        .session_id = session_id,
        .in_fd = second.slave,
        .out_fd = second.slave,
        .term = "xterm-256color",
    } };
    try b.start();
    try second.readUntil("got abc");
    try expectMatchesPrimary(&st, session_id, second.output.items);

    // The program exits; the client reports its status.
    try second.type_("q\r");
    const exited = try b.join();
    try testing.expectEqual(3, exited.exited.status);
    try testing.expectEqual(null, try primaryDump(&st, session_id));
}

test "a client pinning another key is refused" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var st: ServerThread = undefined;
    try st.init(.{
        .listen = try .parseIp4("127.0.0.1", 0),
        .identity = Ed25519.KeyPair.generate(testing.io),
        .environ = &environ,
        .argv = &.{ "/bin/sh", "-c", "sleep 10" },
    });
    defer st.deinit();

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = .{
        .server = st.server.address(),
        .pinned = Ed25519.KeyPair.generate(testing.io).public_key.toBytes(),
        .in_fd = pty.slave,
        .out_fd = pty.slave,
        .term = "xterm-256color",
    } };
    try ct.start();
    const outcome = try ct.join();
    try testing.expectEqual(transport.endpoint.CloseReason.handshake_failed, outcome.disconnected);
}

/// A client that speaks the protocol directly, for messages `tx` doesn't
/// send.
const RawClient = struct {
    loop: xev.Loop,
    tls: transport.quic.Client,
    endpoint: transport.endpoint.Endpoint,
    stream: ?*transport.endpoint.Stream = null,
    decoder: proto.Decoder,
    hello: proto.Hello,
    attached: ?u64 = null,
    output: std.ArrayList(u8) = .empty,

    fn init(rc: *RawClient, server: Io.net.IpAddress, pinned: [32]u8, hello: proto.Hello) !void {
        rc.* = .{
            .loop = try .init(.{}),
            .tls = try .init(pinned),
            .endpoint = undefined,
            .decoder = .init(gpa, 1 << 20),
            .hello = hello,
        };
        try rc.endpoint.init(gpa, testing.io, &rc.loop, .{
            .local = try .parseIp4("127.0.0.1", 0),
            .role = .{ .client = &rc.tls },
            .handler = .{ .ctx = rc, .connected = onConnected, .data = onData },
        });
        _ = try rc.endpoint.connect(server);
    }

    fn deinit(rc: *RawClient) void {
        rc.endpoint.stop();
        rc.loop.run(.until_done) catch {};
        rc.endpoint.deinit();
        rc.decoder.deinit();
        rc.output.deinit(gpa);
        rc.tls.deinit();
        rc.loop.deinit();
    }

    fn send(stream: *transport.endpoint.Stream, message: proto.Message) void {
        const buf = gpa.alloc(u8, proto.encodedLen(message)) catch @panic("OOM");
        defer gpa.free(buf);
        var w: Io.Writer = .fixed(buf);
        proto.encode(&w, message) catch unreachable;
        stream.write(buf) catch @panic("OOM");
    }

    fn onConnected(ctx: ?*anyopaque, conn: *transport.endpoint.Conn) void {
        const rc: *RawClient = @ptrCast(@alignCast(ctx.?));
        const stream = conn.openStream(.bidi) catch @panic("stream");
        rc.stream = stream;
        send(stream, .{ .hello = rc.hello });
        send(stream, .{ .attach = .{} });
    }

    fn onData(ctx: ?*anyopaque, stream: *transport.endpoint.Stream, bytes: []const u8, _: bool) void {
        const rc: *RawClient = @ptrCast(@alignCast(ctx.?));
        stream.consume(bytes.len);
        rc.decoder.feed(bytes);
        while (rc.decoder.next() catch null) |message| switch (message) {
            .attached => |m| rc.attached = m.session_id,
            .output => |m| rc.output.appendSlice(gpa, m.bytes) catch @panic("OOM"),
            else => {},
        };
    }

    fn waitAttached(rc: *RawClient) !u64 {
        const deadline = nowMs() + timeout_ms;
        while (rc.attached == null) {
            if (nowMs() > deadline) return error.Timeout;
            try rc.loop.run(.no_wait);
            testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
        return rc.attached.?;
    }

    fn waitOutput(rc: *RawClient, needle: []const u8) !void {
        const deadline = nowMs() + timeout_ms;
        while (std.mem.indexOf(u8, rc.output.items, needle) == null) {
            if (nowMs() > deadline) return error.Timeout;
            try rc.loop.run(.no_wait);
            testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }
};

/// The size of a session's primary terminal, read on the server thread.
fn primarySize(st: *ServerThread, session_id: u64) !struct { u16, u16 } {
    const Size = struct {
        req: ServerThread.Request = .{ .run = run },
        session_id: u64,
        size: ?struct { u16, u16 } = null,

        fn run(req: *ServerThread.Request, server_thread: *ServerThread) void {
            const d: *@This() = @fieldParentPtr("req", req);
            const s = server_thread.server.sessions.get(d.session_id) orelse return;
            d.size = .{ s.host.primary.terminal.cols, s.host.primary.terminal.rows };
        }
    };
    var d: Size = .{ .session_id = session_id };
    st.call(&d.req);
    return d.size orelse error.NoSession;
}

test "a server bounds the terminal size a client sends" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    try environ.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");
    var st: ServerThread = undefined;
    try st.init(.{
        .listen = try .parseIp4("127.0.0.1", 0),
        .identity = Ed25519.KeyPair.generate(testing.io),
        .environ = &environ,
        .argv = &.{ "/bin/sh", "-c", "sleep 10" },
    });
    defer st.deinit();
    const pinned = st.server.options.identity.public_key.toBytes();

    for ([_]struct { u16, u16, u16, u16 }{
        .{ 0, 0, 80, 24 },
        .{ 65535, 65535, 1024, 1024 },
    }) |case| {
        const cols, const rows, const want_cols, const want_rows = case;
        var rc: RawClient = undefined;
        try rc.init(st.server.address(), pinned, .{ .revision = proto.revision, .term = "xterm-256color", .cols = cols, .rows = rows });
        defer rc.deinit();
        const id = try rc.waitAttached();
        const got_cols, const got_rows = try primarySize(&st, id);
        try testing.expectEqual(want_cols, got_cols);
        try testing.expectEqual(want_rows, got_rows);
    }
}

fn testEnviron() !std.process.Environ.Map {
    var environ: std.process.Environ.Map = .init(gpa);
    errdefer environ.deinit();
    try environ.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");
    return environ;
}

test "input larger than the terminal's input queue reaches the program" {
    transport.crypto.init(testing.io);
    var environ = try testEnviron();
    defer environ.deinit();
    var st: ServerThread = undefined;
    try st.init(.{
        .listen = try .parseIp4("127.0.0.1", 0),
        .identity = Ed25519.KeyPair.generate(testing.io),
        .environ = &environ,
        .argv = &.{ "/bin/sh", "-c", "stty raw -echo; printf 'ready\\r\\n'; head -c 262144 | wc -c" },
    });
    defer st.deinit();

    var rc: RawClient = undefined;
    try rc.init(st.server.address(), st.server.options.identity.public_key.toBytes(), .{
        .revision = proto.revision,
        .term = "xterm-256color",
        .cols = 80,
        .rows = 24,
    });
    defer rc.deinit();
    _ = try rc.waitAttached();
    try rc.waitOutput("ready");
    const input = try gpa.alloc(u8, 262144);
    defer gpa.free(input);
    @memset(input, 'x');
    RawClient.send(rc.stream.?, .{ .input = .{ .bytes = input } });
    try rc.waitOutput("262144");
}

test "stopping the server kills a program that ignores SIGHUP" {
    transport.crypto.init(testing.io);
    var environ = try testEnviron();
    defer environ.deinit();
    var st: ServerThread = undefined;
    try st.init(.{
        .listen = try .parseIp4("127.0.0.1", 0),
        .identity = Ed25519.KeyPair.generate(testing.io),
        .environ = &environ,
        .argv = &.{ "/bin/sh", "-c", "trap '' HUP; printf 'ready\\r\\n'; while :; do sleep 1; done" },
    });

    var rc: RawClient = undefined;
    try rc.init(st.server.address(), st.server.options.identity.public_key.toBytes(), .{
        .revision = proto.revision,
        .term = "xterm-256color",
        .cols = 80,
        .rows = 24,
    });
    defer rc.deinit();
    _ = try rc.waitAttached();
    try rc.waitOutput("ready");
    const start = nowMs();
    st.deinit();
    try testing.expect(nowMs() - start < 5000);
}

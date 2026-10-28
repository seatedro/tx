//! txd and tx end to end. The server and each client run on their own
//! thread and loop in the test's process, and the sessions in txd
//! processes, which the test reaches through their sockets. A
//! pseudo-terminal pair stands in for the user's terminal: the client uses
//! the slave, and the test types into and reads from the master. Clients
//! log in with a key from a test agent, listed in an `authorized_keys` file
//! in a temporary directory.
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
const session = @import("session");
const client = @import("client");
const term = @import("term");
const proto = @import("proto");
const auth = @import("auth");
const build_options = @import("build_options");

const gpa = testing.allocator;
const timeout_ms = 10_000;

/// The account the test server accepts logins for.
const test_user = "tx-test";

/// A user key, an agent holding keys, an `authorized_keys` file listing
/// the user key, and the runtime directory of the server's sessions.
const Login = struct {
    tmp: testing.TmpDir,
    key: Ed25519.KeyPair,
    agent: auth.agent.TestAgent = undefined,
    agent_path: []u8,
    authorized_keys: []u8,
    runtime_dir: []u8,
    /// txd, from the build, as an absolute path.
    session_exe: []u8,
    /// /dev/null, for the session processes' log. The test runner would
    /// show it.
    session_log: posix.fd_t,
    /// Holds the identities `clientOptions` returns.
    identities: [4]client.session.Identity = undefined,

    /// The agent holds `agent_keys`, or the user key if null.
    fn init(l: *Login, agent_keys: ?[]const Ed25519.KeyPair) !void {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const dir = buf[0..try tmp.dir.realPath(testing.io, &buf)];

        l.* = .{
            .tmp = tmp,
            .key = .generate(testing.io),
            .agent_path = try std.fs.path.join(gpa, &.{ dir, "agent.sock" }),
            .authorized_keys = try std.fs.path.join(gpa, &.{ dir, "authorized_keys" }),
            .runtime_dir = try std.fs.path.join(gpa, &.{ dir, "run" }),
            .session_exe = try std.fs.path.resolve(gpa, &.{ try std.process.currentPathAlloc(testing.io, arena.allocator()), build_options.txd_exe }),
            .session_log = c.open("/dev/null", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }),
        };

        const line = try std.fmt.allocPrint(gpa, "ssh-ed25519 {s} test\n", .{auth.ssh.KeyText.init(l.key.public_key.toBytes()).slice()});
        defer gpa.free(line);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "authorized_keys", .data = line });

        try l.agent.start(testing.io, l.agent_path, agent_keys orelse (&l.key)[0..1]);
    }

    /// Adds `key` to the `authorized_keys` file.
    fn authorize(l: *Login, key: *const auth.ssh.PublicKey) !void {
        const old = try l.tmp.dir.readFileAlloc(testing.io, "authorized_keys", gpa, .unlimited);
        defer gpa.free(old);
        var text_buf: [std.base64.standard.Encoder.calcSize(auth.ssh.max_key_blob_len)]u8 = undefined;
        const text = std.base64.standard.Encoder.encode(&text_buf, key.blob());
        const key_type = switch (key.kind) {
            .ed25519 => auth.ssh.ed25519,
            .rsa => auth.ssh.rsa,
        };
        const new = try std.fmt.allocPrint(gpa, "{s}{s} {s}\n", .{ old, key_type, text });
        defer gpa.free(new);
        try l.tmp.dir.writeFile(testing.io, .{ .sub_path = "authorized_keys", .data = new });
    }

    /// Writes a key file into the temporary directory and returns its
    /// path, owned by the caller.
    fn writeKeyFile(l: *Login, name: []const u8, text: []const u8) ![]u8 {
        try l.tmp.dir.writeFile(testing.io, .{ .sub_path = name, .data = text });
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const dir = buf[0..try l.tmp.dir.realPath(testing.io, &buf)];
        return std.fs.path.join(gpa, &.{ dir, name });
    }

    fn deinit(l: *Login) void {
        l.agent.stop(l.agent_path);
        gpa.free(l.agent_path);
        gpa.free(l.authorized_keys);
        gpa.free(l.runtime_dir);
        gpa.free(l.session_exe);
        _ = c.close(l.session_log);
        l.tmp.cleanup();
    }

    /// Server options for a server that runs `argv`.
    fn serverOptions(l: *const Login, environ: *const std.process.Environ.Map, argv: []const []const u8) !server_pkg.Options {
        return .{
            .listen = try .parseIp4("127.0.0.1", 0),
            .identity = Ed25519.KeyPair.generate(testing.io),
            .user = test_user,
            .authorized_keys = (&l.authorized_keys)[0..1],
            .runtime_dir = l.runtime_dir,
            .session_exe = l.session_exe,
            .session_log = l.session_log,
            .environ = environ,
            .argv = argv,
        };
    }

    /// Client options for a client on `pty`, logging in with `keys` from
    /// the agent. The result points into `l`, until the next call.
    fn clientOptions(l: *Login, st: *const ServerThread, pty: *const TestPty, keys: []const auth.Key) client.session.Options {
        for (keys, 0..) |key, i| l.identities[i] = .{ .key = .fromEd25519(key), .source = .agent };
        return .{
            .servers = &st.addresses,
            .host_keys = &st.host_keys,
            .user = test_user,
            .agent = l.agent_path,
            .identities = l.identities[0..keys.len],
            .in_fd = pty.slave,
            .out_fd = pty.slave,
            .term = "xterm-256color",
        };
    }
};

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
    /// The server's public key, for clients to accept.
    host_keys: [1][32]u8 = undefined,
    /// The server's address, for clients to connect to.
    addresses: [1]Io.net.IpAddress = undefined,

    const Request = struct {
        run: *const fn (req: *Request, st: *ServerThread) void,
        done: std.atomic.Value(bool) = .init(false),
    };

    fn init(st: *ServerThread, options: server_pkg.Options) !void {
        st.* = .{ .loop = try .init(.{}), .server = undefined, .wake = try .init() };
        try st.server.init(gpa, testing.io, &st.loop, options);
        st.host_keys = .{options.identity.public_key.toBytes()};
        st.addresses = .{st.server.address()};
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

    /// Stops the server. Its sessions keep running.
    fn stopServer(st: *ServerThread) void {
        var req: Request = .{ .run = stop };
        st.call(&req);
        st.thread.join();
        st.server.deinit();
        st.wake.deinit();
        st.loop.deinit();
    }

    /// Stops the server and ends its sessions.
    fn deinit(st: *ServerThread) void {
        var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
        const dir = dir_buf[0..st.server.options.runtime_dir.len];
        @memcpy(dir, st.server.options.runtime_dir);
        st.stopServer();
        killSessions(dir) catch |err| std.debug.panic("ending the sessions: {t}", .{err});
    }

    /// A new server in place of this one, on the same address, with the
    /// same key and sessions.
    fn restart(st: *ServerThread) !void {
        var options = st.server.options;
        options.listen = st.addresses[0];
        st.stopServer();
        try st.init(options);
    }

    fn stop(_: *Request, st: *ServerThread) void {
        st.stopping = true;
        st.server.stop();
    }

    fn runtimeDir(st: *const ServerThread) []const u8 {
        return st.server.options.runtime_dir;
    }
};

/// A session process's answer, pointing into `bytes`.
const Answer = struct {
    bytes: std.ArrayList(u8) = .empty,
    message: proto.Message = undefined,

    fn deinit(a: *Answer) void {
        a.bytes.deinit(gpa);
    }
};

/// Sends `request` to session `id`'s process, through its socket, and
/// returns the answer. Null if the session is gone.
fn askSession(dir: []const u8, id: u64, request: proto.Message) !?Answer {
    const fd = (try tellSession(dir, id, request)) orelse return null;
    defer session.unix.close(fd);

    var answer: Answer = .{};
    errdefer answer.deinit();
    const deadline = nowMs() + timeout_ms;
    while (true) {
        var d: proto.Decoder = .init(gpa, 1 << 20);
        defer d.deinit();
        d.feed(answer.bytes.items);
        if (try d.next()) |m| {
            answer.message = m;
            return answer;
        }

        // The socket may be non-blocking.
        var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
        const left = deadline - nowMs();
        if (left <= 0) return error.Timeout;
        _ = c.poll(&fds, fds.len, @intCast(left));
        var buf: [64 << 10]u8 = undefined;
        const n = c.read(fd, &buf, buf.len);
        if (n == 0) return null;
        if (n < 0) continue;
        try answer.bytes.appendSlice(gpa, buf[0..@intCast(n)]);
    }
}

/// Sends `message` to session `id`'s process, and returns the socket. Null
/// if the session is gone.
fn tellSession(dir: []const u8, id: u64, message: proto.Message) !?posix.fd_t {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try server_pkg.runtime_dir.socketPath(&path_buf, dir, id);
    const fd = session.unix.connect(path) catch |err| switch (err) {
        error.FileNotFound => return null,
        // The process ended without removing its socket.
        error.ConnectionRefused => {
            server_pkg.runtime_dir.remove(dir, id);
            return null;
        },
        else => return err,
    };
    errdefer session.unix.close(fd);
    var buf: [64 << 10]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try proto.encode(&w, message);
    var rest = w.buffered();
    while (rest.len > 0) {
        const n = c.write(fd, rest.ptr, rest.len);
        if (n <= 0) return error.WriteFailed;
        rest = rest[@intCast(n)..];
    }
    return fd;
}

/// Ends every session in `dir`, and waits for their processes to exit.
fn killSessions(dir: []const u8) !void {
    const ids = try server_pkg.runtime_dir.ids(gpa, testing.io, dir);
    defer gpa.free(ids);
    for (ids) |id| if (try tellSession(dir, id, .{ .kill = .{ .session_id = id } })) |fd| session.unix.close(fd);

    // A session process removes its socket as its session ends.
    const deadline = nowMs() + timeout_ms;
    while (true) {
        const left = try server_pkg.runtime_dir.ids(gpa, testing.io, dir);
        defer gpa.free(left);
        if (left.len == 0) return;
        if (nowMs() > deadline) return error.Timeout;
        try testing.io.sleep(.fromMilliseconds(10), .awake);
    }
}

/// Session `id`'s `DumpReply`. Null once the session has ended.
fn dumpSession(st: *const ServerThread, id: u64) !?Answer {
    var answer = (try askSession(st.runtimeDir(), id, .{ .dump = .{} })) orelse return null;
    if (answer.message != .dump_reply) {
        answer.deinit();
        return error.UnexpectedAnswer;
    }
    return answer;
}

/// The state dump of a session's primary terminal. Null once the session
/// has ended.
fn primaryDump(st: *ServerThread, session_id: u64) !?[]u8 {
    var answer = (try dumpSession(st, session_id)) orelse return null;
    defer answer.deinit();
    return try gpa.dupe(u8, answer.message.dump_reply.state);
}

/// Writes `bytes` to a session's program as if a client had typed them.
fn typeDetached(st: *ServerThread, session_id: u64, bytes: []const u8) !void {
    const fd = (try tellSession(st.runtimeDir(), session_id, .{ .inject = .{ .bytes = bytes } })) orelse return error.NoSession;
    session.unix.close(fd);
}

/// Waits until a session's primary terminal shows `needle`, as plain text.
fn waitForPrimaryText(st: *ServerThread, session_id: u64, needle: []const u8) !void {
    const deadline = nowMs() + timeout_ms;
    while (nowMs() < deadline) {
        const text = try primaryText(st, session_id);
        defer gpa.free(text);
        if (std.mem.indexOf(u8, text, needle) != null) return;
        try testing.io.sleep(.fromMilliseconds(10), .awake);
    }
    return error.Timeout;
}

/// The visible text of a session's primary terminal. Owned by the caller.
fn primaryText(st: *ServerThread, session_id: u64) ![]const u8 {
    var answer = (try dumpSession(st, session_id)) orelse return error.NoSession;
    defer answer.deinit();
    return gpa.dupe(u8, answer.message.dump_reply.text);
}

/// The size of a session's primary terminal.
fn primarySize(st: *ServerThread, session_id: u64) !struct { u16, u16 } {
    var answer = (try dumpSession(st, session_id)) orelse return error.NoSession;
    defer answer.deinit();
    return .{ answer.message.dump_reply.cols, answer.message.dump_reply.rows };
}

/// The pid of session `id`'s process.
fn sessionPid(st: *const ServerThread, id: u64) !posix.pid_t {
    var answer = (try askSession(st.runtimeDir(), id, .{ .list = .{} })) orelse return error.NoSession;
    defer answer.deinit();
    return @intCast(answer.message.session_info.pid.?);
}

/// Relays UDP datagrams between clients and a server on 127.0.0.1, one
/// upstream socket per client address. While `dropping` is set it drops
/// them all, as a network that went away would. `blockExisting` drops
/// those of the client addresses seen so far from then on, as a network
/// change does to a connection's old path.
const Relay = struct {
    fd: posix.fd_t,
    /// For clients to connect to.
    addresses: [1]Io.net.IpAddress,
    server: c.sockaddr.in,
    pairs: [16]Pair = undefined,
    len: usize = 0,
    dropping: std.atomic.Value(bool) = .init(false),
    /// Set by `blockExisting` until the relay's thread takes it.
    block_requested: std.atomic.Value(bool) = .init(false),
    /// Pairs before this index are dropped.
    blocked: usize = 0,
    stopping: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,

    const Pair = struct {
        client: c.sockaddr.in,
        fd: posix.fd_t,
    };

    extern "c" fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;

    fn loopback(port: u16) c.sockaddr.in {
        return .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
    }

    fn open(port: u16) !posix.fd_t {
        const fd = socket(c.AF.INET, c.SOCK.DGRAM, 0);
        if (fd == -1) return error.SocketFailed;
        errdefer _ = c.close(fd);
        const addr = loopback(port);
        if (c.bind(fd, @ptrCast(&addr), @sizeOf(c.sockaddr.in)) != 0) return error.BindFailed;
        return fd;
    }

    fn start(r: *Relay, server: Io.net.IpAddress) !void {
        const fd = try open(0);
        var addr: c.sockaddr.in = undefined;
        var len: c.socklen_t = @sizeOf(c.sockaddr.in);
        if (c.getsockname(fd, @ptrCast(&addr), &len) != 0) return error.SocketFailed;
        r.* = .{
            .fd = fd,
            .addresses = .{try .parseIp4("127.0.0.1", std.mem.bigToNative(u16, addr.port))},
            .server = loopback(server.getPort()),
        };
        r.thread = try std.Thread.spawn(.{}, run, .{r});
    }

    fn blockExisting(r: *Relay) void {
        r.block_requested.store(true, .release);
        while (r.block_requested.load(.acquire)) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    }

    fn stop(r: *Relay) void {
        r.stopping.store(true, .release);
        r.thread.join();
        for (r.pairs[0..r.len]) |pair| _ = c.close(pair.fd);
        _ = c.close(r.fd);
    }

    fn run(r: *Relay) void {
        var buf: [65536]u8 = undefined;
        while (!r.stopping.load(.acquire)) {
            if (r.block_requested.load(.acquire)) {
                r.blocked = r.len;
                r.block_requested.store(false, .release);
            }
            var fds: [17]posix.pollfd = undefined;
            fds[0] = .{ .fd = r.fd, .events = posix.POLL.IN, .revents = 0 };
            for (r.pairs[0..r.len], 1..) |pair, i| fds[i] = .{ .fd = pair.fd, .events = posix.POLL.IN, .revents = 0 };
            if (c.poll(&fds, @intCast(r.len + 1), 20) <= 0) continue;
            const dropping = r.dropping.load(.acquire);

            // From a client, to the server through the client's socket.
            if (fds[0].revents != 0) {
                var from: c.sockaddr.in = undefined;
                var from_len: c.socklen_t = @sizeOf(c.sockaddr.in);
                const n = c.recvfrom(r.fd, &buf, buf.len, 0, @ptrCast(&from), &from_len);
                if (n > 0 and !dropping) if (r.pairFor(from)) |i| {
                    if (i >= r.blocked) _ = c.sendto(r.pairs[i].fd, &buf, @intCast(n), 0, @ptrCast(&r.server), @sizeOf(c.sockaddr.in));
                };
            }

            // From the server, back to the client.
            for (r.pairs[0..r.len], 0..) |pair, i| {
                if (fds[i + 1].revents == 0) continue;
                const n = c.recv(pair.fd, &buf, buf.len, 0);
                if (n > 0 and !dropping and i >= r.blocked) _ = c.sendto(r.fd, &buf, @intCast(n), 0, @ptrCast(&pair.client), @sizeOf(c.sockaddr.in));
            }
        }
    }

    /// The index of the pair for `from`, made on its first datagram.
    fn pairFor(r: *Relay, from: c.sockaddr.in) ?usize {
        for (r.pairs[0..r.len], 0..) |pair, i| {
            if (pair.client.port == from.port and pair.client.addr == from.addr) return i;
        }
        if (r.len == r.pairs.len) return null;
        const fd = open(0) catch return null;
        r.pairs[r.len] = .{ .client = from, .fd = fd };
        r.len += 1;
        return r.len - 1;
    }
};

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

    /// Reads what the client writes to its terminal for up to `ms`.
    fn readFor(p: *TestPty, ms: i32) !void {
        var fds = [_]posix.pollfd{.{ .fd = p.master, .events = posix.POLL.IN, .revents = 0 }};
        if (c.poll(&fds, 1, ms) != 1) return;
        var buf: [4096]u8 = undefined;
        const n = c.read(p.master, &buf, buf.len);
        if (n > 0) try p.output.appendSlice(gpa, buf[0..@intCast(n)]);
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
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,

    fn start(ct: *ClientThread) !void {
        ct.thread = try std.Thread.spawn(.{}, run, .{ct});
    }

    fn run(ct: *ClientThread) void {
        ct.result = client.session.run(gpa, testing.io, ct.options);
        ct.done.store(true, .release);
    }

    /// Keeps reading the client's terminal until the client returns. On
    /// macOS, restoring the terminal's attributes waits until its output
    /// has been read, and a pty holds little output.
    fn join(ct: *ClientThread, pty: *TestPty) !client.session.Outcome {
        while (!ct.done.load(.acquire)) try pty.readFor(10);
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

test "a session runs, detaches, reattaches and exits through txd and tx" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    try environ.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    const keys = [_]auth.Key{login.key.public_key.toBytes()};

    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{
        "/bin/sh", "-c",
        \\printf 'hello \033[1mbold\033[m\r\n'
        \\i=0; while [ $i -lt 40 ]; do printf 'line %d\r\n' $i; i=$((i + 1)); done
        \\printf 'term=%s\r\n' "$TERM"
        \\printf 'ready\r\n'
        \\read -r a
        \\printf 'got %s\r\n' "$a"
        \\read -r b
        \\exit 3
    }));
    defer st.deinit();

    // A new session.
    var first: TestPty = try .open();
    defer first.close();
    var a: ClientThread = .{ .options = login.clientOptions(&st, &first, &keys) };
    try a.start();
    try first.readUntil("ready");
    try testing.expect(std.mem.indexOf(u8, first.output.items, "term=xterm-256color") != null);
    try first.type_("abc\r");
    try first.readUntil("got abc");

    // `~.` detaches. The session keeps running.
    try first.type_("~.");
    const detached = try a.join(&first);
    const session_id = detached.detached.?;
    try expectMatchesPrimary(&st, session_id, first.output.items);

    // Reattach from another terminal: the server rebuilds the session in it.
    var second: TestPty = try .open();
    defer second.close();
    var b: ClientThread = .{ .options = login.clientOptions(&st, &second, &keys) };
    b.options.session_id = session_id;
    try b.start();
    try second.readUntil("got abc");
    try expectMatchesPrimary(&st, session_id, second.output.items);

    // The program exits; the client reports its status.
    try second.type_("q\r");
    const exited = try b.join(&second);
    try testing.expectEqual(3, exited.exited.status);
    try testing.expectEqual(null, try primaryDump(&st, session_id));
}

test "a session whose log was trimmed reattaches with its scrollback" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    try environ.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    const keys = [_]auth.Key{login.key.public_key.toBytes()};

    // A 4 KiB log holds a few lines of the output, which comes once the
    // client has detached. While a client is attached, a log must hold
    // what the program writes between two sends.
    var options = try login.serverOptions(&environ, &.{
        "/bin/sh", "-c",
        \\printf 'started\r\n'
        \\read -r a
        \\i=0; while [ $i -lt 2000 ]; do printf 'line %d\r\n' $i; i=$((i + 1)); done
        \\printf 'ready\r\n'
        \\read -r b
    });
    options.terminal.log_capacity = 4096;
    var st: ServerThread = undefined;
    try st.init(options);
    defer st.deinit();

    var first: TestPty = try .open();
    defer first.close();
    var a: ClientThread = .{ .options = login.clientOptions(&st, &first, &keys) };
    try a.start();
    try first.readUntil("started");
    try first.type_("~.");
    const session_id = (try a.join(&first)).detached.?;

    // The output starts with no client attached.
    try typeDetached(&st, session_id, "\r");
    try waitForPrimaryText(&st, session_id, "ready");

    // The log dropped the first line. Scrollback still has it.
    var second: TestPty = try .open();
    defer second.close();
    var b: ClientThread = .{ .options = login.clientOptions(&st, &second, &keys) };
    b.options.session_id = session_id;
    try b.start();
    try second.readUntil("ready");
    try testing.expect(std.mem.indexOf(u8, second.output.items, "line 0\r\n") != null);
    try expectMatchesPrimary(&st, session_id, second.output.items);

    try second.type_("~.");
    _ = try b.join(&second);
}

test "reattaching inside an unfinished sequence finishes it" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    try environ.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    const keys = [_]auth.Key{login.key.public_key.toBytes()};

    // The title sequence is cut in two by the read.
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{
        "/bin/sh", "-c",
        \\printf 'ready\r\n\033]2;ti'
        \\read -r a
        \\printf 'tle\033\\done\r\n'
        \\read -r b
    }));
    defer st.deinit();

    var first: TestPty = try .open();
    defer first.close();
    var a: ClientThread = .{ .options = login.clientOptions(&st, &first, &keys) };
    try a.start();
    try first.readUntil("\x1b]2;ti");
    try first.type_("~.");
    const session_id = (try a.join(&first)).detached.?;

    var second: TestPty = try .open();
    defer second.close();
    var b: ClientThread = .{ .options = login.clientOptions(&st, &second, &keys) };
    b.options.session_id = session_id;
    try b.start();
    try second.readUntil("\x1b]2;ti");
    try second.type_("\r");
    try second.readUntil("done");
    try expectMatchesPrimary(&st, session_id, second.output.items);

    try second.type_("~.");
    _ = try b.join(&second);
}

/// A server running a shell loop that echoes each line it reads, and a
/// relay in front of it.
const EchoSetup = struct {
    environ: std.process.Environ.Map,
    login: Login,
    st: ServerThread,
    relay: Relay,

    fn init(e: *EchoSetup, log_capacity: ?usize) !void {
        transport.crypto.init(testing.io);
        e.environ = .init(gpa);
        errdefer e.environ.deinit();
        try e.environ.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");
        try e.login.init(null);
        errdefer e.login.deinit();

        var options = try e.login.serverOptions(&e.environ, &.{
            "/bin/sh", "-c",
            \\printf 'ready\r\n'
            \\while read -r a; do
            \\  if [ "$a" = flood ]; then i=0; while [ $i -lt 2000 ]; do printf 'line %d\r\n' $i; i=$((i + 1)); done; fi
            \\  printf 'got %s\r\n' "$a"
            \\done
        });
        if (log_capacity) |n| options.terminal.log_capacity = n;
        try e.st.init(options);
        errdefer e.st.deinit();
        try e.relay.start(e.st.addresses[0]);
    }

    fn deinit(e: *EchoSetup) void {
        e.relay.stop();
        e.st.deinit();
        e.login.deinit();
        e.environ.deinit();
    }

    /// A client through the relay that notices a dead connection within a
    /// second.
    fn clientOptions(e: *EchoSetup, pty: *const TestPty, keys: []const auth.Key) client.session.Options {
        var options = e.login.clientOptions(&e.st, pty, keys);
        options.servers = &e.relay.addresses;
        options.idle_timeout_ns = std.time.ns_per_s;
        options.keep_alive_ns = 200 * std.time.ns_per_ms;
        return options;
    }
};

test "a client that loses its connection resumes where it left off" {
    var e: EchoSetup = undefined;
    try e.init(null);
    defer e.deinit();
    const keys = [_]auth.Key{e.login.key.public_key.toBytes()};

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = e.clientOptions(&pty, &keys) };
    // No notice, so the resume continues from the client's seq.
    ct.options.notice_delay_ms = 60_000;
    try ct.start();
    try pty.readUntil("ready");
    try pty.type_("one\r");
    try pty.readUntil("got one");

    // The network goes away. The server still has the old connection, and
    // sends `got two` on it. The client holds `three` until it is back.
    // The server's first session is 1.
    e.relay.dropping.store(true, .release);
    try testing.io.sleep(.fromMilliseconds(300), .awake);
    try typeDetached(&e.st, 1, "two\r");
    try pty.type_("three\r");
    try testing.io.sleep(.fromMilliseconds(1200), .awake);
    e.relay.dropping.store(false, .release);

    const before = pty.output.items.len;
    try pty.readUntil("got three");
    const after = pty.output.items[before..];
    try testing.expect(std.mem.indexOf(u8, after, "got two") != null);
    // The output continued with no rebuild.
    try testing.expect(std.mem.indexOf(u8, after, "\x1b[!p") == null);
    try expectMatchesPrimary(&e.st, 1, pty.output.items);

    try pty.type_("~.");
    try testing.expectEqual(1, (try ct.join(&pty)).detached.?);
}

test "a client gives up on a silent connection before its idle timeout" {
    var e: EchoSetup = undefined;
    try e.init(null);
    defer e.deinit();
    const keys = [_]auth.Key{e.login.key.public_key.toBytes()};

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = e.clientOptions(&pty, &keys) };
    // Only the silence can end the connection within the test's timeout.
    ct.options.idle_timeout_ns = 30 * std.time.ns_per_s;
    ct.options.silence_timeout_ns = 600 * std.time.ns_per_ms;
    ct.options.notice_delay_ms = 60_000;
    try ct.start();
    try pty.readUntil("ready");

    // The old path stays dead. Only a new connection gets through.
    e.relay.blockExisting();
    try pty.type_("one\r");
    try pty.readUntil("got one");

    try pty.type_("~.");
    _ = try ct.join(&pty);
}

test "a resumed client whose output left the log gets a repaint" {
    var e: EchoSetup = undefined;
    try e.init(4096);
    defer e.deinit();
    const keys = [_]auth.Key{e.login.key.public_key.toBytes()};

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = e.clientOptions(&pty, &keys) };
    ct.options.notice_delay_ms = 100;
    try ct.start();
    try pty.readUntil("ready");

    // The output goes to the old connection, and leaves the log.
    e.relay.dropping.store(true, .release);
    try typeDetached(&e.st, 1, "flood\r");
    try waitForPrimaryText(&e.st, 1, "got flood");
    try pty.readUntil("reconnecting");
    e.relay.dropping.store(false, .release);

    // The repaint shows the screen as it is, without the notice.
    try pty.readUntil("got flood");
    try pty.type_("x\r");
    try pty.readUntil("got x");
    const want = try primaryText(&e.st, 1);
    defer gpa.free(want);
    const stand_in: *term.Primary = try .create(gpa, testing.io, .{ .cols = 80, .rows = 24 });
    defer stand_in.destroy();
    try stand_in.output(pty.output.items);
    const got = try stand_in.terminal.plainString(gpa);
    defer gpa.free(got);
    try testing.expectEqualStrings(want, got);

    try pty.type_("~.");
    _ = try ct.join(&pty);
}

test "a client whose session was attached elsewhere doesn't take it back" {
    var e: EchoSetup = undefined;
    try e.init(null);
    defer e.deinit();
    const keys = [_]auth.Key{e.login.key.public_key.toBytes()};

    var first: TestPty = try .open();
    defer first.close();
    var a: ClientThread = .{ .options = e.clientOptions(&first, &keys) };
    a.options.notice_delay_ms = 60_000;
    try a.start();
    try first.readUntil("ready");

    // While the first client is away, another attaches.
    e.relay.dropping.store(true, .release);
    var second: TestPty = try .open();
    defer second.close();
    var b: ClientThread = .{ .options = e.login.clientOptions(&e.st, &second, &keys) };
    b.options.session_id = 1;
    try b.start();
    try second.readUntil("ready");

    // The first client gives up on its connection before the server's
    // error could reach it. Its key is stale, so its resume fails.
    try testing.io.sleep(.fromMilliseconds(1500), .awake);
    e.relay.dropping.store(false, .release);

    const outcome = try a.join(&first);
    try testing.expectEqualStrings("can't resume session 1: it ended, or was attached elsewhere", outcome.refused.message.slice());

    try second.type_("y\r");
    try second.readUntil("got y");

    // A client that is still connected is told at once.
    var third: TestPty = try .open();
    defer third.close();
    var c3: ClientThread = .{ .options = e.login.clientOptions(&e.st, &third, &keys) };
    c3.options.session_id = 1;
    try c3.start();
    try third.readUntil("ready");
    const taken = try b.join(&second);
    try testing.expectEqualStrings("the session was attached elsewhere", taken.refused.message.slice());

    try third.type_("~.");
    _ = try c3.join(&third);
}

/// A server whose sessions set the title `title N`, N being the session's
/// ID, and wait for a line.
const TitleSetup = struct {
    environ: std.process.Environ.Map,
    login: Login,
    st: ServerThread,
    keys: [1]auth.Key,

    fn init(t: *TitleSetup) !void {
        transport.crypto.init(testing.io);
        t.environ = .init(gpa);
        errdefer t.environ.deinit();
        try t.environ.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");
        try t.login.init(null);
        errdefer t.login.deinit();
        t.keys = .{t.login.key.public_key.toBytes()};
        try t.st.init(try t.login.serverOptions(&t.environ, &.{
            "/bin/sh", "-c",
            \\printf '\033]2;title %s\033\\ready\r\n' "$TX_SESSION_ID"
            \\read -r a
        }));
    }

    fn deinit(t: *TitleSetup) void {
        t.st.deinit();
        t.login.deinit();
        t.environ.deinit();
    }

    /// Runs a client until its outcome. A client that attaches is detached
    /// once it shows `ready`.
    fn run(t: *TitleSetup, command: client.session.Command, session_id: ?u64, reuse: bool) !client.session.Outcome {
        var pty: TestPty = try .open();
        defer pty.close();
        var ct: ClientThread = .{ .options = t.login.clientOptions(&t.st, &pty, &t.keys) };
        ct.options.command = command;
        ct.options.session_id = session_id;
        ct.options.reuse_detached = reuse;
        try ct.start();

        // A refused attach ends without `ready`.
        if (command == .attach) {
            const deadline = nowMs() + timeout_ms;
            while (std.mem.indexOf(u8, pty.output.items, "ready") == null and !ct.done.load(.acquire)) {
                if (nowMs() > deadline) return error.Timeout;
                try pty.readFor(10);
            }
            if (!ct.done.load(.acquire)) try pty.type_("~.");
        }
        return ct.join(&pty);
    }
};

test "a client lists the sessions, and kills one" {
    var t: TitleSetup = undefined;
    try t.init();
    defer t.deinit();

    try testing.expectEqual(1, (try t.run(.attach, null, false)).detached.?);

    // A second session, attached while the list is taken.
    var pty: TestPty = try .open();
    defer pty.close();
    var attached: ClientThread = .{ .options = t.login.clientOptions(&t.st, &pty, &t.keys) };
    try attached.start();
    try pty.readUntil("ready");

    const listed = (try t.run(.list, null, false)).listed;
    defer gpa.free(listed);
    try testing.expectEqual(2, listed.len);
    try testing.expectEqual(1, listed[0].session_id);
    try testing.expectEqual(null, listed[0].attached_from);
    try testing.expectEqualStrings("title 1", listed[0].title.?.slice());
    try testing.expectEqual(80, listed[0].cols);
    try testing.expectEqual(2, listed[1].session_id);
    try testing.expect(std.mem.startsWith(u8, listed[1].attached_from.?.slice(), "127.0.0.1:"));

    try testing.expectEqual(1, (try t.run(.{ .kill = 1 }, null, false)).killed);
    const deadline = nowMs() + timeout_ms;
    while (try primaryDump(&t.st, 1)) |dump| {
        gpa.free(dump);
        if (nowMs() > deadline) return error.Timeout;
        try testing.io.sleep(.fromMilliseconds(10), .awake);
    }
    const after = (try t.run(.list, null, false)).listed;
    defer gpa.free(after);
    try testing.expectEqual(1, after.len);
    try testing.expectEqual(2, after[0].session_id);

    try testing.expectEqualStrings("no such session", (try t.run(.{ .kill = 7 }, null, false)).refused.message.slice());

    try pty.type_("~.");
    _ = try attached.join(&pty);
}

test "a client without an ID attaches the one detached session" {
    var t: TitleSetup = undefined;
    try t.init();
    defer t.deinit();

    // With none detached, a session starts. With one, it is attached.
    try testing.expectEqual(1, (try t.run(.attach, null, true)).detached.?);
    try testing.expectEqual(1, (try t.run(.attach, null, true)).detached.?);

    // An attached session isn't picked.
    var pty: TestPty = try .open();
    defer pty.close();
    var attached: ClientThread = .{ .options = t.login.clientOptions(&t.st, &pty, &t.keys) };
    attached.options.reuse_detached = true;
    try attached.start();
    try pty.readUntil("title 1");
    try testing.expectEqual(2, (try t.run(.attach, null, true)).detached.?);
    try pty.type_("~.");
    _ = try attached.join(&pty);

    const refusal = (try t.run(.attach, null, true)).refused;
    try testing.expectEqual(@backingInt(proto.ErrorCode.several_detached), refusal.code);
    try testing.expectEqualStrings("sessions 1, 2 are detached", refusal.message.slice());
}

test "a client accepting another server key is refused" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" }));
    defer st.deinit();

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &.{login.key.public_key.toBytes()}) };
    ct.options.host_keys = &.{Ed25519.KeyPair.generate(testing.io).public_key.toBytes()};
    try ct.start();
    const outcome = try ct.join(&pty);
    try testing.expectEqual(st.host_keys[0], outcome.host_key_refused);
}

test "a client tries the next address when the first doesn't answer" {
    transport.crypto.init(testing.io);
    var environ = try testEnviron();
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "printf 'ready\\r\\n'" }));
    defer st.deinit();

    // The server listens on 127.0.0.1 only. Nothing answers on ::1.
    const port = st.server.address().getPort();
    const servers = [_]Io.net.IpAddress{ try .parseIp6("::1", port), st.server.address() };

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &.{login.key.public_key.toBytes()}) };
    ct.options.servers = &servers;
    const start = nowMs();
    try ct.start();
    const outcome = try ct.join(&pty);
    try testing.expectEqual(0, outcome.exited.status);

    // The second attempt starts 250 ms after the first, long before the
    // first times out.
    try testing.expect(nowMs() - start < 5000);
}

test "a client whose addresses all fail reports the failure" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" }));
    defer st.deinit();

    // Ports nothing listens on.
    const servers = [_]Io.net.IpAddress{ try .parseIp6("::1", 9), try .parseIp4("127.0.0.1", 9) };

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &.{login.key.public_key.toBytes()}) };
    ct.options.servers = &servers;
    ct.options.handshake_timeout_ns = std.time.ns_per_s;
    const start = nowMs();
    try ct.start();
    const outcome = try ct.join(&pty);
    try testing.expectEqual(transport.endpoint.CloseReason.idle_timeout, outcome.no_connection);

    // The handshake timeout ends the attempts, long before the 30 s idle
    // timeout.
    try testing.expect(nowMs() - start < 5000);
}

test "the agent's keys are probed in order and only the accepted one signs" {
    transport.crypto.init(testing.io);
    var environ = try testEnviron();
    defer environ.deinit();

    // The agent holds an unlisted key first, then the user key.
    const unlisted: Ed25519.KeyPair = .generate(testing.io);
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    login.agent.keys = &.{ unlisted, login.key };
    const keys = [_]auth.Key{ unlisted.public_key.toBytes(), login.key.public_key.toBytes() };

    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "printf 'ready\\r\\n'; read -r a" }));
    defer st.deinit();

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &keys) };
    ct.options.show_session_id = true;
    try ct.start();
    try pty.readUntil("tx: session 1\r\n");
    try pty.readUntil("ready");
    try pty.type_("\r");
    _ = try ct.join(&pty);

    try testing.expectEqual(1, login.agent.signatures.load(.monotonic));
}

test "a client whose keys aren't in authorized_keys is refused" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();

    const unlisted: Ed25519.KeyPair = .generate(testing.io);
    var login: Login = undefined;
    try login.init(&.{unlisted});
    defer login.deinit();
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" }));
    defer st.deinit();

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &.{unlisted.public_key.toBytes()}) };
    try ct.start();
    const outcome = try ct.join(&pty);
    try testing.expectEqualStrings("the server accepted none of the keys for tx-test", outcome.refused.message.slice());
    try testing.expectEqual(0, login.agent.signatures.load(.monotonic));
}

test "a client logging in as another user is refused" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" }));
    defer st.deinit();

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &.{login.key.public_key.toBytes()}) };
    ct.options.user = "root";
    try ct.start();
    const outcome = try ct.join(&pty);
    try testing.expectEqualStrings("the server accepted none of the keys for root", outcome.refused.message.slice());
}

test "a refused signature fails the login" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    login.agent.refuse.store(true, .release);
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" }));
    defer st.deinit();

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &.{login.key.public_key.toBytes()}) };
    try ct.start();
    const outcome = try ct.join(&pty);
    try testing.expectEqualStrings("the SSH agent refused to sign", outcome.refused.message.slice());
}

test "a signature over another transcript is refused" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" }));
    defer st.deinit();

    var rc: RawClient = undefined;
    try rc.init(&st, login.key, .{ .revision = proto.revision, .term = "xterm-256color", .cols = 80, .rows = 24 });
    defer rc.deinit();
    rc.login = .wrong_exporter;
    try testing.expectEqual(@backingInt(server_pkg.ErrorCode.auth), try rc.waitError());
    try testing.expectEqual(null, rc.attached);
}

test "attaching before login is refused" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" }));
    defer st.deinit();

    var rc: RawClient = undefined;
    try rc.init(&st, login.key, .{ .revision = proto.revision, .term = "xterm-256color", .cols = 80, .rows = 24 });
    defer rc.deinit();
    rc.login = .skip;
    try testing.expectEqual(@backingInt(server_pkg.ErrorCode.protocol), try rc.waitError());
    try testing.expectEqual(null, rc.attached);
}

const raw_hello: proto.Hello = .{ .revision = proto.revision, .term = "xterm-256color", .cols = 80, .rows = 24 };

test "a client that doesn't log in in time is told so and closed" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var options = try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" });
    options.pending.timeout_ns = 300 * std.time.ns_per_ms;
    var st: ServerThread = undefined;
    try st.init(options);
    defer st.deinit();

    var rc: RawClient = undefined;
    try rc.init(&st, login.key, raw_hello);
    defer rc.deinit();
    rc.login = .idle;
    const start = nowMs();
    try testing.expectEqual(@backingInt(server_pkg.ErrorCode.auth), try rc.waitError());
    try testing.expectEqualStrings("login timed out", rc.error_message[0..rc.error_message_len]);
    try rc.waitClosed();

    // The deadline, then the second the server gives the message.
    const elapsed = nowMs() - start;
    try testing.expect(elapsed >= 300 and elapsed < 3000);
}

test "connections from one address past the limit are dropped until one closes" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var options = try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" });
    options.pending.max_per_source = 2;
    var st: ServerThread = undefined;
    try st.init(options);
    defer st.deinit();

    var first: RawClient = undefined;
    try first.init(&st, login.key, raw_hello);
    first.login = .idle;
    try first.waitConnected();
    var second: RawClient = undefined;
    try second.init(&st, login.key, raw_hello);
    defer second.deinit();
    second.login = .idle;
    try second.waitConnected();

    // The server drops the third's packets.
    var third: RawClient = undefined;
    try third.init(&st, login.key, raw_hello);
    defer third.deinit();
    third.login = .idle;
    try third.runFor(1000);
    try testing.expectEqual(null, third.conn);

    // Once the first closes, the third's retransmitted Initial gets in.
    first.deinit();
    try third.waitConnected();
}

test "past retry_from, a client logs in after a Retry" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var options = try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" });
    options.pending.retry_from = 0;
    var st: ServerThread = undefined;
    try st.init(options);
    defer st.deinit();

    var rc: RawClient = undefined;
    try rc.init(&st, login.key, raw_hello);
    defer rc.deinit();
    _ = try rc.waitAttached();
    // Each Initial the client sends before the Retry arrives gets one.
    try testing.expect(@atomicLoad(u64, &st.server.pending.retries, .monotonic) >= 1);
}

test "a server with an SPA key answers only clients with its key" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    const key = transport.spa.generate();
    var options = try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" });
    options.spa_key = key;
    var st: ServerThread = undefined;
    try st.init(options);
    defer st.deinit();

    // Without the key, or with another, nothing answers.
    var pty: TestPty = try .open();
    defer pty.close();
    for ([_]?transport.spa.Key{ null, transport.spa.generate() }) |spa_key| {
        var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &.{login.key.public_key.toBytes()}) };
        ct.options.command = .list;
        ct.options.spa_key = spa_key;
        ct.options.handshake_timeout_ns = std.time.ns_per_s;
        try ct.start();
        const outcome = try ct.join(&pty);
        try testing.expectEqual(transport.endpoint.CloseReason.idle_timeout, outcome.no_connection);
    }

    // With it, the client logs in.
    var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &.{login.key.public_key.toBytes()}) };
    ct.options.command = .list;
    ct.options.spa_key = key;
    try ct.start();
    const listed = (try ct.join(&pty)).listed;
    defer gpa.free(listed);
    try testing.expectEqual(0, listed.len);
}

test "a client with the SPA key logs in after a Retry" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    const key = transport.spa.generate();
    var options = try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" });
    options.spa_key = key;
    options.pending.retry_from = 0;
    var st: ServerThread = undefined;
    try st.init(options);
    defer st.deinit();

    // The Initial after the Retry has the same source ID, so the same
    // nonce, from the same address.
    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &.{login.key.public_key.toBytes()}) };
    ct.options.command = .list;
    ct.options.spa_key = key;
    try ct.start();
    const listed = (try ct.join(&pty)).listed;
    defer gpa.free(listed);
    try testing.expect(@atomicLoad(u64, &st.server.pending.retries, .monotonic) >= 1);
}

test "a server with an SPA key sends nothing to a copy of a first packet from another address" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    const key = transport.spa.generate();
    var options = try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" });
    options.spa_key = key;
    // The connection the first packet starts is gone a few seconds later:
    // ngtcp2 waits at least three probe timeouts.
    options.idle_timeout_ns = 500 * std.time.ns_per_ms;
    var st: ServerThread = undefined;
    try st.init(options);
    defer st.deinit();
    const server = Relay.loopback(st.addresses[0].getPort());

    var marked_buf: [2048]u8 = undefined;
    const marked = try firstDatagram(&key, &marked_buf);
    var unmarked_buf: [2048]u8 = undefined;
    const unmarked = try firstDatagram(null, &unmarked_buf);

    const first = try Relay.open(0);
    defer _ = c.close(first);
    const other = try Relay.open(0);
    defer _ = c.close(other);

    // An unmarked packet gets nothing, and the marked one an answer.
    try testing.expect(!answered(first, unmarked, server, 500));
    try testing.expect(answered(first, marked, server, timeout_ms));

    // Once the server has dropped that connection, the copy from another
    // address gets nothing. From the first address, it is a retransmit,
    // and gets an answer.
    const deadline = nowMs() + timeout_ms;
    while (@atomicLoad(u32, &st.server.pending.total, .monotonic) > 0) {
        if (nowMs() > deadline) return error.Timeout;
        try testing.io.sleep(.fromMilliseconds(20), .awake);
    }
    while (receive(first, 0) != null) {}
    try testing.expect(!answered(other, marked, server, 500));
    try testing.expect(answered(first, marked, server, timeout_ms));
}

/// The first datagram of a client, marked with `spa_key` if it is set,
/// caught on a socket of the test's before it reaches any server.
fn firstDatagram(spa_key: ?*const transport.spa.Key, buf: []u8) ![]u8 {
    const catcher = try Relay.open(0);
    defer _ = c.close(catcher);
    var addr: c.sockaddr.in = undefined;
    var len: c.socklen_t = @sizeOf(c.sockaddr.in);
    if (c.getsockname(catcher, @ptrCast(&addr), &len) != 0) return error.SocketFailed;

    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();
    var tls: transport.quic.Client = try .init(.any);
    defer tls.deinit();
    var endpoint: transport.endpoint.Endpoint = undefined;
    try endpoint.init(gpa, testing.io, &loop, .{
        .local = try .parseIp4("127.0.0.1", 0),
        .role = .{ .client = &tls },
        .spa_key = spa_key,
    });
    defer endpoint.deinit();

    // `connect` sends the first Initial before it returns.
    _ = try endpoint.connect(try .parseIp4("127.0.0.1", std.mem.bigToNative(u16, addr.port)));
    const n = c.recv(catcher, buf.ptr, buf.len, 0);
    endpoint.stop();
    try loop.run(.until_done);
    if (n <= 0) return error.ReceiveFailed;
    return buf[0..@intCast(n)];
}

/// Sends `packet` from `fd` to `to`, and waits up to `ms` for anything
/// back.
fn answered(fd: posix.fd_t, packet: []const u8, to: c.sockaddr.in, ms: i32) bool {
    if (c.sendto(fd, packet.ptr, packet.len, 0, @ptrCast(&to), @sizeOf(c.sockaddr.in)) != packet.len) return false;
    return receive(fd, ms) != null;
}

/// The length of a datagram that arrives on `fd` within `ms`.
fn receive(fd: posix.fd_t, ms: i32) ?usize {
    var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    if (c.poll(&fds, 1, ms) != 1) return null;
    var buf: [2048]u8 = undefined;
    const n = c.recv(fd, &buf, buf.len, 0);
    return if (n > 0) @intCast(n) else null;
}

// From `ssh-keygen -t ed25519`, with no passphrase and with "correct horse".
// They are the test keys of auth/private_key.zig.
const plain_key_file =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    \\QyNTUxOQAAACDI/tJmA4x7Bqj2AcaIoSueX1FmHADCLttG/2lcclxpWQAAAIjXUWLl11Fi
    \\5QAAAAtzc2gtZWQyNTUxOQAAACDI/tJmA4x7Bqj2AcaIoSueX1FmHADCLttG/2lcclxpWQ
    \\AAAEAgNr/hbGFlAKl+PqHYq7+Fb0LObTU5440OQQiXF0X+G8j+0mYDjHsGqPYBxoihK55f
    \\UWYcAMIu20b/aVxyXGlZAAAABXBsYWlu
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
const encrypted_key_file =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAm/7i1ie
    \\UhrMoBGLvmYoqEAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAINCQJexQXcQKPgL7
    \\X1aHoO45B6XEMcJxRSwTy8TYKT6vAAAAkMWEVaaFHfH4dTZLp0RicWHT1/vWTXf2iW8Vlf
    \\bRk9QcckE+ynTGOb28DigYKDoFQoPiLnvB0kFtPGmTq2QBbnIL+5EO+TQbxEhXkUGo9OUk
    \\z7FhHZW/Fqm4oivLFKYSdMTQmi8vpsmT79m0jYlPaa+6W5AqhjNaGWxdqpEk/GA28CCTKY
    \\JXjp9dszWtvnBnHQ==
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;

fn rightPassphrase(_: []const u8, buf: []u8, _: posix.fd_t) ?[]u8 {
    const pass = "correct horse";
    @memcpy(buf[0..pass.len], pass);
    return buf[0..pass.len];
}

fn wrongPassphrase(_: []const u8, buf: []u8, _: posix.fd_t) ?[]u8 {
    buf[0] = 'x';
    return buf[0..1];
}

fn noPassphrase(_: []const u8, _: []u8, _: posix.fd_t) ?[]u8 {
    return null;
}

/// Logs in with the key in `text`, saved as a key file the server accepts,
/// and returns the outcome. The program prints `ready` and exits.
fn loginWithKeyFile(text: []const u8, ask: *const fn ([]const u8, []u8, posix.fd_t) ?[]u8) !client.session.Outcome {
    transport.crypto.init(testing.io);
    var environ = try testEnviron();
    defer environ.deinit();

    // The agent holds no key the server accepts.
    const other: Ed25519.KeyPair = .generate(testing.io);
    var login: Login = undefined;
    try login.init(&.{other});
    defer login.deinit();

    const path = try login.writeKeyFile("id_ed25519", text);
    defer gpa.free(path);
    var file: auth.private_key.PrivateKeyFile = try .parse(gpa, text);
    defer file.deinit(gpa);
    try login.authorize(&.fromEd25519(file.public_key));

    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "printf 'ready\\r\\n'" }));
    defer st.deinit();

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &.{other.public_key.toBytes()}) };
    const ids = [_]client.session.Identity{
        .{ .key = .fromEd25519(other.public_key.toBytes()), .source = .agent },
        .{ .key = .fromEd25519(file.public_key), .source = .{ .file = path } },
    };
    ct.options.identities = &ids;
    ct.options.passphrase = ask;
    try ct.start();
    return ct.join(&pty);
}

test "an RSA key from the agent logs in" {
    transport.crypto.init(testing.io);
    var environ = try testEnviron();
    defer environ.deinit();

    // The agent holds only the RSA key, and authorized_keys lists it.
    var login: Login = undefined;
    try login.init(&.{});
    defer login.deinit();
    login.agent.rsa_keys = (&auth.agent.test_rsa_key)[0..1];
    const rsa_key = auth.agent.test_rsa_key.public();
    try login.authorize(&rsa_key);

    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "printf 'ready\\r\\n'" }));
    defer st.deinit();

    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = login.clientOptions(&st, &pty, &.{}) };
    const ids = [_]client.session.Identity{.{ .key = rsa_key, .source = .agent }};
    ct.options.identities = &ids;
    try ct.start();
    const outcome = try ct.join(&pty);
    try testing.expectEqual(0, outcome.exited.status);
    try testing.expectEqual(1, login.agent.signatures.load(.monotonic));
}

test "a key file logs in when the agent's keys don't" {
    const outcome = try loginWithKeyFile(plain_key_file, noPassphrase);
    try testing.expectEqual(0, outcome.exited.status);
}

test "an encrypted key file logs in with its passphrase" {
    const outcome = try loginWithKeyFile(encrypted_key_file, rightPassphrase);
    try testing.expectEqual(0, outcome.exited.status);
}

test "a wrong passphrase fails the login" {
    const outcome = try loginWithKeyFile(encrypted_key_file, wrongPassphrase);
    try testing.expect(std.mem.startsWith(u8, outcome.refused.message.slice(), "wrong passphrase for "));
}

test "a canceled passphrase prompt fails the login" {
    const outcome = try loginWithKeyFile(encrypted_key_file, noPassphrase);
    try testing.expectEqualStrings("login canceled", outcome.refused.message.slice());
}

/// A client that speaks the protocol directly, for messages `tx` doesn't
/// send. It logs in with `key`, signing itself.
const RawClient = struct {
    loop: xev.Loop,
    tls: transport.quic.Client,
    endpoint: transport.endpoint.Endpoint,
    conn: ?*transport.endpoint.Conn = null,
    stream: ?*transport.endpoint.Stream = null,
    decoder: proto.Decoder,
    hello: proto.Hello,
    key: Ed25519.KeyPair,
    /// Set before the loop first runs. `idle` says hello and nothing more.
    login: enum { normal, wrong_exporter, skip, idle } = .normal,
    attached: ?u64 = null,
    error_code: ?u32 = null,
    error_message: [64]u8 = undefined,
    error_message_len: usize = 0,
    closed: bool = false,
    output: std.ArrayList(u8) = .empty,

    fn init(rc: *RawClient, st: *const ServerThread, key: Ed25519.KeyPair, hello: proto.Hello) !void {
        return rc.initTo(st, st.server.address(), key, hello);
    }

    fn initTo(rc: *RawClient, st: *const ServerThread, server: Io.net.IpAddress, key: Ed25519.KeyPair, hello: proto.Hello) !void {
        rc.* = .{
            .loop = try .init(.{}),
            .tls = try .init(.{ .keys = &.{st.server.options.identity.public_key.toBytes()} }),
            .endpoint = undefined,
            .decoder = .init(gpa, 1 << 20),
            .hello = hello,
            .key = key,
        };
        try rc.endpoint.init(gpa, testing.io, &rc.loop, .{
            .local = switch (server) {
                .ip4 => try .parseIp4("0.0.0.0", 0),
                .ip6 => try .parseIp6("::", 0),
            },
            .role = .{ .client = &rc.tls },
            .handler = .{ .ctx = rc, .connected = onConnected, .data = onData, .closed = onClosed },
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
        rc.conn = conn;
        rc.stream = stream;
        send(stream, .{ .hello = rc.hello });
        switch (rc.login) {
            .skip => send(stream, .{ .attach = .{} }),
            .idle => {},
            else => send(stream, .{ .auth_probe = .{ .user = test_user, .key = &auth.ssh.keyBlob(rc.key.public_key.toBytes()) } }),
        }
    }

    /// Signs the transcript, or one with another exporter value, and
    /// attaches.
    fn signIn(rc: *RawClient, stream: *transport.endpoint.Stream) void {
        var transcript: auth.login.Transcript = .{
            .exporter = undefined,
            .host_key = rc.tls.presentedKey().?,
            .user = test_user,
            .alpn = transport.quic.alpn,
            .revision = proto.revision,
        };
        rc.conn.?.quic.exportSecret(&transcript.exporter, auth.login.exporter_label);
        if (rc.login == .wrong_exporter) transcript.exporter[0] ^= 1;

        const data = transcript.signedData();
        const sig = rc.key.sign(data.slice(), null) catch @panic("sign");
        send(stream, .{ .auth_signature = .{
            .user = test_user,
            .key = &auth.ssh.keyBlob(rc.key.public_key.toBytes()),
            .signature = &auth.sshsig.signatureBlob(sig.toBytes()),
        } });
        send(stream, .{ .attach = .{} });
    }

    fn onData(ctx: ?*anyopaque, stream: *transport.endpoint.Stream, bytes: []const u8, _: bool) void {
        const rc: *RawClient = @ptrCast(@alignCast(ctx.?));
        stream.consume(bytes.len);
        rc.decoder.feed(bytes);
        while (rc.decoder.next() catch null) |message| switch (message) {
            .auth_probe_reply => |m| if (m.accepted) rc.signIn(stream),
            .attached => |m| rc.attached = m.session_id,
            .output => |m| rc.output.appendSlice(gpa, m.bytes) catch @panic("OOM"),
            .@"error" => |m| {
                rc.error_code = m.code;
                rc.error_message_len = @min(m.message.len, rc.error_message.len);
                @memcpy(rc.error_message[0..rc.error_message_len], m.message[0..rc.error_message_len]);
            },
            else => {},
        };
    }

    fn onClosed(ctx: ?*anyopaque, _: *transport.endpoint.Conn, _: transport.endpoint.CloseReason) void {
        const rc: *RawClient = @ptrCast(@alignCast(ctx.?));
        rc.closed = true;
    }

    fn waitConnected(rc: *RawClient) !void {
        const deadline = nowMs() + timeout_ms;
        while (rc.conn == null) {
            if (nowMs() > deadline) return error.Timeout;
            try rc.loop.run(.no_wait);
            testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }

    fn waitClosed(rc: *RawClient) !void {
        const deadline = nowMs() + timeout_ms;
        while (!rc.closed) {
            if (nowMs() > deadline) return error.Timeout;
            try rc.loop.run(.no_wait);
            testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }

    /// Runs the loop for `ms`.
    fn runFor(rc: *RawClient, ms: i64) !void {
        const end = nowMs() + ms;
        while (nowMs() < end) {
            try rc.loop.run(.no_wait);
            testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }

    fn waitError(rc: *RawClient) !u32 {
        const deadline = nowMs() + timeout_ms;
        while (rc.error_code == null) {
            if (nowMs() > deadline) return error.Timeout;
            try rc.loop.run(.no_wait);
            testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
        return rc.error_code.?;
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

test "a server on a wildcard address answers on each address it binds" {
    transport.crypto.init(testing.io);
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var options = try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" });
    options.listen = try .parseIp6("::", 0);
    var st: ServerThread = undefined;
    try st.init(options);
    defer st.deinit();

    // Read before the first rescan can change the list.
    var bound: std.ArrayList(Io.net.IpAddress) = .empty;
    defer bound.deinit(gpa);
    for (st.server.endpoints.items) |e| try bound.append(gpa, e.local);
    try testing.expect(bound.items.len > 0);

    // Every endpoint shares the first one's port.
    for (bound.items) |address| try testing.expectEqual(bound.items[0].getPort(), address.getPort());

    for (bound.items) |address| {
        // macOS can't send to its own Tailscale IPv6 address, through tx or
        // otherwise.
        if (!try reachesItself(address)) continue;

        var rc: RawClient = undefined;
        try rc.initTo(&st, address, login.key, .{ .revision = proto.revision, .term = "xterm-256color", .cols = 80, .rows = 24 });
        defer rc.deinit();
        _ = try rc.waitAttached();
    }
}

/// Whether a UDP datagram sent to `address`, from this machine, arrives.
fn reachesItself(address: Io.net.IpAddress) !bool {
    var any = address;
    any.setPort(0);
    const receiver = try any.bind(testing.io, .{ .mode = .dgram });
    defer receiver.close(testing.io);
    const sender = try any.bind(testing.io, .{ .mode = .dgram });
    defer sender.close(testing.io);

    sender.send(testing.io, &receiver.address, "ping") catch return false;
    var buf: [16]u8 = undefined;
    const timeout: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(500), .clock = .awake } };
    _ = receiver.receiveTimeout(testing.io, &buf, timeout) catch return false;
    return true;
}

test "a server bounds the terminal size a client sends" {
    transport.crypto.init(testing.io);
    var environ = try testEnviron();
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "sleep 10" }));
    defer st.deinit();

    for ([_]struct { u16, u16, u16, u16 }{
        .{ 0, 0, 80, 24 },
        .{ 65535, 65535, 1024, 1024 },
    }) |case| {
        const cols, const rows, const want_cols, const want_rows = case;
        var rc: RawClient = undefined;
        try rc.init(&st, login.key, .{ .revision = proto.revision, .term = "xterm-256color", .cols = cols, .rows = rows });
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
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "stty raw -echo; printf 'ready\\r\\n'; head -c 262144 | wc -c" }));
    defer st.deinit();

    var rc: RawClient = undefined;
    try rc.init(&st, login.key, .{
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

test "a session told to stop kills a program that ignores SIGHUP" {
    transport.crypto.init(testing.io);
    var environ = try testEnviron();
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "trap '' HUP; printf 'ready\\r\\n'; while :; do sleep 1; done" }));
    defer st.deinit();

    var rc: RawClient = undefined;
    try rc.init(&st, login.key, raw_hello);
    defer rc.deinit();
    const id = try rc.waitAttached();
    try rc.waitOutput("ready");

    // As a service manager stopping the user's services does.
    const start = nowMs();
    try posix.kill(try sessionPid(&st, id), .TERM);
    try testing.expectEqual(@backingInt(proto.ErrorCode.session_lost), try rc.waitError());
    try testing.expect(nowMs() - start < 5000);
    try testing.expectEqual(null, try primaryDump(&st, id));
}

test "a session process that dies tells its client" {
    transport.crypto.init(testing.io);
    var environ = try testEnviron();
    defer environ.deinit();
    var login: Login = undefined;
    try login.init(null);
    defer login.deinit();
    var st: ServerThread = undefined;
    try st.init(try login.serverOptions(&environ, &.{ "/bin/sh", "-c", "printf 'ready\\r\\n'; sleep 10" }));
    defer st.deinit();

    var rc: RawClient = undefined;
    try rc.init(&st, login.key, raw_hello);
    defer rc.deinit();
    const id = try rc.waitAttached();
    try rc.waitOutput("ready");

    try posix.kill(try sessionPid(&st, id), .KILL);
    try testing.expectEqual(@backingInt(proto.ErrorCode.session_lost), try rc.waitError());
    try testing.expectEqualStrings("the session's process ended", rc.error_message[0..rc.error_message_len]);
}

test "a session outlives txd, and its client resumes it on the next txd" {
    var e: EchoSetup = undefined;
    try e.init(null);
    defer e.deinit();
    const keys = [_]auth.Key{e.login.key.public_key.toBytes()};

    // `restart` replaces the server thread's fields, which the client
    // mustn't read meanwhile.
    const servers = e.st.addresses;
    const host_keys = e.st.host_keys;
    var pty: TestPty = try .open();
    defer pty.close();
    var ct: ClientThread = .{ .options = e.login.clientOptions(&e.st, &pty, &keys) };
    ct.options.servers = &servers;
    ct.options.host_keys = &host_keys;
    ct.options.notice_delay_ms = 60_000;
    try ct.start();
    try pty.readUntil("ready");
    try pty.type_("one\r");
    try pty.readUntil("got one");

    // The client's connection closes with the server. Input typed
    // meanwhile is sent once it is back.
    try e.st.restart();
    try pty.type_("two\r");
    const before = pty.output.items.len;
    try pty.readUntil("got two");
    // The output continued with no rebuild.
    try testing.expect(std.mem.indexOf(u8, pty.output.items[before..], "\x1b[!p") == null);
    try expectMatchesPrimary(&e.st, 1, pty.output.items);

    try pty.type_("~.");
    try testing.expectEqual(1, (try ct.join(&pty)).detached.?);
}

test "a new txd lists and kills the sessions it didn't start, and numbers new ones after them" {
    var t: TitleSetup = undefined;
    try t.init();
    defer t.deinit();

    try testing.expectEqual(1, (try t.run(.attach, null, false)).detached.?);
    try testing.expectEqual(2, (try t.run(.attach, null, false)).detached.?);
    try t.st.restart();

    const listed = (try t.run(.list, null, false)).listed;
    defer gpa.free(listed);
    try testing.expectEqual(2, listed.len);
    try testing.expectEqual(1, listed[0].session_id);
    try testing.expectEqualStrings("title 2", listed[1].title.?.slice());

    try testing.expectEqual(3, (try t.run(.attach, null, false)).detached.?);
    try testing.expectEqual(1, (try t.run(.{ .kill = 1 }, null, false)).killed);
    // 2 and 3 are detached.
    try testing.expectEqual(@backingInt(proto.ErrorCode.several_detached), (try t.run(.attach, null, true)).refused.code);
}

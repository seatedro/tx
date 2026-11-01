const std = @import("std");
const builtin = @import("builtin");
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
const wayland = @import("wayland");
pub const addresses = @import("addresses.zig");
pub const runtime_dir = @import("runtime_dir.zig");
pub const exec = @import("exec.zig");
pub const terminfo = @import("terminfo.zig");
pub const clipboard = @import("clipboard.zig");

const Endpoint = transport.endpoint.Endpoint;
const Exec = exec.Exec;
const Conn = transport.endpoint.Conn;
const Stream = transport.endpoint.Stream;
const Channel = session.Channel;
const unix = session.unix;

const log = std.log.scoped(.server);

pub const Options = struct {
    listen: IpAddress,
    scope: addresses.Scope = .all,
    identity: Ed25519.KeyPair,
    user: []const u8,
    authorized_keys: []const []const u8,
    runtime_dir: []const u8,
    session_exe: []const u8,
    session_log: ?posix.fd_t = null,
    environ: *const std.process.Environ.Map,
    shell: []const u8 = "/bin/sh",
    terminfo_dir: ?[]const u8 = null,
    argv: []const []const u8,
    program: ?[]const u8 = null,
    cwd: std.process.Child.Cwd = .inherit,
    terminal: session.host.Options.TerminalOptions = .{},
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
    pending: transport.pending.Limits = .{},
    wayland_socket: ?[]const u8 = null,
};

const has_clipboard = builtin.os.tag == .linux;
const Clipboard = if (has_clipboard) clipboard.Clipboard else void;

const display_defaults = [_]struct { []const u8, []const u8 }{
    .{ "MPLBACKEND", "Agg" },
    .{ "SDL_VIDEODRIVER", "x11" },
    .{ "SDL_VIDEO_DRIVER", "x11" },
    .{ "QT_QPA_PLATFORM", "xcb" },
};

pub const ErrorCode = proto.ErrorCode;

const high_water = 1 << 20;
const low_water = 256 << 10;

const query_timeout_ms = 1000;

const max_message = 1 << 20;

const max_login_message = 16 << 10;

const max_login_attempts = 6;

const boundedSize = session.session.boundedSize;
const cellSize = session.session.cellSize;

const rescan_ms = 5000;

pub const Server = struct {
    gpa: Allocator,
    io: Io,
    loop: *xev.Loop,
    options: Options,
    tls: transport.quic.Server,
    pending: transport.pending.Pending,
    endpoints: std.ArrayList(*Endpoint) = .empty,
    retired: std.ArrayList(*Endpoint) = .empty,
    rescan: ?Rescan = null,
    execs: std.ArrayList(*Exec) = .empty,
    stopping: bool = false,
    next_id: u64 = 1,
    clipboard: ?*Clipboard = null,

    const Rescan = struct {
        wildcard: IpAddress,
        host_loopback: []IpAddress,
        timer: xev.Timer,
        c: xev.Completion = .{},
        cancel_c: xev.Completion = .{},
    };

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
            self.startClipboard();
            return;
        }

        self.rescan = .{
            .wildcard = options.listen,
            .host_loopback = try addresses.hostLoopback(gpa, io, options.listen),
            .timer = try .init(),
        };
        const in_use = try self.updateAddresses(.initial);
        if (self.endpoints.items.len == 0) return if (in_use > 0) error.AddressInUse else error.NoAddresses;
        self.rescan.?.timer.run(loop, &self.rescan.?.c, rescan_ms, Server, self, onRescan);
        self.startClipboard();
    }

    fn startClipboard(self: *Server) void {
        if (!has_clipboard) return;
        const path = self.options.wayland_socket orelse return;
        self.clipboard = Clipboard.create(self.gpa, self.io, self.loop, path) catch |err| {
            log.warn("no clipboard server at {s}: {t}", .{ path, err });
            return;
        };
    }

    pub fn address(self: *const Server) IpAddress {
        return self.endpoints.items[0].local;
    }

    pub fn stop(self: *Server) void {
        self.stopping = true;
        for (self.execs.items) |e| e.kill();
        for (self.endpoints.items) |e| e.stop();
        if (has_clipboard) if (self.clipboard) |cb| cb.close();
        self.clipboard = null;
        if (self.rescan) |*r| if (r.c.state() == .active) {
            r.cancel_c = .{ .op = .{ .cancel = .{ .c = &r.c } } };
            self.loop.add(&r.cancel_c);
        };
    }

    pub fn deinit(self: *Server) void {
        for (self.endpoints.items) |e| self.destroyEndpoint(e);
        while (self.execs.items.len > 0) self.execs.items[0].destroy();
        self.execs.deinit(self.gpa);
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

    fn updateAddresses(self: *Server, when: enum { initial, rescan }) !usize {
        const r = &self.rescan.?;
        const found = try addresses.interfaces(self.gpa, r.wildcard, self.options.scope);
        defer self.gpa.free(found);

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

            var local = found_address;
            local.setPort(r.wildcard.getPort());

            const e = self.listen(local) catch |err| {
                if (err == error.AddressInUse) in_use += 1;
                if (when == .initial) log.warn("can't listen on {f}: {t}", .{ local, err });
                continue;
            };
            log.info("listening on {f}", .{e.local});

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

    fn onConnected(ctx: ?*anyopaque, conn: *Conn) void {
        const self = fromCtx(ctx);
        const client = self.gpa.create(Client) catch return conn.close(0);
        client.* = .{ .server = self, .conn = conn, .decoder = .init(self.gpa, max_login_message) };
        conn.context = client;
    }

    fn onStreamOpened(_: ?*anyopaque, stream: *Stream) void {
        const client = Client.of(stream.conn) orelse return stream.reset(0);
        if (client.stream == null) {
            client.stream = stream;
            stream.context = client;
            return;
        }
        if (has_clipboard and isUni(stream) and client.upstream != null and client.server.clipboard != null) {
            const answer = client.server.gpa.create(ClipboardAnswer) catch return stream.reset(0);
            answer.* = .{ .stream = stream };
            client.answers.append(client.server.gpa, answer) catch {
                client.server.gpa.destroy(answer);
                return stream.reset(0);
            };
            stream.context = answer;
            return;
        }
        stream.reset(0);
    }

    fn isUni(stream: *const Stream) bool {
        return stream.id & 0x2 != 0;
    }

    fn onData(_: ?*anyopaque, stream: *Stream, bytes: []const u8, fin: bool) void {
        const client = Client.of(stream.conn) orelse return stream.consume(bytes.len);
        if (client.exec) |e| if (e.owns(stream)) return e.received(stream, bytes, fin);
        if (has_clipboard) if (client.answerOn(stream)) |answer| return client.onAnswerData(answer, bytes, fin);
        if (client.stream != stream) return stream.consume(bytes.len);

        if (client.upstream != null and client.upstream.?.congested()) {
            client.held += bytes.len;
        } else stream.consume(bytes.len);

        if (stream.fin) {
            if (fin) stream.conn.close(0);
            return;
        }

        client.decoder.feed(bytes);
        while (true) {
            const message = client.decoder.next() catch return client.fail(.protocol, "malformed message");
            client.handle(message orelse break);
            if (stream.conn.closing != null or stream.fin) return;
        }

        if (fin) stream.conn.close(0);
    }

    fn onAcked(_: ?*anyopaque, stream: *Stream) void {
        const client = Client.of(stream.conn) orelse return;
        if (client.exec) |e| if (e.owns(stream)) return e.acked(stream);
        const u = client.upstream orelse return;
        if (u.paused and stream.buffered() <= low_water) u.resumeReading();
    }

    fn onStreamClosed(_: ?*anyopaque, stream: *Stream) void {
        const client = Client.of(stream.conn) orelse return;
        if (client.exec) |e| e.streamClosed(stream);
        if (client.stream == stream) client.stream = null;
        if (has_clipboard) if (client.answerOn(stream)) |answer| client.endAnswer(answer, null);
    }

    fn onClosed(_: ?*anyopaque, conn: *Conn, reason: transport.endpoint.CloseReason) void {
        const client = Client.of(conn) orelse return;
        client.destroy(reason == .peer);
        conn.context = null;
    }

    fn onPendingExpired(_: ?*anyopaque, conn: *Conn) void {
        const client = Client.of(conn) orelse return;
        log.info("{f} didn't log in in time", .{conn.remote});
        client.fail(.auth, "login timed out");
    }

    fn accepts(self: *Server, user: []const u8, key_blob: []const u8) bool {
        if (user.len > 0 and !std.mem.eql(u8, user, self.options.user)) return false;

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

    fn socketPath(self: *const Server, buf: []u8, id: u64) error{NameTooLong}![]const u8 {
        return runtime_dir.socketPath(buf, self.options.runtime_dir, id);
    }

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

    fn sessionIds(self: *Server) ![]u64 {
        return runtime_dir.ids(self.gpa, self.io, self.options.runtime_dir);
    }

    fn newId(self: *Server) !u64 {
        const ids = try self.sessionIds();
        defer self.gpa.free(ids);
        if (ids.len > 0) self.next_id = @max(self.next_id, ids[ids.len - 1] + 1);
        const id = self.next_id;
        self.next_id += 1;
        return id;
    }

    fn clientEnviron(self: *Server, arena: Allocator, hello: *const Hello) !std.process.Environ.Map {
        var environ = try self.options.environ.clone(arena);
        if (self.clipboard != null) {
            try environ.put("WAYLAND_DISPLAY", self.options.wayland_socket.?);
            for (display_defaults) |entry| {
                const name, const value = entry;
                if (!environ.contains(name)) try environ.put(name, value);
            }
        }
        var items = std.mem.splitScalar(u8, hello.locale.items, 0);
        while (items.next()) |item| {
            const eq = std.mem.indexOfScalar(u8, item, '=') orelse continue;
            const name = item[0..eq];
            const value = item[eq + 1 ..];
            if (!proto.isLocaleName(name) or value.len == 0) continue;
            try environ.put(name, localeValue(value));
        }
        return environ;
    }

    fn startSession(self: *Server, hello: *const Hello, new: NewSession, handler: session.channel.Handler) !*Channel {
        const command = new.command;
        const id = try self.newId();
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var environ = try self.clientEnviron(arena, hello);
        try environ.put("TERM", hello.term.items);
        if (hello.colorterm.items.len > 0) try environ.put("COLORTERM", hello.colorterm.items);
        try environ.put("TX_SESSION_ID", try std.fmt.allocPrint(arena, "{d}", .{id}));

        if (new.terminfo) |source| if (self.options.terminfo_dir) |base| {
            if (terminfo.install(arena, self.io, base, source)) |dir| {
                try environ.put("TERMINFO", dir);
            } else |err| {
                log.warn("session {d}: can't compile the terminfo entry for {s}, so TERM is {s}: {t}", .{ id, hello.term.items, fallback_term, err });
                try environ.put("TERM", fallback_term);
            }
        };

        var environ_list: std.ArrayList(u8) = .empty;
        var it = environ.iterator();
        while (it.next()) |entry| try environ_list.print(arena, "{s}={s}\x00", .{ entry.key_ptr.*, entry.value_ptr.* });
        var argv_list: std.ArrayList(u8) = .empty;
        const argv: []const []const u8 = if (command) |cmd| &.{ std.fs.path.basename(self.options.shell), "-c", cmd } else self.options.argv;
        for (argv) |arg| try argv_list.print(arena, "{s}\x00", .{arg});

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
            .program = if (command != null) self.options.shell else self.options.program,
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

const NewSession = struct {
    command: ?[]const u8 = null,
    terminfo: ?[]const u8 = null,
};

const Colors = struct {
    foreground: ?u32 = null,
    background: ?u32 = null,
    palette: [16 * 4]u8 = undefined,
    palette_len: usize = 0,
    dark: ?bool = null,

    fn of(m: proto.Attach) Colors {
        var colors: Colors = .{ .foreground = m.foreground, .background = m.background, .dark = m.dark };
        const palette = m.palette orelse "";
        colors.palette_len = @min(palette.len, colors.palette.len);
        @memcpy(colors.palette[0..colors.palette_len], palette[0..colors.palette_len]);
        return colors;
    }

    fn in(colors: *const Colors, m: proto.Attach) proto.Attach {
        var with = m;
        with.foreground = colors.foreground;
        with.background = colors.background;
        with.palette = if (colors.palette_len > 0) colors.palette[0..colors.palette_len] else null;
        with.dark = colors.dark;
        return with;
    }
};

const fallback_term = "xterm-256color";

fn localeValue(value: []const u8) []const u8 {
    if (builtin.os.tag == .linux and std.mem.eql(u8, value, "UTF-8")) return "C.UTF-8";
    return value;
}

const Hello = struct {
    term: std.ArrayList(u8) = .empty,
    colorterm: std.ArrayList(u8) = .empty,
    locale: std.ArrayList(u8) = .empty,
    size: term.log.Resize = undefined,

    fn copy(h: *Hello, gpa: Allocator, m: proto.Hello) Allocator.Error!void {
        try h.term.appendSlice(gpa, m.term);
        try h.colorterm.appendSlice(gpa, m.colorterm orelse "");
        try h.locale.appendSlice(gpa, m.locale orelse "");
    }

    fn deinit(h: *Hello, gpa: Allocator) void {
        h.term.deinit(gpa);
        h.colorterm.deinit(gpa);
        h.locale.deinit(gpa);
    }
};

const ClipboardAnswer = struct {
    stream: *Stream,
    bytes: std.ArrayList(u8) = .empty,
    id: ?u64 = null,
    refused: bool = false,
    data_start: usize = 0,
};

const max_answer_header = 64;

const Client = struct {
    server: *Server,
    conn: *Conn,
    stream: ?*Stream = null,
    decoder: proto.Decoder,
    hello: ?Hello = null,
    logged_in: bool = false,
    login_attempts: u32 = 0,
    upstream: ?*Channel = null,
    session_id: ?u64 = null,
    query: ?*Query = null,
    exec: ?*Exec = null,
    terminfo: std.ArrayList(u8) = .empty,
    colors: Colors = .{},
    hangup: bool = false,
    held: usize = 0,
    acked: ?u64 = null,
    peer: clipboard.Peer = .{ .request = sendClipboardRequest, .copy = sendClipboardCopy },
    answers: std.ArrayList(*ClipboardAnswer) = .empty,

    fn of(conn: *Conn) ?*Client {
        return @ptrCast(@alignCast(conn.context orelse return null));
    }

    fn destroy(client: *Client, left: bool) void {
        const gpa = client.server.gpa;
        if (client.upstream) |u| {
            if (left) {
                u.handler = null;
                u.send(.{ .detach = .{} });
                u.finish();
            } else u.close();
        }
        if (client.query) |q| q.abandon();
        if (client.exec) |e| e.detach();
        if (has_clipboard) {
            if (client.server.clipboard) |cb| cb.gone(&client.peer);
            client.peer.dropOffer(gpa);
            for (client.answers.items) |answer| {
                answer.bytes.deinit(gpa);
                gpa.destroy(answer);
            }
        }
        client.answers.deinit(gpa);
        client.terminfo.deinit(gpa);
        client.decoder.deinit();
        if (client.hello) |*h| h.deinit(gpa);
        gpa.destroy(client);
    }

    fn handle(client: *Client, message: proto.Message) void {
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
            .exec => |m| client.onExec(m),
            .input, .resize => if (client.upstream) |u| {
                u.send(message);
                if (has_clipboard and message == .input) if (client.server.clipboard) |cb| cb.input(&client.peer);
            },
            .clipboard_offer => |m| client.onClipboardOffer(m),
            .ack => |m| client.acked = m.seq,
            .detach => client.conn.close(0),
            .unknown => {},
            else => client.fail(.protocol, "unexpected message"),
        }
    }

    fn onClipboardOffer(client: *Client, m: proto.ClipboardOffer) void {
        if (!has_clipboard) return;
        const cb = client.server.clipboard orelse return;
        if (client.upstream == null) return;

        var mimes: [wayland.server.max_mimes][]const u8 = undefined;
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, m.mimes, 0);
        while (it.next()) |mime| {
            if (mime.len == 0 or count == mimes.len) continue;
            mimes[count] = mime;
            count += 1;
        }
        cb.offer(&client.peer, m.change, mimes[0..count]);
    }

    fn fromPeer(peer: *clipboard.Peer) *Client {
        return @fieldParentPtr("peer", peer);
    }

    fn sendClipboardRequest(peer: *clipboard.Peer, m: proto.ClipboardRequest) void {
        fromPeer(peer).send(.{ .clipboard_request = m });
    }

    fn sendClipboardCopy(peer: *clipboard.Peer, mimes: []const []const u8, data: []const *wayland.pipe.Blob) void {
        const client = fromPeer(peer);
        const gpa = client.server.gpa;
        var names: std.ArrayList(u8) = .empty;
        defer names.deinit(gpa);
        var lens: std.ArrayList(u8) = .empty;
        defer lens.deinit(gpa);
        for (mimes, data) |mime, blob| {
            names.appendSlice(gpa, mime) catch return;
            names.append(gpa, 0) catch return;
            var len: [8]u8 = undefined;
            std.mem.writeInt(u64, &len, blob.bytes.len, .big);
            lens.appendSlice(gpa, &len) catch return;
        }

        const header: proto.Message = .{ .clipboard_copy = .{ .mimes = names.items, .lens = lens.items } };
        const buf = gpa.alloc(u8, proto.encodedLen(header)) catch return;
        defer gpa.free(buf);
        var w: Io.Writer = .fixed(buf);
        proto.encode(&w, header) catch unreachable;

        const stream = client.conn.openStream(.uni) catch |err| return log.warn("can't send a copy to {f}: {t}", .{ client.conn.remote, err });
        stream.write(buf) catch return stream.reset(0);
        for (data) |blob| stream.write(blob.bytes) catch return stream.reset(0);
        stream.finish();
    }

    fn answerOn(client: *Client, stream: *Stream) ?*ClipboardAnswer {
        for (client.answers.items) |answer| if (answer.stream == stream) return answer;
        return null;
    }

    fn onAnswerData(client: *Client, answer: *ClipboardAnswer, bytes: []const u8, fin: bool) void {
        const gpa = client.server.gpa;
        const cb = client.server.clipboard orelse return client.endAnswer(answer, null);
        answer.stream.consume(bytes.len);
        if (answer.bytes.items.len + bytes.len > clipboard.max_copy_len + max_answer_header) {
            answer.stream.reset(0);
            return client.endAnswer(answer, null);
        }
        answer.bytes.appendSlice(gpa, bytes) catch {
            answer.stream.reset(0);
            return client.endAnswer(answer, null);
        };

        if (answer.id == null) {
            const m, const len = (proto.frame.firstMessage(answer.bytes.items, max_answer_header) catch {
                answer.stream.reset(0);
                return client.endAnswer(answer, null);
            }) orelse {
                if (fin) client.endAnswer(answer, null);
                return;
            };
            if (m != .clipboard_data) {
                answer.stream.reset(0);
                return client.endAnswer(answer, null);
            }
            answer.id = m.clipboard_data.id;
            answer.refused = m.clipboard_data.refused;
            answer.data_start = len;
            cb.answerStarted(&client.peer, m.clipboard_data.id);
        }
        if (!fin) return;

        const data: ?[]u8 = if (answer.refused) null else gpa.dupe(u8, answer.bytes.items[answer.data_start..]) catch null;
        client.endAnswer(answer, data);
    }

    fn endAnswer(client: *Client, answer: *ClipboardAnswer, data: ?[]u8) void {
        const gpa = client.server.gpa;
        const index = std.mem.indexOfScalar(*ClipboardAnswer, client.answers.items, answer) orelse return;
        _ = client.answers.swapRemove(index);
        if (answer.id) |id| {
            if (client.server.clipboard) |cb| cb.answer(&client.peer, id, data) else if (data) |d| gpa.free(d);
        } else if (data) |d| gpa.free(d);
        answer.bytes.deinit(gpa);
        gpa.destroy(answer);
    }

    fn onHello(client: *Client, m: proto.Hello) void {
        if (client.hello != null) return client.fail(.protocol, "second hello");
        if (m.revision != proto.revision) return client.fail(.revision, "unsupported protocol revision");

        const gpa = client.server.gpa;
        var hello: Hello = .{ .size = boundedSize(m.cols, m.rows, cellSize(m.cell_width_px, m.cell_height_px)) orelse
            .{ .cols = 80, .rows = 24 } };
        hello.copy(gpa, m) catch {
            hello.deinit(gpa);
            return client.fail(.protocol, "out of memory");
        };
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

        if (!server.accepts(m.user, m.key)) return client.fail(.auth, "login refused");
        const key = auth.ssh.PublicKey.parse(m.key) catch unreachable;
        const fingerprint = auth.Fingerprint.ofBlob(key.blob());

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

        log.info("{f} logged in as {s} with key {s}", .{ client.conn.remote, server.options.user, fingerprint.slice() });
        client.completeLogin();
        client.send(.{ .auth_ok = .{} });
    }

    fn completeLogin(client: *Client) void {
        client.logged_in = true;
        client.conn.admit();
        client.decoder.max_body_len = max_message;
    }

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

    fn onExec(client: *Client, m: proto.Exec) void {
        const server = client.server;
        const hello = &(client.hello orelse return client.fail(.protocol, "exec before hello"));
        if (client.upstream != null or client.query != null or client.exec != null) return client.fail(.protocol, "second command");

        var arena_state: std.heap.ArenaAllocator = .init(server.gpa);
        defer arena_state.deinit();
        const environ = server.clientEnviron(arena_state.allocator(), hello) catch return client.fail(.spawn, "out of memory");
        const e = Exec.start(server.gpa, server.loop, client.conn, .{
            .shell = server.options.shell,
            .command = m.command,
            .environ = &environ,
            .cwd = server.options.cwd,
            .handler = .{ .client = client, .exited = onExecExited, .server = server, .freed = onExecFreed },
        }) catch |err| {
            log.warn("{f} can't run a command: {t}", .{ client.conn.remote, err });
            return client.fail(.spawn, "can't run the command");
        };
        server.execs.append(server.gpa, e) catch {
            e.detach();
            return client.fail(.spawn, "out of memory");
        };
        client.exec = e;
        log.info("{f} runs a command", .{client.conn.remote});
    }

    fn onExecExited(context: *anyopaque, exit: proto.Exit) void {
        const client: *Client = @ptrCast(@alignCast(context));
        client.send(.{ .exit = exit });
    }

    fn onExecFreed(context: *anyopaque, client_context: ?*anyopaque, e: *Exec) void {
        const server: *Server = @ptrCast(@alignCast(context));
        for (server.execs.items, 0..) |item, i| if (item == e) {
            _ = server.execs.swapRemove(i);
            break;
        };
        if (client_context) |c| {
            const client: *Client = @ptrCast(@alignCast(c));
            client.exec = null;
        }
    }

    fn onAttach(client: *Client, m: proto.Attach) void {
        if (client.hello == null) return client.fail(.protocol, "attach before hello");
        if (client.upstream != null or client.query != null or client.exec != null) return client.fail(.protocol, "second attach");

        client.colors = .of(m);
        client.hangup = m.hangup;
        if (m.terminfo) |source| {
            if (source.len > terminfo.max_source_len) return client.fail(.protocol, "terminfo entry too long");
            client.terminfo.appendSlice(client.server.gpa, source) catch return client.fail(.protocol, "out of memory");
        }

        if (m.command) |command| {
            if (m.session_id != null or m.reuse) return client.fail(.protocol, "a command needs a new session");
            return client.startNew(command);
        }

        if (m.session_id) |id| {
            const fd = client.server.connectSession(id) orelse return client.fail(.no_session, "no such session");
            return client.connectTo(fd, null, .{ .attach = m });
        }
        if (m.reuse) return client.startQuery(.reuse);
        client.startNew(null);
    }

    fn startNew(client: *Client, command: ?[]const u8) void {
        const new: NewSession = .{
            .command = command,
            .terminfo = if (client.terminfo.items.len > 0) client.terminfo.items else null,
        };
        const ch = client.server.startSession(&client.hello.?, new, client.upstreamHandler()) catch |err| {
            log.warn("starting a session failed: {t}", .{err});
            return client.fail(.spawn, "can't start the session");
        };
        client.upstream = ch;
        client.sendConnect(null, .{ .attach = .{} });
    }

    fn onResume(client: *Client, m: proto.Resume) void {
        if (!client.startLoginAttempt()) return;
        if (client.upstream != null) return client.fail(.protocol, "second attach");

        const fd = client.server.connectSession(m.session_id) orelse return client.fail(.auth, "can't resume the session");
        var exporter: [auth.resume_.exporter_len]u8 = undefined;
        client.conn.quic.exportSecret(&exporter, auth.resume_.exporter_label);
        client.connectTo(fd, &exporter, .{ .@"resume" = m });
    }

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
            .attach => |m| attach: {
                var with = client.colors.in(m);
                with.hangup = client.hangup;
                break :attach .{ .attach = with };
            },
            .@"resume" => |m| .{ .@"resume" = m },
        });
    }

    fn onKill(client: *Client, m: proto.Kill) void {
        const fd = client.server.connectSession(m.session_id) orelse return client.fail(.no_session, "no such session");
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
        client.query = q;
        q.reportIfDone();
    }

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
            w.print("{s} {d}", .{ if (count > 1) "," else "", a.id }) catch {};
        }

        if (count > 1) {
            w.writeAll(" are detached") catch {};
            return client.fail(.several_detached, w.buffered());
        }
        const id = found orelse return client.startNew(null);
        const fd = client.server.connectSession(id) orelse return client.startNew(null);
        client.connectTo(fd, null, .{ .attach = .{} });
    }

    fn upstreamHandler(client: *Client) session.channel.Handler {
        return .{ .context = client, .received = onUpstream, .drained = onUpstreamDrained, .closed = onUpstreamClosed };
    }

    fn fromContext(context: *anyopaque) *Client {
        return @ptrCast(@alignCast(context));
    }

    fn onUpstream(context: *anyopaque, u: *Channel, raw: proto.Decoder.Raw) void {
        const client = fromContext(context);
        switch (raw.type_id) {
            proto.messages.Started.type_id => return,
            proto.Attached.type_id => {
                const m = proto.Attached.decode(raw.body) catch return client.fail(.protocol, "malformed message from the session");
                client.session_id = m.session_id;
                if (!client.logged_in) client.completeLogin();
            },
            else => {},
        }
        client.forward(raw.bytes);

        if (raw.type_id == proto.Exit.type_id or raw.type_id == proto.Error.type_id) {
            client.upstream = null;
            u.close();
            if (client.stream) |stream| stream.finish();
            return;
        }

        if (client.stream) |stream| if (stream.buffered() > high_water) u.pauseReading();
    }

    fn onUpstreamDrained(context: *anyopaque, _: *Channel) void {
        const client = fromContext(context);
        const stream = client.stream orelse return;
        stream.consume(client.held);
        client.held = 0;
    }

    fn onUpstreamClosed(context: *anyopaque, _: *Channel) void {
        const client = fromContext(context);
        client.upstream = null;
        if (client.session_id) |id| log.info("session {d}'s process ended before its program", .{id});
        client.fail(.session_lost, "the session's process ended");
    }

    fn forward(client: *Client, bytes: []const u8) void {
        const stream = client.stream orelse return;
        if (stream.fin) return;
        stream.write(bytes) catch client.conn.close(0);
    }

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

    fn fail(client: *Client, code: ErrorCode, message: []const u8) void {
        client.send(.{ .@"error" = .{ .code = @backingInt(code), .message = message } });
        if (client.stream) |stream| stream.finish();
    }
};

const Query = struct {
    server: *Server,
    client: ?*Client,
    purpose: Purpose,
    answers: std.ArrayList(Answer) = .empty,
    waiting: usize = 0,
    reported: bool = false,
    timer: xev.Timer,
    timer_c: xev.Completion = .{},
    cancel_c: xev.Completion = .{},

    const Purpose = enum { list, reuse };

    const Answer = struct {
        query: *Query,
        id: u64,
        channel: ?*Channel,
        reply: ?[]u8 = null,
        body_start: usize = 0,

        fn info(a: *const Answer) ?proto.SessionInfo {
            const reply = a.reply orelse return null;
            return proto.SessionInfo.decode(reply[a.body_start..]) catch null;
        }
    };

    fn start(client: *Client, purpose: Purpose) !*Query {
        const server = client.server;
        const ids = try server.sessionIds();
        defer server.gpa.free(ids);

        const q = try server.gpa.create(Query);
        q.* = .{ .server = server, .client = client, .purpose = purpose, .timer = try .init() };
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

        if (q.waiting > 0) q.timer.run(server.loop, &q.timer_c, query_timeout_ms, Query, q, onTimer);
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
        if (q.timer_c.state() == .dead) return q.destroy();
        q.timer.cancel(q.server.loop, &q.timer_c, &q.cancel_c, Query, q, onCanceled);
    }

    fn report(q: *Query) void {
        q.reported = true;
        for (q.answers.items) |*a| if (a.channel) |ch| {
            a.channel = null;
            ch.close();
        };
        if (q.client) |client| client.onQueryDone(q);
    }

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
    _ = exec;
    _ = terminfo;
    _ = &transport.crypto.init;
}

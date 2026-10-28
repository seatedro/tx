//! A session process, `txd --session --fd N`: one session (see `session`),
//! reached over Unix sockets.
//!
//! txd starts it with one end of a socket pair as fd N, and sends `Start`
//! there. The process starts the program, listens at `Start.socket_path`,
//! and answers `Started`. After that the socket pair is a channel like any
//! txd connects later.
//!
//! On each channel txd's first message says what the channel is for.
//! `Connect` describes a client, and the client's `Attach` or `Resume`,
//! then its `Input`, `Resize` and `Detach`, follow. `List` gets the
//! session's `SessionInfo`, and `Kill` ends the session and gets `Killed`.
//! For tests, `Dump` gets `DumpReply`, and `Inject` types into the program.
//! Only the user running the process may connect.
//!
//! The process exits once the program has exited and its client has read
//! `Exit`. SIGTERM, SIGINT and SIGHUP stop the session (see
//! `Session.stop`); after the grace period the program is killed and the
//! process exits.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const posix = std.posix;
const c = std.c;
const xev = @import("xev");
const proto = @import("proto");
const auth = @import("auth");
const term = @import("term");
const session_pkg = @import("session.zig");
const unix = @import("unix.zig");
const channel = @import("channel.zig");

const Session = session_pkg.Session;
const Channel = channel.Channel;

const log = std.log.scoped(.session);

/// The signals that stop the session.
const stop_signals = [_]posix.SIG{ .TERM, .INT, .HUP };

/// Runs the session process on `fd`, the socket from txd. Returns the
/// exit status: 0, or 1 if the session didn't start.
pub fn run(gpa: Allocator, io: Io, fd: posix.fd_t) !u8 {
    unix.ignoreSigpipe();

    // Blocked before any thread starts, so that only `watchSignals` takes
    // them.
    var signals: posix.sigset_t = undefined;
    _ = c.sigemptyset(&signals);
    for (stop_signals) |sig| _ = c.sigaddset(&signals, sig);
    var old_mask: posix.sigset_t = undefined;
    _ = c.pthread_sigmask(posix.SIG.BLOCK, &signals, &old_mask);

    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();

    var p: Process = .{ .gpa = gpa, .io = io, .loop = &loop, .uid = c.getuid(), .signal = try .init() };
    defer p.signal.deinit();
    p.signal.wait(&loop, &p.signal_c, Process, &p, onSignal);
    const thread = try std.Thread.spawn(.{}, watchSignals, .{ &p, signals });
    thread.detach();

    try unix.adopt(fd);
    try p.addPeer(fd, true);

    while (!p.finished()) {
        try loop.run(.once);

        // A program that outlived the grace period is killed, and the
        // clients learn the session is gone.
        if (p.session) |s| if (s.stopped()) {
            s.destroy();
            p.session = null;
            p.finishPeers();
        };
    }

    // The session frees itself in a callback of its own. The loop then
    // has nothing left but the signal wait, which the notification ends.
    p.exiting = true;
    try p.signal.notify();
    try loop.run(.until_done);
    p.peers.deinit(gpa);
    if (p.socket_path) |path| gpa.free(path);
    return if (p.started) 0 else 1;
}

fn watchSignals(p: *Process, signals: posix.sigset_t) void {
    var set = signals;
    while (true) {
        var sig: c_int = 0;
        if (c.sigwait(&set, &sig) != 0) continue;
        p.signaled.store(true, .release);
        p.signal.notify() catch {};
    }
}

fn onSignal(p_: ?*Process, _: *xev.Loop, _: *xev.Completion, result: xev.Async.WaitError!void) xev.CallbackAction {
    const p = p_.?;
    result catch return .disarm;
    if (p.exiting) return .disarm;
    if (p.signaled.swap(false, .acq_rel)) p.stop();
    return .rearm;
}

const Process = struct {
    gpa: Allocator,
    io: Io,
    loop: *xev.Loop,
    uid: posix.uid_t,
    /// Null until `Start`, and once the session has ended or been
    /// destroyed.
    session: ?*Session = null,
    /// The session started.
    started: bool = false,
    /// The listening socket, null once closed.
    listener: ?posix.fd_t = null,
    socket_path: ?[]u8 = null,
    accept_c: xev.Completion = .{},
    cancel_accept_c: xev.Completion = .{},
    peers: std.ArrayList(*Peer) = .empty,
    /// Notified by `watchSignals`.
    signal: xev.Async,
    signal_c: xev.Completion = .{},
    signaled: std.atomic.Value(bool) = .init(false),
    /// The process is done, and the signal wait ends.
    exiting: bool = false,

    /// Nothing is left to serve.
    fn finished(p: *const Process) bool {
        return p.session == null and p.listener == null and p.peers.items.len == 0;
    }

    fn addPeer(p: *Process, fd: posix.fd_t, inherited: bool) !void {
        errdefer unix.close(fd);
        try p.peers.ensureUnusedCapacity(p.gpa, 1);
        const peer = try p.gpa.create(Peer);
        errdefer p.gpa.destroy(peer);
        peer.* = .{ .process = p, .inherited = inherited, .channel = undefined };
        peer.channel = try Channel.create(p.gpa, p.loop, fd, .{
            .context = peer,
            .received = Peer.onReceived,
            .drained = Peer.onDrained,
            .closed = Peer.onClosed,
        });
        p.peers.appendAssumeCapacity(peer);
    }

    fn removePeer(p: *Process, peer: *Peer) void {
        const i = std.mem.indexOfScalar(*Peer, p.peers.items, peer).?;
        _ = p.peers.swapRemove(i);
        p.gpa.destroy(peer);
    }

    /// Starts the session `start` describes, and listens for txd.
    fn start(p: *Process, peer: *Peer, m: proto.Start) void {
        if (p.started) return peer.fail(.protocol, "the session has started");
        p.startSession(m) catch |err| {
            log.warn("session {d}: starting failed: {t}", .{ m.session_id, err });
            return peer.fail(.spawn, "can't start the session");
        };
        p.started = true;
        peer.channel.send(.{ .started = .{ .pid = @intCast(c.getpid()) } });
    }

    fn startSession(p: *Process, m: proto.Start) !void {
        if (m.internal_revision != proto.internal_revision) return error.WrongRevision;

        // `Start` points into the channel's buffer. Host.create copies what
        // it keeps.
        var arena_state: std.heap.ArenaAllocator = .init(p.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var argv: std.ArrayList([]const u8) = .empty;
        var args = std.mem.splitScalar(u8, std.mem.trimEnd(u8, m.argv, "\x00"), 0);
        while (args.next()) |arg| try argv.append(arena, arg);
        if (argv.items.len == 0) return error.NoProgram;
        var environ: std.process.Environ.Map = .init(arena);
        var entries = std.mem.splitScalar(u8, std.mem.trimEnd(u8, m.environ, "\x00"), 0);
        while (entries.next()) |entry| {
            const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
            try environ.put(entry[0..eq], entry[eq + 1 ..]);
        }

        const path = try p.gpa.dupe(u8, m.socket_path);
        errdefer p.gpa.free(path);
        const listener = try unix.listen(path);
        errdefer {
            unix.close(listener);
            unlink(path);
        }

        const size = session_pkg.boundedSize(m.cols, m.rows, session_pkg.cellSize(m.cell_width_px, m.cell_height_px)) orelse
            term.log.Resize{ .cols = 80, .rows = 24 };
        p.session = try Session.create(p.gpa, p.io, p.loop, .{
            .id = m.session_id,
            .argv = argv.items,
            .program = m.program,
            .environ = &environ,
            .cwd = if (m.cwd) |cwd| .{ .path = cwd } else .inherit,
            .size = size,
            .terminal = .{
                .max_scrollback_bytes = if (m.max_scrollback_bytes) |n| @intCast(n) else null,
                .max_scrollback_lines = if (m.max_scrollback_lines) |n| @intCast(n) else null,
                .kitty_image_storage_limit = @intCast(m.kitty_image_storage_limit),
                .log_capacity = @intCast(m.log_capacity),
            },
            .ended = .{ .context = p, .call = onSessionEnded },
        });

        p.listener = listener;
        p.socket_path = path;
        xev.TCP.initFd(listener).accept(p.loop, &p.accept_c, Process, p, onAccept);
    }

    fn onAccept(p_: ?*Process, _: *xev.Loop, _: *xev.Completion, result: xev.AcceptError!xev.TCP) xev.CallbackAction {
        const p = p_.?;
        const socket = result catch |err| {
            // `stopListening` canceled the accept.
            if (err == error.Canceled) {
                unix.close(p.listener.?);
                p.listener = null;
                return .disarm;
            }
            log.warn("accept failed: {t}", .{err});
            return .rearm;
        };

        p.accept(socket.fd) catch |err| log.warn("refused a connection: {t}", .{err});
        return .rearm;
    }

    fn accept(p: *Process, fd: posix.fd_t) !void {
        errdefer unix.close(fd);
        try unix.adopt(fd);
        if (!unix.acceptsPeer(try unix.peerUid(fd), p.uid)) return error.AccessDenied;
        try p.addPeer(fd, false);
    }

    /// No new channels. The socket goes away, and txd stops listing the
    /// session.
    fn stopListening(p: *Process) void {
        if (p.socket_path) |path| unlink(path);
        if (p.listener == null or p.cancel_accept_c.state() == .active) return;
        p.cancel_accept_c = .{ .op = .{ .cancel = .{ .c = &p.accept_c } } };
        p.loop.add(&p.cancel_accept_c);
    }

    /// Ends every channel after what was sent on it.
    fn finishPeers(p: *Process) void {
        // Backwards: a channel that closes at once removes its peer, and
        // the last peer takes its place.
        var i = p.peers.items.len;
        while (i > 0) {
            i -= 1;
            p.peers.items[i].channel.finish();
        }
    }

    /// The program exited and the client, if any, was sent `Exit`. The
    /// session frees itself.
    fn onSessionEnded(context: ?*anyopaque, _: *Session) void {
        const p: *Process = @ptrCast(@alignCast(context.?));
        p.session = null;
        p.stopListening();
        p.finishPeers();
    }

    fn stop(p: *Process) void {
        p.stopListening();
        if (p.session) |s| s.stop() else p.finishPeers();
    }
};

fn unlink(path: []const u8) void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len >= buf.len) return;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    _ = c.unlink(buf[0..path.len :0]);
}

/// A channel from txd.
const Peer = struct {
    process: *Process,
    channel: *Channel,
    /// The socket pair txd started the process with, on which `Start`
    /// comes.
    inherited: bool,
    role: enum {
        /// Before the first message.
        new,
        /// After `Connect`, waiting for `Attach` or `Resume`.
        connected,
        /// The client's `Attach` or `Resume` went to the session.
        client,
        /// `List`, `Kill`, `Dump` or `Inject`.
        control,
    } = .new,
    /// The session holds this channel as its link.
    attached: bool = false,
    /// txd said the client left on purpose (`Detach`).
    left: bool = false,
    connect: proto.Connect = undefined,
    remote_buf: [64]u8 = undefined,
    exporter_buf: [auth.resume_.exporter_len]u8 = undefined,

    fn of(context: *anyopaque) *Peer {
        return @ptrCast(@alignCast(context));
    }

    fn onReceived(context: *anyopaque, _: *Channel, raw: proto.Decoder.Raw) void {
        const peer = of(context);
        const message = raw.decode() catch return peer.fail(.protocol, "malformed message");
        switch (peer.role) {
            .new => peer.first(message),
            .connected => peer.attach(message),
            .client => peer.client(message),
            .control => peer.control(message),
        }
    }

    fn first(peer: *Peer, message: proto.Message) void {
        switch (message) {
            .start => |m| if (peer.inherited) peer.process.start(peer, m) else peer.fail(.protocol, "unexpected message"),
            .connect => |m| {
                if (m.internal_revision != proto.internal_revision)
                    return peer.fail(.revision, "the session runs another version of txd");
                const remote = m.remote[0..@min(m.remote.len, peer.remote_buf.len)];
                @memcpy(peer.remote_buf[0..remote.len], remote);
                peer.connect = m;
                peer.connect.remote = peer.remote_buf[0..remote.len];
                peer.connect.resume_exporter = null;
                if (m.resume_exporter) |e| if (e.len == peer.exporter_buf.len) {
                    @memcpy(&peer.exporter_buf, e);
                    peer.connect.resume_exporter = &peer.exporter_buf;
                };
                peer.role = .connected;
            },
            else => {
                peer.role = .control;
                peer.control(message);
            },
        }
    }

    fn attach(peer: *Peer, message: proto.Message) void {
        const s = peer.process.session orelse return peer.fail(.no_session, "the session has ended");
        const first_message: session_pkg.First = switch (message) {
            .attach => |m| .{ .attach = m },
            .@"resume" => |m| .{ .@"resume" = m },
            else => return peer.fail(.protocol, "unexpected message"),
        };
        peer.role = .client;
        s.connect(peer.link(), peer.connect, first_message);
    }

    fn client(peer: *Peer, message: proto.Message) void {
        if (!peer.attached) return;
        const s = peer.process.session orelse return;
        switch (message) {
            .input, .resize => s.handle(message),
            // The client left, on purpose. Its channel closing detaches it.
            .detach => {
                peer.left = true;
                peer.channel.finish();
            },
            else => {},
        }
    }

    fn control(peer: *Peer, message: proto.Message) void {
        const p = peer.process;
        const s = p.session orelse return peer.fail(.no_session, "the session has ended");
        switch (message) {
            .list => {
                var info = s.info();
                info.pid = @intCast(c.getpid());
                peer.channel.send(.{ .session_info = info });
            },
            .kill => {
                s.kill();
                peer.channel.send(.{ .killed = .{ .session_id = s.id } });
            },
            .dump => {
                const t = &s.host.primary.terminal;
                const state = term.state.dumpAlloc(p.gpa, t) catch return peer.fail(.protocol, "out of memory");
                defer p.gpa.free(state);
                const text = t.plainString(p.gpa) catch return peer.fail(.protocol, "out of memory");
                defer p.gpa.free(text);
                peer.channel.send(.{ .dump_reply = .{ .state = state, .text = text, .cols = t.cols, .rows = t.rows } });
            },
            .inject => |m| s.host.sendInput(m.bytes) catch log.warn("session {d}: input dropped", .{s.id}),
            else => peer.fail(.protocol, "unexpected message"),
        }
    }

    fn fail(peer: *Peer, code: proto.ErrorCode, message: []const u8) void {
        peer.channel.send(.{ .@"error" = .{ .code = @backingInt(code), .message = message } });
        peer.channel.finish();
    }

    fn onDrained(context: *anyopaque, _: *Channel) void {
        const peer = of(context);
        if (!peer.attached) return;
        if (peer.process.session) |s| s.drained();
    }

    /// txd closed the channel, or it was finished.
    fn onClosed(context: *anyopaque, _: *Channel) void {
        const peer = of(context);
        const p = peer.process;
        if (peer.attached) if (p.session) |s| s.disconnect(peer.left);
        p.removePeer(peer);
    }

    fn link(peer: *Peer) session_pkg.Link {
        return .{ .context = peer, .vtable = &link_vtable };
    }

    const link_vtable: session_pkg.Link.VTable = .{
        .send = linkSend,
        .finish = linkFinish,
        .congested = linkCongested,
        .detached = linkDetached,
    };

    fn linkSend(context: *anyopaque, message: proto.Message) void {
        const peer = of(context);
        if (message == .attached) peer.attached = true;
        peer.channel.send(message);
    }

    fn linkFinish(context: *anyopaque) void {
        of(context).channel.finish();
    }

    fn linkCongested(context: *anyopaque) bool {
        return of(context).channel.congested();
    }

    fn linkDetached(context: *anyopaque) void {
        of(context).attached = false;
    }
};

test {
    _ = &run;
}

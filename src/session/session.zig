const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const xev = @import("xev");
const proto = @import("proto");
const auth = @import("auth");
const term = @import("term");
const host_pkg = @import("host.zig");
const Host = host_pkg.Host;
const pty = @import("pty.zig");

const log = std.log.scoped(.session);

// Rebuild frames carry at most this many bytes, to decode under max_message
// (1 MiB) in the channel and the client.
const rebuild_part = 256 << 10;

pub const stop_grace_ms = 1000;

pub const hangup_grace_ms = 5 * 60 * 1000;

const max_cols = 1024;
const max_rows = 1024;

pub fn exitMessage(t: pty.Term) proto.Exit {
    return switch (t) {
        .exited => |code| .{ .status = code },
        .signal => |sig| .{ .status = 128 +| @as(u8, @truncate(@backingInt(sig))), .signal = @tagName(sig) },
        else => .{ .status = 255 },
    };
}

pub fn boundedSize(cols: u16, rows: u16, cell: ?term.log.Resize.CellSize) ?term.log.Resize {
    if (cols == 0 or rows == 0) return null;
    return .{ .cols = @min(cols, max_cols), .rows = @min(rows, max_rows), .cell_size_px = cell };
}

pub fn cellSize(width: ?u32, height: ?u32) ?term.log.Resize.CellSize {
    return .{ .width = width orelse return null, .height = height orelse return null };
}

pub const Link = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (context: *anyopaque, message: proto.Message) void,
        finish: *const fn (context: *anyopaque) void,
        congested: *const fn (context: *anyopaque) bool,
        detached: *const fn (context: *anyopaque) void,
    };

    fn send(l: Link, message: proto.Message) void {
        l.vtable.send(l.context, message);
    }

    fn fail(l: Link, code: proto.ErrorCode, message: []const u8) void {
        l.send(.{ .@"error" = .{ .code = @backingInt(code), .message = message } });
        l.vtable.finish(l.context);
    }
};

pub const Options = struct {
    id: u64,
    argv: []const []const u8,
    program: ?[]const u8 = null,
    environ: *const std.process.Environ.Map,
    cwd: std.process.Child.Cwd = .inherit,
    size: term.log.Resize,
    terminal: host_pkg.Options.TerminalOptions = .{},
    ended: ?Callback = null,

    pub const Callback = struct {
        context: ?*anyopaque,
        call: *const fn (context: ?*anyopaque, s: *Session) void,
    };
};

pub const First = union(enum) {
    attach: proto.Attach,
    @"resume": proto.Resume,
};

pub const Session = struct {
    gpa: Allocator,
    io: Io,
    loop: *xev.Loop,
    id: u64,
    host: *Host,
    ended_callback: ?Options.Callback,
    link: ?Link = null,
    remote_buf: [64]u8 = undefined,
    remote_len: usize = 0,
    /// No client has attached yet. The first one reads the log from its first
    /// record, without a Rebuild.
    fresh: bool = true,
    next_seq: u64 = 0,
    /// A Rebuild to send before more Output. It waits while Primary.rebuild
    /// reports Unfinished.
    rebuild_pending: ?term.rebuild.Kind = null,
    /// Drawn for each connection and sent in Attached. A Resume proves the key
    /// with the exporter secret of its own connection.
    resume_key: [auth.resume_.key_len]u8 = undefined,
    input_offset: u64 = 0,
    paused: bool = false,
    wake: xev.Async,
    wake_c: xev.Completion = .{},
    grace: xev.Timer,
    grace_c: xev.Completion = .{},
    grace_over: bool = false,
    kill_timer: xev.Timer,
    kill_c: xev.Completion = .{},
    hangup: bool = false,
    hangup_timer: xev.Timer,
    hangup_c: xev.Completion = .{},
    hangup_cancel_c: xev.Completion = .{},
    detached_at: Io.Timestamp = .zero,
    started: Io.Timestamp,
    ended: bool = false,

    /// Starts the program. The session frees itself after the program has
    /// exited and Options.ended has been called. After stop, the owner
    /// destroys it once stopped() is true.
    pub fn create(gpa: Allocator, io: Io, loop: *xev.Loop, options: Options) !*Session {
        const s = try gpa.create(Session);
        errdefer gpa.destroy(s);
        var wake: xev.Async = try .init();
        errdefer wake.deinit();
        var grace: xev.Timer = try .init();
        errdefer grace.deinit();
        var kill_timer: xev.Timer = try .init();
        errdefer kill_timer.deinit();
        var hangup_timer: xev.Timer = try .init();
        errdefer hangup_timer.deinit();

        s.* = .{
            .gpa = gpa,
            .io = io,
            .loop = loop,
            .id = options.id,
            .host = undefined,
            .ended_callback = options.ended,
            .started = Io.Clock.boot.now(io),
            .wake = wake,
            .grace = grace,
            .kill_timer = kill_timer,
            .hangup_timer = hangup_timer,
        };
        s.host = try Host.create(gpa, io, .{
            .argv = options.argv,
            .program = options.program,
            .environ = options.environ,
            .cwd = options.cwd,
            .size = options.size,
            .terminal = options.terminal,
            .notify = onHostNotify,
            .context = s,
        });

        s.wake.wait(loop, &s.wake_c, Session, s, onWake);
        return s;
    }

    pub fn destroy(s: *Session) void {
        s.host.destroy();
        s.wake.deinit();
        s.grace.deinit();
        s.kill_timer.deinit();
        s.hangup_timer.deinit();
        s.gpa.destroy(s);
    }

    pub fn attached(s: *const Session) bool {
        return s.link != null;
    }

    /// Attaches link, and takes the session from any other client, which gets
    /// an Error. A Resume whose proof fails is refused. The client gets
    /// Attached, then Output from the log or a Rebuild of the screen.
    pub fn connect(s: *Session, link: Link, c: proto.Connect, first: First) void {
        const size = boundedSize(c.cols, c.rows, cellSize(c.cell_width_px, c.cell_height_px)) orelse
            term.log.Resize{ .cols = 80, .rows = 24 };
        const remote = c.remote[0..@min(c.remote.len, s.remote_buf.len)];

        if (first == .attach) {
            s.host.setColors(first.attach);
            if (s.fresh) s.hangup = first.attach.hangup;
        }

        const start: Start, const how: How = switch (first) {
            .attach => if (s.fresh) .{ .new, .attached } else .{ .{ .rebuild = .attach }, .attached },
            .@"resume" => |m| start: {
                // txd puts the exporter secret of the client's connection in
                // Connect. A proof made on another connection fails.
                const exporter = c.resume_exporter orelse &.{};
                if (exporter.len != auth.resume_.exporter_len or
                    !auth.resume_.verify(&s.resume_key, exporter[0..auth.resume_.exporter_len], s.id, m.proof))
                {
                    log.info("{s} failed to resume session {d}", .{ remote, s.id });
                    return link.fail(.auth, "can't resume the session");
                }
                log.info("{s} resumed session {d}", .{ remote, s.id });

                const seq = m.next_seq orelse break :start .{ .{ .rebuild = .repaint }, .resumed };
                break :start if (s.canContinue(seq, size))
                    .{ .{ .continue_from = seq }, .resumed }
                else
                    .{ .{ .rebuild = .repaint }, .resumed };
            },
        };

        if (s.link) |other| {
            s.detach();
            other.fail(.attached_elsewhere, "the session was attached elsewhere");
            other.vtable.detached(other.context);
        }

        s.attach(link, remote);
        if (how == .attached) s.input_offset = 0;
        link.send(.{ .attached = .{ .session_id = s.id, .resume_key = &s.resume_key, .input_offset = s.input_offset } });
        switch (start) {
            .new => {},
            .rebuild => |kind| s.rebuild_pending = kind,
            .continue_from => |seq| s.next_seq = seq,
        }

        if (start != .new) {
            const t = &s.host.primary.terminal;
            if (t.cols != size.cols or t.rows != size.rows) s.resize(size);
        }
        s.pump();
    }

    const Start = union(enum) {
        new,
        rebuild: term.rebuild.Kind,
        continue_from: u64,
    };

    const How = enum { attached, resumed };

    pub fn handle(s: *Session, message: proto.Message) void {
        switch (message) {
            .input => |m| {
                s.host.sendInput(m.bytes) catch log.warn("session {d}: input dropped", .{s.id});
                s.input_offset += m.bytes.len;
            },
            .resize => |m| if (boundedSize(m.cols, m.rows, cellSize(m.cell_width_px, m.cell_height_px))) |size| s.resize(size),
            else => {},
        }
    }

    pub fn disconnect(s: *Session, left: bool) void {
        s.detach();
        if (!s.hangup) return;
        if (left) return s.hangUp();

        // A timer started by an earlier loss may be running. It reads
        // detached_at when it fires.
        s.detached_at = Io.Clock.boot.now(s.io);
        if (s.hangup_c.state() != .active) s.hangup_timer.run(s.loop, &s.hangup_c, hangup_grace_ms, Session, s, onHangupTimer);
    }

    fn hangUp(s: *Session) void {
        if (s.ended) return;
        log.info("session {d}: its client is gone, so its program gets SIGHUP", .{s.id});
        s.host.pty.killGroup(.HUP) catch {};
    }

    fn onHangupTimer(s_: ?*Session, _: *xev.Loop, _: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
        const s = s_.?;
        result catch {
            s.freeIfEnded();
            return .disarm;
        };
        if (s.ended or s.link != null) {
            s.freeIfEnded();
            return .disarm;
        }

        // The timer may date from an earlier loss. It runs again for the time
        // left after the latest one.
        const gone_ms = s.detached_at.durationTo(Io.Clock.boot.now(s.io)).toMilliseconds();
        if (gone_ms < hangup_grace_ms) {
            s.hangup_timer.run(s.loop, &s.hangup_c, @intCast(hangup_grace_ms - gone_ms), Session, s, onHangupTimer);
            return .disarm;
        }
        s.hangUp();
        return .disarm;
    }

    pub fn drained(s: *Session) void {
        if (!s.paused) return;
        s.paused = false;
        s.process();
    }

    pub fn info(s: *const Session) proto.SessionInfo {
        const t = &s.host.primary.terminal;
        return .{
            .session_id = s.id,
            .cols = t.cols,
            .rows = t.rows,
            .running_s = @intCast(@divTrunc(s.started.durationTo(Io.Clock.boot.now(s.io)).nanoseconds, std.time.ns_per_s)),
            .attached_from = if (s.link != null) s.remote_buf[0..s.remote_len] else null,
            .title = t.getTitle(),
        };
    }

    fn attach(s: *Session, link: Link, remote: []const u8) void {
        s.link = link;
        s.fresh = false;
        @memcpy(s.remote_buf[0..remote.len], remote);
        s.remote_len = remote.len;
        s.next_seq = 0;
        s.io.random(&s.resume_key);

        s.host.answer_queries = false;
    }

    fn detach(s: *Session) void {
        s.link = null;
        s.rebuild_pending = null;
        s.host.answer_queries = true;

        s.drained();
    }

    fn resize(s: *Session, size: term.log.Resize) void {
        s.host.resize(size) catch |err| log.warn("session {d}: resize failed: {t}", .{ s.id, err });
    }

    fn pump(s: *Session) void {
        const link = s.link orelse return;
        if (s.rebuild_pending) |kind| {
            s.sendRebuild(link, kind);
            if (s.rebuild_pending != null) return;
        }

        var it = s.host.primary.log.iterator(s.next_seq) catch {
            return link.fail(.log_trimmed, "the client fell behind the session's log");
        };

        while (it.next()) |record| {
            switch (record.payload) {
                .output => |bytes| link.send(.{ .output = .{ .seq = record.seq, .bytes = bytes } }),
                .resize => {},
            }
            s.next_seq = record.seq + 1;
        }

        // While paused, output stays queued in the Host, whose thread stops
        // reading the pty at output_limit.
        if (link.vtable.congested(link.context)) s.paused = true;
    }

    /// The client can continue from seq when the log still holds seq, and
    /// every resize from seq on is to the client's size.
    fn canContinue(s: *const Session, seq: u64, size: term.log.Resize) bool {
        var it = s.host.primary.log.iterator(seq) catch return false;
        while (it.next()) |record| switch (record.payload) {
            .output => {},
            .resize => |r| if (r.cols != size.cols or r.rows != size.rows) return false,
        };
        return true;
    }

    fn sendRebuild(s: *Session, link: Link, kind: term.rebuild.Kind) void {
        var out: Io.Writer.Allocating = .init(s.gpa);
        defer out.deinit();
        s.host.primary.rebuild(&out.writer, kind) catch |err| switch (err) {
            error.Unfinished => return,
            error.WriteFailed => {
                log.warn("session {d}: rebuild failed: out of memory", .{s.id});
                return link.fail(.protocol, "out of memory");
            },
        };
        s.rebuild_pending = null;
        s.next_seq = s.host.primary.log.nextSeq();

        var rest = out.written();
        while (rest.len > 0) {
            const part = rest[0..@min(rest.len, rebuild_part)];
            link.send(.{ .rebuild = .{ .seq = s.next_seq, .bytes = part } });
            rest = rest[part.len..];
        }
    }

    fn process(s: *Session) void {
        if (s.paused or s.ended) return;

        s.host.processOutput() catch |err| log.warn("session {d}: output dropped: {t}", .{ s.id, err });
        s.pump();

        if (s.host.finished) s.reap();
    }

    /// Called on the host thread. The Async wakes the loop thread, which runs
    /// onWake.
    fn onHostNotify(context: ?*anyopaque) void {
        const s: *Session = @ptrCast(@alignCast(context.?));
        s.wake.notify() catch |err| log.warn("session {d}: wakeup failed: {t}", .{ s.id, err });
    }

    fn onWake(s_: ?*Session, _: *xev.Loop, _: *xev.Completion, result: xev.Async.WaitError!void) xev.CallbackAction {
        const s = s_.?;
        result catch |err| log.warn("session {d}: wakeup failed: {t}", .{ s.id, err });

        // After stop's grace period, output is left alone and the wait ends,
        // so that stopped() can see every completion dead.
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

        s.end(exitMessage(t));
    }

    fn end(s: *Session, exit: proto.Exit) void {
        if (exit.signal) |name| {
            log.info("session {d}: its program was killed by SIG{s}", .{ s.id, name });
        } else {
            log.info("session {d}: its program exited with status {d}", .{ s.id, exit.status });
        }

        if (s.link) |link| {
            link.send(.{ .exit = exit });
            link.vtable.finish(link.context);
            link.vtable.detached(link.context);
        }
        s.link = null;
        s.ended = true;
        if (s.ended_callback) |cb| cb.call(cb.context, s);

        if (s.hangup_c.state() == .active and s.hangup_cancel_c.state() != .active) {
            s.hangup_cancel_c = .{ .op = .{ .cancel = .{ .c = &s.hangup_c } } };
            s.loop.add(&s.hangup_cancel_c);
        }

        s.wake.notify() catch {};
    }

    /// Sends the program SIGHUP. After stop_grace_ms, stopped() turns true and
    /// the owner destroys the session, which kills the program.
    pub fn stop(s: *Session) void {
        if (s.ended) return;

        s.host.pty.kill(.HUP) catch {};
        s.grace.run(s.loop, &s.grace_c, stop_grace_ms, Session, s, onGraceOver);
    }

    pub fn stopped(s: *const Session) bool {
        return s.grace_over and !s.ended and s.wake_c.state() == .dead and s.grace_c.state() == .dead and s.kill_c.state() == .dead and s.hangup_c.state() == .dead;
    }

    pub fn kill(s: *Session) void {
        if (s.ended or s.kill_c.state() == .active) return;
        s.host.pty.kill(.HUP) catch {};
        s.kill_timer.run(s.loop, &s.kill_c, stop_grace_ms, Session, s, onKillTimer);
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
        s.wake.notify() catch {};
        s.freeIfEnded();
        return .disarm;
    }

    /// Frees the session once it has ended and no completion is pending. Each
    /// callback calls it before it disarms; libxev marks a completion dead
    /// before it runs the callback.
    fn freeIfEnded(s: *Session) void {
        if (s.ended and s.wake_c.state() == .dead and s.grace_c.state() == .dead and s.kill_c.state() == .dead and
            s.hangup_c.state() == .dead and s.hangup_cancel_c.state() == .dead) s.destroy();
    }
};

const testing = std.testing;

const test_timeout_ms = 10_000;

const TestLink = struct {
    types: std.ArrayList(std.meta.Tag(proto.Message)) = .empty,
    output: std.ArrayList(u8) = .empty,
    resume_key: [auth.resume_.key_len]u8 = undefined,
    error_code: ?u32 = null,
    exit: ?u8 = null,
    finished: bool = false,
    detached: bool = false,

    const vtable: Link.VTable = .{ .send = send, .finish = finish, .congested = congested, .detached = onDetached };

    fn link(t: *TestLink) Link {
        return .{ .context = t, .vtable = &vtable };
    }

    fn deinit(t: *TestLink) void {
        t.types.deinit(testing.allocator);
        t.output.deinit(testing.allocator);
    }

    fn of(context: *anyopaque) *TestLink {
        return @ptrCast(@alignCast(context));
    }

    fn send(context: *anyopaque, message: proto.Message) void {
        const t = of(context);
        if (t.finished) return;
        t.types.append(testing.allocator, message) catch @panic("OOM");
        switch (message) {
            .attached => |m| @memcpy(&t.resume_key, m.resume_key),
            .output => |m| t.output.appendSlice(testing.allocator, m.bytes) catch @panic("OOM"),
            .rebuild => |m| t.output.appendSlice(testing.allocator, m.bytes) catch @panic("OOM"),
            .@"error" => |m| t.error_code = m.code,
            .exit => |m| t.exit = m.status,
            else => {},
        }
    }

    fn finish(context: *anyopaque) void {
        of(context).finished = true;
    }

    fn congested(_: *anyopaque) bool {
        return false;
    }

    fn onDetached(context: *anyopaque) void {
        of(context).detached = true;
    }

    fn got(t: *const TestLink, tag: std.meta.Tag(proto.Message)) bool {
        return std.mem.indexOfScalar(std.meta.Tag(proto.Message), t.types.items, tag) != null;
    }
};

const TestSession = struct {
    loop: xev.Loop,
    environ: std.process.Environ.Map,
    session: *Session,
    ended: bool = false,

    fn init(t: *TestSession, script: []const u8) !void {
        t.* = .{ .loop = try .init(.{}), .environ = .init(testing.allocator), .session = undefined };
        try t.environ.put("PATH", testing.environ.getPosix("PATH") orelse "/usr/bin:/bin");
        try t.environ.put("TERM", "xterm-256color");
        t.session = try Session.create(testing.allocator, testing.io, &t.loop, .{
            .id = 7,
            .argv = &.{ "/bin/sh", "-c", script },
            .environ = &t.environ,
            .size = .{ .cols = 80, .rows = 24 },
            .ended = .{ .context = t, .call = onEnded },
        });
    }

    fn deinit(t: *TestSession) void {
        if (!t.ended) {
            t.session.disconnect(false);
            t.session.kill();
            t.runUntil(endedCheck) catch {};
        }
        t.loop.run(.until_done) catch {};
        t.environ.deinit();
        t.loop.deinit();
    }

    fn onEnded(context: ?*anyopaque, _: *Session) void {
        const t: *TestSession = @ptrCast(@alignCast(context.?));
        t.ended = true;
    }

    fn endedCheck(t: *TestSession) bool {
        return t.ended;
    }

    fn runUntil(t: *TestSession, done: *const fn (*TestSession) bool) !void {
        const deadline = Io.Clock.awake.now(testing.io).toMilliseconds() + test_timeout_ms;
        while (!done(t)) {
            if (Io.Clock.awake.now(testing.io).toMilliseconds() > deadline) return error.Timeout;
            try t.loop.run(.no_wait);
            try testing.io.sleep(.fromMilliseconds(1), .awake);
        }
    }

    fn connect(t: *TestSession, link: *TestLink, first: First, resume_exporter: ?[]const u8) void {
        t.session.connect(link.link(), .{ .remote = "test", .cols = 80, .rows = 24, .resume_exporter = resume_exporter }, first);
    }
};

test "the first client gets the output from the first record, then Exit" {
    var t: TestSession = undefined;
    try t.init("printf ready");
    defer t.deinit();
    var link: TestLink = .{};
    defer link.deinit();

    t.connect(&link, .{ .attach = .{} }, null);
    try t.runUntil(TestSession.endedCheck);

    try testing.expectEqual(.attached, link.types.items[0]);
    try testing.expect(!link.got(.rebuild));
    try testing.expectEqualStrings("ready", link.output.items);
    try testing.expectEqual(0, link.exit);
    try testing.expect(link.finished and link.detached);
}

test "a newer attach takes the session, and the older client is told" {
    var t: TestSession = undefined;
    try t.init("printf ready; sleep 10");
    defer t.deinit();
    var first: TestLink = .{};
    defer first.deinit();
    var second: TestLink = .{};
    defer second.deinit();

    t.connect(&first, .{ .attach = .{} }, null);
    t.connect(&second, .{ .attach = .{} }, null);

    try testing.expectEqual(@backingInt(proto.ErrorCode.attached_elsewhere), first.error_code);
    try testing.expect(first.finished and first.detached);
    try testing.expectEqual(.attached, second.types.items[0]);
    try testing.expect(second.got(.rebuild));
    try testing.expect(t.session.attached());
}

test "a resume needs the proof for its connection, and continues from its seq" {
    var t: TestSession = undefined;
    try t.init("printf ready; sleep 10");
    defer t.deinit();
    var first: TestLink = .{};
    defer first.deinit();
    t.connect(&first, .{ .attach = .{} }, null);
    try t.runUntil(struct {
        fn f(ts: *TestSession) bool {
            return ts.session.next_seq > 0;
        }
    }.f);
    const seq = t.session.next_seq;
    t.session.disconnect(false);

    const exporter: [auth.resume_.exporter_len]u8 = @splat(1);
    const other: [auth.resume_.exporter_len]u8 = @splat(2);
    var refused: TestLink = .{};
    defer refused.deinit();
    t.connect(&refused, .{ .@"resume" = .{ .session_id = 7, .next_seq = seq, .proof = &auth.resume_.proof(&first.resume_key, &other, 7) } }, &exporter);
    try testing.expectEqual(@backingInt(proto.ErrorCode.auth), refused.error_code);
    try testing.expect(!t.session.attached());

    var resumed: TestLink = .{};
    defer resumed.deinit();
    t.connect(&resumed, .{ .@"resume" = .{ .session_id = 7, .next_seq = seq, .proof = &auth.resume_.proof(&first.resume_key, &exporter, 7) } }, &exporter);
    try testing.expectEqual(.attached, resumed.types.items[0]);
    try testing.expect(!resumed.got(.rebuild));
    try testing.expect(t.session.attached());
}

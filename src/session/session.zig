//! A session: a program on a pseudo-terminal with its primary terminal and
//! output log (see `host`), and the client attached to it, if any.
//!
//! The session reaches its client through a `Link`, in protocol messages.
//! txd hands it a `Connect` describing the client, then the client's
//! `Attach` or `Resume`, then the client's `Input` and `Resize`. The
//! session answers with `Attached`, `Rebuild` and `Output`, and `Exit` once
//! the program exits.
//!
//! The first client of a new session gets the output from the first
//! record. A later attach resizes the session to the client's terminal and
//! gets `Rebuild`, bytes generated from the primary terminal's state (see
//! `term.rebuild`), then the records that follow. A `Resume` proves the
//! client holds the session's resume key (see `auth.resume_`); its output
//! continues from the first record the client hasn't written, or it gets a
//! repaint when the log no longer holds that record.
//!
//! One client is attached at a time. A newer attach wins, and the older
//! client gets `Error` with `attached_elsewhere`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const xev = @import("xev");
const proto = @import("proto");
const auth = @import("auth");
const term = @import("term");
const host_pkg = @import("host.zig");
const Host = host_pkg.Host;

const log = std.log.scoped(.session);

/// The most rebuild bytes sent in one message. Well below the client's
/// message limit.
const rebuild_part = 256 << 10;

/// How long `stop` and `kill` give a program to exit after SIGHUP.
pub const stop_grace_ms = 1000;

/// Bounds on a client's terminal size. libghostty-vt asserts on zero, and
/// the size sets how much memory the primary terminal allocates.
const max_cols = 1024;
const max_rows = 1024;

/// A client's size within bounds, or null to ignore it.
pub fn boundedSize(cols: u16, rows: u16, cell: ?term.log.Resize.CellSize) ?term.log.Resize {
    if (cols == 0 or rows == 0) return null;
    return .{ .cols = @min(cols, max_cols), .rows = @min(rows, max_rows), .cell_size_px = cell };
}

/// Null unless both are present.
pub fn cellSize(width: ?u32, height: ?u32) ?term.log.Resize.CellSize {
    return .{ .width = width orelse return null, .height = height orelse return null };
}

/// How a session reaches its attached client.
pub const Link = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Sends `message`, copying it. Nothing is sent after `finish`.
        send: *const fn (context: *anyopaque, message: proto.Message) void,
        /// Ends the link after what was sent. The client leaves once it has
        /// read it.
        finish: *const fn (context: *anyopaque) void,
        /// The client is behind. The session stops processing the program's
        /// output until `Session.drained`.
        congested: *const fn (context: *anyopaque) bool,
        /// The session let go of the link, after `Exit` or a takeover. No
        /// more calls follow.
        detached: *const fn (context: *anyopaque) void,
    };

    fn send(l: Link, message: proto.Message) void {
        l.vtable.send(l.context, message);
    }

    /// Sends `Error` and finishes the link.
    fn fail(l: Link, code: proto.ErrorCode, message: []const u8) void {
        l.send(.{ .@"error" = .{ .code = @backingInt(code), .message = message } });
        l.vtable.finish(l.context);
    }
};

pub const Options = struct {
    id: u64,
    /// See `host.Options`.
    argv: []const []const u8,
    program: ?[]const u8 = null,
    environ: *const std.process.Environ.Map,
    cwd: std.process.Child.Cwd = .inherit,
    size: term.log.Resize,
    terminal: host_pkg.Options.TerminalOptions = .{},
    /// Called once the program has exited and the client got `Exit`. The
    /// session frees itself after.
    ended: ?Callback = null,

    pub const Callback = struct {
        context: ?*anyopaque,
        call: *const fn (context: ?*anyopaque, s: *Session) void,
    };
};

/// What follows a client's `Connect`.
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
    /// The attached client's address, from `Connect`.
    remote_buf: [64]u8 = undefined,
    remote_len: usize = 0,
    /// No client has attached yet.
    fresh: bool = true,
    /// The next log seq to send to the client.
    next_seq: u64 = 0,
    /// The client gets a rebuild of this kind before any output.
    rebuild_pending: ?term.rebuild.Kind = null,
    /// Proves a client was the last to attach (see `auth.resume_`).
    resume_key: [auth.resume_.key_len]u8 = undefined,
    /// Bytes of input from the client since it attached, counted across
    /// its resumes.
    input_offset: u64 = 0,
    /// Output processing stopped because the link is congested. The host's
    /// thread stops reading the pty once its queue fills.
    paused: bool = false,
    /// Notified by the host's thread.
    wake: xev.Async,
    wake_c: xev.Completion = .{},
    grace: xev.Timer,
    grace_c: xev.Completion = .{},
    /// `stop` was called and the grace period is over.
    grace_over: bool = false,
    /// Sends SIGKILL after `kill`.
    kill_timer: xev.Timer,
    kill_c: xev.Completion = .{},
    /// On `Io.Clock.boot`.
    started: Io.Timestamp,
    /// The program exited and the client got `Exit`.
    ended: bool = false,

    /// Starts the program. The session must not move while the loop runs.
    pub fn create(gpa: Allocator, io: Io, loop: *xev.Loop, options: Options) !*Session {
        const s = try gpa.create(Session);
        errdefer gpa.destroy(s);
        var wake: xev.Async = try .init();
        errdefer wake.deinit();
        var grace: xev.Timer = try .init();
        errdefer grace.deinit();
        var kill_timer: xev.Timer = try .init();
        errdefer kill_timer.deinit();

        // The host's thread can notify as soon as it starts. `wake` has to
        // exist first.
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

        // A notification sent before this is kept by the Async.
        s.wake.wait(loop, &s.wake_c, Session, s, onWake);
        return s;
    }

    /// Kills the program if it is still running.
    pub fn destroy(s: *Session) void {
        // First, since the host's thread notifies `wake` until it is joined.
        s.host.destroy();
        s.wake.deinit();
        s.grace.deinit();
        s.kill_timer.deinit();
        s.gpa.destroy(s);
    }

    pub fn attached(s: *const Session) bool {
        return s.link != null;
    }

    /// Attaches the client that `connect` describes, as `first` asks. A
    /// `Resume` whose proof doesn't verify fails the link.
    pub fn connect(s: *Session, link: Link, c: proto.Connect, first: First) void {
        const size = boundedSize(c.cols, c.rows, cellSize(c.cell_width_px, c.cell_height_px)) orelse
            term.log.Resize{ .cols = 80, .rows = 24 };
        const remote = c.remote[0..@min(c.remote.len, s.remote_buf.len)];

        const start: Start, const how: How = switch (first) {
            .attach => if (s.fresh) .{ .new, .attached } else .{ .{ .rebuild = .attach }, .attached },
            .@"resume" => |m| start: {
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

        // The newer attach wins. The other client is told, so that it
        // doesn't resume. When it is this client's own connection that was
        // lost, nobody reads the error.
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

        // A running session is resized to the client's terminal. The
        // program redraws at that size, in output that follows.
        if (start != .new) {
            const t = &s.host.primary.terminal;
            if (t.cols != size.cols or t.rows != size.rows) s.resize(size);
        }
        s.pump();
    }

    const Start = union(enum) {
        /// The first client of the session. Its output goes from the first
        /// record.
        new,
        /// Output from the session's next record, after a rebuild.
        rebuild: term.rebuild.Kind,
        /// Output from `seq`, which the log holds.
        continue_from: u64,
    };

    /// `.resumed` keeps counting the client's input from where its last
    /// connection left off.
    const How = enum { attached, resumed };

    /// The attached client's `Input` and `Resize`. Others are ignored.
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

    /// The attached client went away. The session keeps running.
    pub fn disconnect(s: *Session) void {
        s.detach();
    }

    /// The link is no longer congested.
    pub fn drained(s: *Session) void {
        if (!s.paused) return;
        s.paused = false;
        s.process();
    }

    /// `SessionInfo` for `List`. Its strings point into the session, and
    /// change with the next output.
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

        // The client's terminal answers queries now.
        s.host.answer_queries = false;
    }

    fn detach(s: *Session) void {
        s.link = null;
        s.rebuild_pending = null;
        s.host.answer_queries = true;

        // No link is backed up now. Output keeps flowing while detached.
        s.drained();
    }

    fn resize(s: *Session, size: term.log.Resize) void {
        s.host.resize(size) catch |err| log.warn("session {d}: resize failed: {t}", .{ s.id, err });
    }

    /// Sends the client the rebuild it is owed, then the log records it
    /// hasn't seen. Resize records are skipped: the client's terminal is
    /// already at the size it asked for.
    fn pump(s: *Session) void {
        const link = s.link orelse return;
        if (s.rebuild_pending) |kind| {
            s.sendRebuild(link, kind);
            // The output ends inside a long sequence. The next output may
            // finish it.
            if (s.rebuild_pending != null) return;
        }

        // The log dropped records the client hasn't been sent.
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

        // The link copies what it's given. A client that doesn't keep up
        // would grow it without bound.
        if (link.vtable.congested(link.context)) s.paused = true;
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

        // After the grace period, the session is left for its owner to
        // destroy.
        if (!s.grace_over) s.process();

        // Disarming is what lets the loop finish after `stop`.
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
        if (s.link) |link| {
            link.send(.{ .exit = exit });
            link.vtable.finish(link.context);
            link.vtable.detached(link.context);
        }
        s.link = null;
        s.ended = true;
        if (s.ended_callback) |cb| cb.call(cb.context, s);

        // `end` may run outside `onWake`, from `drained`. The notification
        // makes `onWake` run and free the session.
        s.wake.notify() catch {};
    }

    /// Sends the program SIGHUP. A program that exits within the grace
    /// period ends its session as usual.
    pub fn stop(s: *Session) void {
        if (s.ended) return;

        // Only the program gets it. Its jobs get SIGHUP from the shell, or
        // from the terminal closing in `Host.destroy`.
        s.host.pty.kill(.HUP) catch {};
        s.grace.run(s.loop, &s.grace_c, stop_grace_ms, Session, s, onGraceOver);
    }

    /// After `stop`: the grace period is over and the program still runs.
    /// The owner destroys the session, which kills it.
    pub fn stopped(s: *const Session) bool {
        return s.grace_over and !s.ended and s.wake_c.state() == .dead and s.grace_c.state() == .dead and s.kill_c.state() == .dead;
    }

    /// Sends the program SIGHUP, and SIGKILL if it is still running after
    /// the grace period.
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
        // Ends the `wake` wait. The loop can then finish.
        s.wake.notify() catch {};
        s.freeIfEnded();
        return .disarm;
    }

    /// Frees an ended session once no completion holds a pointer to it. A
    /// session that hasn't ended is destroyed by its owner.
    fn freeIfEnded(s: *Session) void {
        if (s.ended and s.wake_c.state() == .dead and s.grace_c.state() == .dead and s.kill_c.state() == .dead) s.destroy();
    }
};

const testing = std.testing;

const test_timeout_ms = 10_000;

/// A link that keeps what the session sends.
const TestLink = struct {
    /// The type of each message, in order.
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

    /// Kills a program still running, and runs the loop until the session
    /// is freed. The links may be gone already, so the client is detached
    /// first.
    fn deinit(t: *TestSession) void {
        if (!t.ended) {
            t.session.disconnect();
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
    t.session.disconnect();

    // A proof made for another connection's exporter.
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

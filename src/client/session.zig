const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const posix = std.posix;
const xev = @import("xev");
const transport = @import("transport");
const proto = @import("proto");
const auth = @import("auth");
const Wake = @import("wake").Wake;
const tty = @import("tty.zig");
const escape = @import("escape.zig");
const report = @import("report.zig");
const passphrase = @import("passphrase.zig");
const connect = @import("connect.zig");
const clipboard = @import("clipboard.zig");

const Endpoint = transport.endpoint.Endpoint;
const Conn = transport.endpoint.Conn;
const Stream = transport.endpoint.Stream;
const CloseReason = transport.endpoint.CloseReason;

const log = std.log.scoped(.client);

pub const Options = struct {
    servers: []const IpAddress,
    host_keys: []const [32]u8,
    /// Empty logs in as the account txd runs as.
    user: []const u8 = "",
    /// Probed in order; the first one the server accepts signs the login.
    /// Must not be empty.
    identities: []const Identity,
    agent: ?[]const u8 = null,
    /// Asks for a key file's passphrase, on the signing thread. Returns null
    /// to cancel, and must return once cancel_fd is readable.
    passphrase: *const fn (path: []const u8, buf: []u8, cancel_fd: posix.fd_t) ?[]u8 = askPassphrase,
    show_session_id: bool = false,
    command: Command = .attach,
    session_id: ?u64 = null,
    session_command: ?[]const u8 = null,
    reuse_detached: bool = false,
    in_fd: posix.fd_t = posix.STDIN_FILENO,
    out_fd: posix.fd_t = posix.STDOUT_FILENO,
    err_fd: posix.fd_t = posix.STDERR_FILENO,
    term: []const u8,
    colorterm: ?[]const u8 = null,
    terminfo: ?[]const u8 = null,
    colors: report.Colors = .{},
    typed: []const u8 = "",
    locale: ?[]const u8 = null,
    escape_char: ?u8 = '~',
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
    handshake_timeout_ns: ?u64 = null,
    keep_alive_ns: u64 = 2 * std.time.ns_per_s,
    /// While attached, a connection that receives nothing for this long is
    /// closed, and the session resumed on a new one.
    silence_timeout_ns: u64 = 6 * std.time.ns_per_s,
    notice_delay_ms: u64 = 3000,
    clipboard: ?clipboard.Provider = null,
};

pub const Command = union(enum) {
    attach,
    list,
    kill: u64,
    exec: []const u8,
};

pub const Identity = struct {
    key: auth.ssh.PublicKey,
    source: union(enum) {
        agent,
        file: []const u8,
    },
};

fn askPassphrase(path: []const u8, buf: []u8, cancel_fd: posix.fd_t) ?[]u8 {
    var prompt_buf: [std.fs.max_path_bytes + 64]u8 = undefined;
    const prompt = std.fmt.bufPrint(&prompt_buf, "Enter passphrase for key '{s}': ", .{path}) catch "Enter passphrase: ";
    return passphrase.ask(prompt, buf, cancel_fd) catch null;
}

pub const Outcome = union(enum) {
    exited: Exit,
    detached: ?u64,
    no_connection: CloseReason,
    disconnected: CloseReason,
    host_key_refused: [32]u8,
    refused: Refusal,
    /// Allocated with run's gpa; the caller frees it.
    listed: []Listed,
    killed: u64,
    ended,

    pub const Listed = struct {
        session_id: u64,
        cols: u16,
        rows: u16,
        running_s: u64,
        attached_from: ?Name,
        title: ?Name,
    };

    pub const Exit = struct {
        status: u8,
        signal: ?Name = null,
    };

    pub const Refusal = struct {
        code: u32,
        message: Name,
    };

    pub const Name = struct {
        buf: [max_len]u8 = undefined,
        len: usize = 0,

        pub const max_len = 256;

        fn init(text: []const u8) Name {
            var name: Name = .{ .len = @min(text.len, max_len) };
            @memcpy(name.buf[0..name.len], text[0..name.len]);
            return name;
        }

        pub fn slice(name: *const Name) []const u8 {
            return name.buf[0..name.len];
        }
    };
};

// The capacity exceeds high_water plus stream_window. Above high water a
// stream's bytes stay unconsumed, so flow control stops the server before
// the queue fills.
const writer_options = .{
    .capacity = 4 << 20,
    .high_water = 1 << 20,
    .low_water = 256 << 10,
};

const stream_window = 2 << 20;

const max_pending_stdin = 256 << 10;

const stdin_high_water = 1 << 20;

// The largest message body on the main stream. The session's Rebuild parts
// (rebuild_part, 256 KiB) and Output records fit.
const max_message = 1 << 20;

const retry_delays_ms = [_]u64{ 0, 1000, 2000, 4000, 8000 };

const reconnect_handshake_timeout_ns = 5 * std.time.ns_per_s;

const max_held_input = 64 << 10;

const max_sent_input = 64 << 10;

const silence_check_ms = 500;

const max_copy_header = 16 << 10;

fn nowMs(io: Io) i64 {
    return Io.Clock.awake.now(io).toMilliseconds();
}

pub fn run(gpa: Allocator, io: Io, options: Options) !Outcome {
    std.debug.assert(options.identities.len > 0);
    transport.crypto.init(io);

    // The threads started below inherit the mask, and tty.Signals waits
    // for these signals.
    const old_mask = tty.blockSignals();
    defer {
        var ignored: posix.sigset_t = undefined;
        _ = std.c.pthread_sigmask(posix.SIG.SETMASK, &old_mask, &ignored);
    }

    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();

    // Threads and callbacks hold pointers to r, so it stays in this frame.
    var r: Run = undefined;
    try r.init(gpa, io, &loop, options);
    defer r.deinit();

    while (r.outcome == null) try loop.run(.once);
    if (r.failure) |err| return err;
    return r.outcome.?;
}

const Run = struct {
    gpa: Allocator,
    io: Io,
    loop: *xev.Loop,
    options: Options,
    size: tty.Size,
    /// The current race. Earlier racers wait in retired until their
    /// endpoints have stopped.
    racer: *connect.Racer,
    retired: std.ArrayList(*connect.Racer) = .empty,
    conn: ?*Conn = null,
    /// The terminal's attributes, saved at init for attach. Raw mode starts
    /// after the login.
    raw: ?tty.RawMode,
    terminal: bool = false,
    hello_size: tty.Size = undefined,
    stream: ?*Stream = null,
    decoder: proto.Decoder,
    escape: escape.Escape,

    /// The tty, signal and signing threads post here and notify wake, and
    /// onWake takes their events on the loop.
    inbox: Inbox = .{},
    wake: xev.Async,
    wake_c: xev.Completion = .{},
    writer: tty.Writer = undefined,
    reader: tty.Reader = undefined,
    signals: tty.Signals = undefined,
    held: usize = 0,
    session_id: ?u64 = null,
    /// From the last Attached. Once it's set, a lost connection is resumed.
    resume_key: ?[auth.resume_.key_len]u8 = null,
    next_seq: u64 = 0,
    attached: bool = false,
    listing: std.ArrayList(Outcome.Listed) = .empty,
    exec: Exec = .{},
    held_input: std.ArrayList(u8) = .empty,
    sent_input: std.ArrayList(u8) = .empty,
    sent_input_offset: u64 = 0,
    reconnect: Reconnect = .{},
    retry_timer: xev.Timer,
    retry_c: xev.Completion = .{},
    retry_cancel_c: xev.Completion = .{},
    notice_timer: xev.Timer,
    notice_c: xev.Completion = .{},
    notice_cancel_c: xev.Completion = .{},
    silence_timer: xev.Timer,
    silence_c: xev.Completion = .{},
    silence_cancel_c: xev.Completion = .{},
    clip: Clip = .{},
    clip_timer: xev.Timer,
    clip_c: xev.Completion = .{},
    clip_cancel_c: xev.Completion = .{},
    key_index: usize = 0,
    signer: ?Signer = null,
    outcome: ?Outcome = null,
    failure: ?anyerror = null,

    const Exec = struct {
        started: bool = false,
        stdout: Output = .{},
        stderr: Output = .{},
        stdin: ?*Stream = null,
        input_ended: bool = false,
        stdin_done: bool = false,
        /// From Exit. The run ends once stdout and stderr have ended too.
        exit: ?Outcome.Exit = null,

        // Exec.start in server/exec.zig opens stdout, stderr, then stdin as
        // the connection's first server-initiated streams. RFC 9000 section
        // 2.1 numbers the server's first two unidirectional streams 3 and
        // 7, and its first bidirectional stream 1.
        const stdout_id = 3;
        const stderr_id = 7;
        const stdin_id = 1;

        const Output = struct {
            writer: tty.Writer = undefined,
            stream: ?*Stream = null,
            held: usize = 0,
            fin: bool = false,
        };
    };

    const Clip = struct {
        offered: ?u64 = null,
        /// The change count after the host's last copy, which isn't offered
        /// back.
        written: ?u64 = null,
        pasted_ms: ?i64 = null,
        copies: std.ArrayList(*Copy) = .empty,

        const Copy = struct {
            stream: *Stream,
            bytes: std.ArrayList(u8) = .empty,
        };
    };

    const Reconnect = struct {
        active: bool = false,
        tries: usize = 0,
        /// The notice is on the screen, so Resume asks for a repaint.
        notice_shown: bool = false,
    };

    const Signer = struct {
        thread: std.Thread,
        identity: Identity,
        data: auth.sshsig.SignedData,
        agent: ?auth.Agent,
        cancel: Wake,
    };

    const SignError = auth.agent.Error || error{
        Canceled,
        WrongPassphrase,
        KeyFile,
    };

    const Inbox = struct {
        mutex: Io.Mutex = .init,
        input: std.ArrayList(u8) = .empty,
        resize: ?tty.Size = null,
        terminate: bool = false,
        input_ended: bool = false,
        below_low_water: bool = false,
        output_failed: bool = false,
        stdout_low: bool = false,
        stderr_low: bool = false,
        room: Io.Condition = .init,
        closed: bool = false,
        signature: ?(SignError![]u8) = null,
    };

    fn init(r: *Run, gpa: Allocator, io: Io, loop: *xev.Loop, options: Options) !void {
        r.* = .{
            .gpa = gpa,
            .io = io,
            .loop = loop,
            .options = options,
            .size = terminalSize(options),
            .racer = undefined,
            .raw = if (options.command == .attach) try .save(options.in_fd) else null,
            .decoder = .init(gpa, max_message),
            .escape = .{ .char = options.escape_char },
            .wake = try .init(),
            .retry_timer = try .init(),
            .notice_timer = try .init(),
            .silence_timer = try .init(),
            .clip_timer = try .init(),
        };
        errdefer r.clip_timer.deinit();
        errdefer r.wake.deinit();
        errdefer r.retry_timer.deinit();
        errdefer r.notice_timer.deinit();
        errdefer r.silence_timer.deinit();
        errdefer r.decoder.deinit();
        r.wake.wait(loop, &r.wake_c, Run, r, onWake);

        try r.held_input.appendSlice(gpa, options.typed[0..@min(options.typed.len, max_held_input)]);

        try r.signals.start(.{ .fd = options.in_fd, .raw_mode = if (r.raw) |*raw| raw else null, .context = r, .callback = onSignal });
        errdefer r.signals.stop();

        r.racer = try r.startRacer(options.handshake_timeout_ns);
    }

    fn startRacer(r: *Run, handshake_timeout_ns: ?u64) !*connect.Racer {
        const racer = try r.gpa.create(connect.Racer);
        racer.init(r.gpa, r.io, r.loop, .{
            .addresses = r.options.servers,
            .accept = .{ .keys = r.options.host_keys },
            .idle_timeout_ns = r.options.idle_timeout_ns,
            .handshake_timeout_ns = handshake_timeout_ns,
            .keep_alive_ns = r.options.keep_alive_ns,
            .stream_window = stream_window,
            .connection_window = stream_window,
            .handler = .{
                .ctx = r,
                .connected = onConnected,
                .data = onData,
                .acked = onAcked,
                .streamClosed = onStreamClosed,
                .closed = onClosed,
            },
        }) catch |err| {
            // The attempts that failed to start may still be closing on the
            // loop.
            racer.stop();
            r.retired.append(r.gpa, racer) catch {};
            return err;
        };
        return racer;
    }

    fn startTerminal(r: *Run) !void {
        try r.raw.?.apply();
        errdefer r.raw.?.restore();

        try r.writer.start(r.gpa, r.io, .{
            .fd = r.options.out_fd,
            .capacity = writer_options.capacity,
            .high_water = writer_options.high_water,
            .low_water = writer_options.low_water,
            .context = r,
            .callback = onWriterEvent,
        });
        errdefer r.writer.stop(.drain);
        try r.reader.start(.{ .fd = r.options.in_fd, .context = r, .callback = onReaderEvent });
        r.terminal = true;
    }

    fn deinit(r: *Run) void {
        if (r.terminal) r.reader.stop();
        r.signals.stop();
        if (r.terminal) r.writer.stop(.drain);
        if (r.exec.started) {
            {
                r.inbox.mutex.lockUncancelable(r.io);
                defer r.inbox.mutex.unlock(r.io);
                r.inbox.closed = true;
                r.inbox.room.broadcast(r.io);
            }
            r.reader.stop();
            r.exec.stdout.writer.stop(.drain);
            r.exec.stderr.writer.stop(.drain);
        }

        // A shut down socket ends a pending agent call, and cancel ends a
        // passphrase prompt.
        if (r.signer) |*signer| {
            if (signer.agent) |*agent| agent.stream.shutdown(r.io, .both) catch {};
            signer.cancel.notify();
            r.finishSigning();
        }
        if (r.inbox.signature) |result| if (result) |sig| r.gpa.free(sig) else |_| {};

        r.racer.stop();
        cancelTimer(r.loop, &r.retry_c, &r.retry_cancel_c);
        cancelTimer(r.loop, &r.notice_c, &r.notice_cancel_c);
        cancelTimer(r.loop, &r.silence_c, &r.silence_cancel_c);
        cancelTimer(r.loop, &r.clip_c, &r.clip_cancel_c);
        if (r.wake_c.state() == .active) r.wake.notify() catch {};
        // Stopped endpoints and canceled completions finish before their
        // memory is freed.
        r.loop.run(.until_done) catch {};
        for (r.retired.items) |racer| destroyRacer(r.gpa, racer);
        r.retired.deinit(r.gpa);
        destroyRacer(r.gpa, r.racer);
        r.retry_timer.deinit();
        r.notice_timer.deinit();
        r.silence_timer.deinit();
        r.clip_timer.deinit();
        r.dropCopies();
        r.clip.copies.deinit(r.gpa);
        r.wake.deinit();
        r.decoder.deinit();
        r.inbox.input.deinit(r.gpa);
        r.held_input.deinit(r.gpa);
        r.sent_input.deinit(r.gpa);
        r.listing.deinit(r.gpa);
        if (r.terminal) r.raw.?.restore();
    }

    fn destroyRacer(gpa: Allocator, racer: *connect.Racer) void {
        racer.deinit();
        gpa.destroy(racer);
    }

    fn cancelTimer(loop: *xev.Loop, c: *xev.Completion, cancel_c: *xev.Completion) void {
        if (c.state() != .active or cancel_c.state() == .active) return;
        cancel_c.* = .{ .op = .{ .cancel = .{ .c = c } } };
        loop.add(cancel_c);
    }

    fn fromCtx(ctx: ?*anyopaque) *Run {
        return @ptrCast(@alignCast(ctx.?));
    }

    /// The first outcome stays. The server takes the connection's close as
    /// the client leaving.
    fn finish(r: *Run, outcome: Outcome) void {
        if (r.outcome == null) r.outcome = outcome;
        if (r.conn) |conn| conn.close(0);
    }

    fn send(r: *Run, message: proto.Message) void {
        const stream = r.stream orelse return;
        const buf = r.gpa.alloc(u8, proto.encodedLen(message)) catch return r.finish(.{ .disconnected = .failed });
        defer r.gpa.free(buf);
        var w: Io.Writer = .fixed(buf);
        proto.encode(&w, message) catch unreachable;
        stream.write(buf) catch r.finish(.{ .disconnected = .failed });
    }

    fn terminalSize(options: Options) tty.Size {
        const size = tty.getSize(options.out_fd) catch tty.getSize(options.in_fd) catch return .{ .cols = 80, .rows = 24 };
        if (size.cols == 0 or size.rows == 0) return .{ .cols = 80, .rows = 24 };
        return size;
    }

    fn cellSize(size: tty.Size) struct { ?u32, ?u32 } {
        if (size.width_px == 0 or size.height_px == 0 or size.cols == 0 or size.rows == 0) return .{ null, null };
        return .{ size.width_px / size.cols, size.height_px / size.rows };
    }

    fn onConnected(ctx: ?*anyopaque, conn: *Conn) void {
        const r = fromCtx(ctx);
        r.conn = conn;
        r.decoder.reset();
        r.stream = conn.openStream(.bidi) catch return r.finish(.{ .disconnected = .failed });

        r.hello_size = r.size;
        const cell_w, const cell_h = cellSize(r.size);
        r.send(.{ .hello = .{
            .revision = proto.revision,
            .term = r.options.term,
            .colorterm = r.options.colorterm,
            .cols = r.size.cols,
            .rows = r.size.rows,
            .cell_width_px = cell_w,
            .cell_height_px = cell_h,
            .locale = r.options.locale,
        } });
        if (r.resume_key) |*key| r.sendResume(conn, key) else r.probe();
    }

    fn sendResume(r: *Run, conn: *Conn, key: *const [auth.resume_.key_len]u8) void {
        // The proof ties the resume key to this connection's TLS exporter
        // and to the session.
        var exporter: [auth.resume_.exporter_len]u8 = undefined;
        conn.quic.exportSecret(&exporter, auth.resume_.exporter_label);
        const proof = auth.resume_.proof(key, &exporter, r.session_id.?);
        // Without a next_seq the session sends a repaint, which clears the
        // notice off the screen.
        r.send(.{ .@"resume" = .{
            .session_id = r.session_id.?,
            .next_seq = if (r.reconnect.notice_shown) null else r.next_seq,
            .proof = &proof,
        } });
    }

    /// Asks whether the server takes the current key, before anything is
    /// signed with it.
    fn probe(r: *Run) void {
        const key = &r.options.identities[r.key_index].key;
        r.send(.{ .auth_probe = .{ .user = r.options.user, .key = key.blob() } });
    }

    fn onProbeReply(r: *Run, m: proto.AuthProbeReply) void {
        const key = &r.options.identities[r.key_index].key;
        if (r.signer != null or !std.mem.eql(u8, m.key, key.blob())) return r.refuse("unexpected probe reply");

        if (m.accepted) return r.startSigning();

        r.key_index += 1;
        if (r.key_index == r.options.identities.len) {
            var buf: [512]u8 = undefined;
            if (r.options.user.len == 0) return r.refuse("the server accepted none of the keys");
            return r.refuse(std.fmt.bufPrint(&buf, "the server accepted none of the keys for {s}", .{r.options.user}) catch unreachable);
        }
        r.probe();
    }

    fn startSigning(r: *Run) void {
        const conn = r.conn orelse return;

        var transcript: auth.login.Transcript = .{
            .exporter = undefined,
            .host_key = r.racer.presentedKey().?,
            .user = r.options.user,
            .alpn = transport.quic.alpn,
            .revision = proto.revision,
        };
        conn.quic.exportSecret(&transcript.exporter, auth.login.exporter_label);

        const identity = r.options.identities[r.key_index];
        var agent: ?auth.Agent = null;
        if (identity.source == .agent) {
            agent = auth.Agent.connect(r.io, r.options.agent.?) catch return r.refuse("can't connect to the SSH agent");
        }
        var cancel: Wake = Wake.init() catch {
            if (agent) |*a| a.close();
            return r.finish(.{ .disconnected = .failed });
        };

        // Signing runs on its own thread, since an agent call or a
        // passphrase prompt blocks.
        r.signer = .{
            .thread = undefined,
            .identity = identity,
            .data = transcript.signedData(),
            .agent = agent,
            .cancel = cancel,
        };
        r.signer.?.thread = std.Thread.spawn(.{}, signMain, .{r}) catch {
            if (agent) |*a| a.close();
            cancel.deinit();
            r.signer = null;
            return r.finish(.{ .disconnected = .failed });
        };
    }

    fn signMain(r: *Run) void {
        const signer = &r.signer.?;
        const result: SignError![]u8 = switch (signer.identity.source) {
            .agent => signer.agent.?.sign(r.gpa, signer.identity.key.blob(), signer.data.slice()),
            .file => |path| r.signWithFile(path, signer),
        };
        {
            r.inbox.mutex.lockUncancelable(r.io);
            defer r.inbox.mutex.unlock(r.io);
            r.inbox.signature = result;
        }
        r.wake.notify() catch {};
    }

    fn signWithFile(r: *Run, path: []const u8, signer: *const Signer) SignError![]u8 {
        const text = Io.Dir.cwd().readFileAlloc(r.io, path, r.gpa, .limited(64 << 10)) catch return error.KeyFile;
        defer {
            std.crypto.secureZero(u8, text);
            r.gpa.free(text);
        }
        var file = auth.private_key.PrivateKeyFile.parse(r.gpa, text) catch return error.KeyFile;
        defer file.deinit(r.gpa);

        var pass_buf: [1024]u8 = undefined;
        defer std.crypto.secureZero(u8, &pass_buf);
        var kp = for (0..3) |_| {
            const pass = if (file.isEncrypted())
                r.options.passphrase(path, &pass_buf, signer.cancel.read_fd) orelse return error.Canceled
            else
                "";
            break file.decrypt(pass) catch |err| switch (err) {
                error.WrongPassphrase => continue,
                error.Malformed => return error.KeyFile,
            };
        } else return error.WrongPassphrase;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));

        const sig = kp.sign(signer.data.slice(), null) catch return error.KeyFile;
        return r.gpa.dupe(u8, &auth.sshsig.signatureBlob(sig.toBytes()));
    }

    fn finishSigning(r: *Run) void {
        const signer = &r.signer.?;
        signer.thread.join();
        if (signer.agent) |*agent| agent.close();
        signer.cancel.deinit();
        r.signer = null;
    }

    fn onSignature(r: *Run, result: SignError![]u8) void {
        const identity = r.signer.?.identity;
        r.finishSigning();

        const sig = result catch |err| {
            var buf: [std.fs.max_path_bytes + 64]u8 = undefined;
            const path = switch (identity.source) {
                .agent => "",
                .file => |p| p,
            };
            return r.refuse(switch (err) {
                error.Refused => "the SSH agent refused to sign",
                error.Canceled => "login canceled",
                error.WrongPassphrase => std.fmt.bufPrint(&buf, "wrong passphrase for {s}", .{path}) catch "wrong passphrase",
                error.KeyFile => std.fmt.bufPrint(&buf, "can't read the key in {s}", .{path}) catch "can't read the key file",
                else => "the SSH agent failed",
            });
        };
        defer r.gpa.free(sig);

        // The command follows the signature without waiting for AuthOk. The
        // server reads them in order and answers a failed login with Error.
        r.send(.{ .auth_signature = .{ .user = r.options.user, .key = identity.key.blob(), .signature = sig } });
        var palette_buf: [64]u8 = undefined;
        r.send(switch (r.options.command) {
            .attach => .{
                .attach = .{
                    .session_id = r.options.session_id,
                    .reuse = r.options.reuse_detached,
                    .command = r.options.session_command,
                    .terminfo = r.options.terminfo,
                    .foreground = report.packRgb(r.options.colors.foreground),
                    .background = report.packRgb(r.options.colors.background),
                    .palette = report.paletteBytes(&r.options.colors, &palette_buf),
                    .dark = r.options.colors.dark,
                    .hangup = r.options.session_command != null,
                },
            },
            .list => .{ .list = .{} },
            .kill => |id| .{ .kill = .{ .session_id = id } },
            .exec => |command| .{ .exec = .{ .command = command } },
        });

        if (r.options.command == .exec) r.startExec() catch |err| {
            r.failure = err;
            r.finish(.{ .disconnected = .failed });
        };
    }

    fn startExec(r: *Run) !void {
        const outputs = [_]struct { *Exec.Output, posix.fd_t, *const fn (?*anyopaque, tty.Writer.Event) void }{
            .{ &r.exec.stdout, r.options.out_fd, onStdoutEvent },
            .{ &r.exec.stderr, r.options.err_fd, onStderrEvent },
        };
        for (outputs, 0..) |entry, i| {
            const output, const fd, const callback = entry;
            output.writer.start(r.gpa, r.io, .{
                .fd = fd,
                .capacity = writer_options.capacity,
                .high_water = writer_options.high_water,
                .low_water = writer_options.low_water,
                .context = r,
                .callback = callback,
            }) catch |err| {
                if (i == 1) r.exec.stdout.writer.stop(.discard);
                return err;
            };
        }
        r.reader.start(.{ .fd = r.options.in_fd, .context = r, .callback = onReaderEvent }) catch |err| {
            r.exec.stdout.writer.stop(.discard);
            r.exec.stderr.writer.stop(.discard);
            return err;
        };
        r.exec.started = true;
    }

    fn onAuthOk(r: *Run) void {
        if (r.options.command != .attach) return;
        // Until now no reader ran, and a passphrase prompt had the terminal
        // to itself.
        r.startTerminal() catch |err| {
            r.failure = err;
            r.finish(.{ .disconnected = .failed });
        };
    }

    fn sendResize(r: *Run) void {
        const cell_w, const cell_h = cellSize(r.size);
        r.send(.{ .resize = .{ .cols = r.size.cols, .rows = r.size.rows, .cell_width_px = cell_w, .cell_height_px = cell_h } });
    }

    fn refuse(r: *Run, message: []const u8) void {
        r.finish(.{ .refused = .{ .code = 0, .message = .init(message) } });
    }

    fn onData(ctx: ?*anyopaque, stream: *Stream, bytes: []const u8, fin: bool) void {
        const r = fromCtx(ctx);
        if (stream != r.stream) {
            if (r.options.command == .attach) return r.onCopyData(stream, bytes, fin);
            return r.onExecData(stream, bytes, fin);
        }

        r.decoder.feed(bytes);
        while (r.outcome == null) {
            const message = r.decoder.next() catch return r.finish(.{ .disconnected = .failed });
            r.handle(message orelse break);
        }

        if (r.terminal and r.writer.aboveHighWater()) r.held += bytes.len else stream.consume(bytes.len);

        if (fin) r.finish(.{ .disconnected = .{ .peer = .{ .application = 0 } } });
    }

    fn onExecData(r: *Run, stream: *Stream, bytes: []const u8, fin: bool) void {
        if (r.options.command != .exec or !r.exec.started) {
            stream.consume(bytes.len);
            return r.refuse("the server opened a stream unasked");
        }
        const output = switch (stream.id) {
            Exec.stdout_id => &r.exec.stdout,
            Exec.stderr_id => &r.exec.stderr,
            // The server finishes its side of stdin at once, and the FIN
            // shows the client the stream to write input on.
            Exec.stdin_id => {
                stream.consume(bytes.len);
                if (r.exec.stdin == null) {
                    r.exec.stdin = stream;
                    r.pumpStdin();
                }
                return;
            },
            else => {
                stream.consume(bytes.len);
                return r.refuse("the server opened a stream unasked");
            },
        };

        output.stream = stream;
        output.writer.write(bytes) catch |err| switch (err) {
            error.Failed => return r.finish(.ended),
            error.QueueFull => unreachable,
        };
        if (output.writer.aboveHighWater()) output.held += bytes.len else stream.consume(bytes.len);
        if (fin) {
            output.fin = true;
            r.finishExecIfDone();
        }
    }

    fn finishExecIfDone(r: *Run) void {
        const exit = r.exec.exit orelse return;
        if (!r.exec.stdout.fin or !r.exec.stderr.fin) return;
        r.finish(.{ .exited = exit });
    }

    fn pumpStdin(r: *Run) void {
        const stream = r.exec.stdin orelse return;
        while (!r.exec.stdin_done and stream.buffered() < stdin_high_water) {
            var chunk: std.ArrayList(u8) = .empty;
            defer chunk.deinit(r.gpa);
            {
                r.inbox.mutex.lockUncancelable(r.io);
                defer r.inbox.mutex.unlock(r.io);
                chunk = r.inbox.input;
                r.inbox.input = .empty;
                r.inbox.room.broadcast(r.io);
            }
            if (chunk.items.len == 0) {
                if (r.exec.input_ended) {
                    stream.finish();
                    r.exec.stdin_done = true;
                }
                return;
            }
            stream.write(chunk.items) catch return r.finish(.{ .disconnected = .failed });
        }
    }

    fn onAcked(ctx: ?*anyopaque, stream: *Stream) void {
        const r = fromCtx(ctx);
        if (stream == r.exec.stdin) r.pumpStdin();
    }

    fn onStreamClosed(ctx: ?*anyopaque, stream: *Stream) void {
        const r = fromCtx(ctx);
        for ([_]*?*Stream{ &r.exec.stdout.stream, &r.exec.stderr.stream, &r.exec.stdin }) |s| {
            if (s.* == stream) s.* = null;
        }
        for (r.clip.copies.items, 0..) |copy, i| if (copy.stream == stream) {
            _ = r.clip.copies.swapRemove(i);
            copy.bytes.deinit(r.gpa);
            r.gpa.destroy(copy);
            break;
        };
    }

    fn handle(r: *Run, message: proto.Message) void {
        switch (message) {
            .hello_reply => |m| if (m.revision != proto.revision) r.refuse("the server speaks another protocol revision"),
            .auth_probe_reply => |m| r.onProbeReply(m),
            .auth_ok => r.onAuthOk(),
            .attached => |m| {
                if (!r.terminal) return r.refuse("the server attached before the login");
                if (m.resume_key.len != auth.resume_.key_len) return r.refuse("the server sent a malformed resume key");
                const resumed = r.resume_key != null;
                r.resume_key = m.resume_key[0..auth.resume_.key_len].*;
                r.session_id = m.session_id;
                r.attached = true;
                if (r.silence_c.state() != .active) r.silence_timer.run(r.loop, &r.silence_c, silence_check_ms, Run, r, onSilenceTimer);
                if (resumed) {
                    r.reconnected();
                    r.resendInput(m.input_offset);
                }

                // Resizes since Hello weren't sent.
                if (!std.meta.eql(r.size, r.hello_size)) r.sendResize();

                if (r.options.show_session_id and !resumed) {
                    var buf: [64]u8 = undefined;
                    const line = std.fmt.bufPrint(&buf, "tx: session {d}\r\n", .{m.session_id}) catch unreachable;
                    r.writer.write(line) catch {};
                }
                if (r.held_input.items.len > 0) r.sendInput(r.held_input.items);
                r.held_input.clearAndFree(r.gpa);

                // The server keeps an offer per connection, so each
                // connection gets the clipboard offered.
                r.clip.offered = null;
                r.offerClipboard();
            },
            .rebuild => |m| {
                if (!r.terminal) return r.refuse("the server sent a rebuild before the login");
                r.writeTerminal(m.bytes) catch return;
                // A Rebuild's seq is the seq of the Output after it.
                r.next_seq = m.seq;
            },
            .output => |m| {
                if (!r.terminal) return r.refuse("the server sent output before the login");
                r.writeTerminal(m.bytes) catch return;
                r.next_seq = m.seq + 1;
                r.send(.{ .ack = .{ .seq = m.seq } });
            },
            .session_info => |m| {
                if (r.options.command != .list) return r.refuse("the server sent a session list unasked");
                r.listing.append(r.gpa, .{
                    .session_id = m.session_id,
                    .cols = m.cols,
                    .rows = m.rows,
                    .running_s = m.running_s,
                    .attached_from = if (m.attached_from) |from| .init(from) else null,
                    .title = if (m.title) |title| .init(title) else null,
                }) catch return r.finish(.{ .disconnected = .failed });
            },
            .list_end => {
                if (r.options.command != .list) return r.refuse("the server sent a session list unasked");
                const listed = r.listing.toOwnedSlice(r.gpa) catch return r.finish(.{ .disconnected = .failed });
                r.finish(.{ .listed = listed });
            },
            .killed => |m| r.finish(.{ .killed = m.session_id }),
            .clipboard_request => |m| if (r.attached) r.answerClipboard(m),
            .exit => |m| {
                const exit: Outcome.Exit = .{
                    .status = m.status,
                    .signal = if (m.signal) |s| .init(s) else null,
                };
                if (r.options.command != .exec) return r.finish(.{ .exited = exit });
                r.exec.exit = exit;
                r.finishExecIfDone();
            },
            .@"error" => |m| {
                // A refused resume means the session is gone, or another
                // attach gave it a new resume key.
                if (r.reconnect.active and m.code == @backingInt(proto.ErrorCode.auth)) {
                    var buf: [128]u8 = undefined;
                    const text = std.fmt.bufPrint(&buf, "can't resume session {d}: it ended, or was attached elsewhere", .{r.session_id.?}) catch unreachable;
                    return r.finish(.{ .refused = .{ .code = m.code, .message = .init(text) } });
                }
                r.finish(.{ .refused = .{ .code = m.code, .message = .init(m.message) } });
            },
            else => {},
        }
    }

    fn writeTerminal(r: *Run, bytes: []const u8) error{Failed}!void {
        r.writer.write(bytes) catch |err| switch (err) {
            error.Failed => {
                r.finish(.{ .detached = r.session_id });
                return error.Failed;
            },
            error.QueueFull => log.warn("output dropped: the terminal queue is full", .{}),
        };
    }

    fn onClosed(ctx: ?*anyopaque, conn: *Conn, reason: CloseReason) void {
        const r = fromCtx(ctx);
        const current = r.conn == conn;
        if (current) {
            r.conn = null;
            r.stream = null;
            r.attached = false;
            r.held = 0;
            r.dropCopies();
        }
        if (r.outcome != null) return;

        if (!current and r.racer.winner != null) return;

        if (r.racer.winner == null) if (r.racer.refusedKey()) |key| {
            return r.finish(.{ .host_key_refused = key });
        };

        // After an Attached, every loss is retried, with no limit on tries.
        if (r.resume_key != null) return r.retry(reason);
        r.outcome = if (r.racer.winner == null) .{ .no_connection = reason } else .{ .disconnected = reason };
    }

    fn retry(r: *Run, reason: CloseReason) void {
        if (r.retry_c.state() == .active) return;
        if (!r.reconnect.active) {
            log.info("connection lost ({t}), reconnecting", .{reason});
            r.reconnect = .{ .active = true };
            r.notice_timer.run(r.loop, &r.notice_c, r.options.notice_delay_ms, Run, r, onNoticeTimer);
        }
        const delay = retry_delays_ms[@min(r.reconnect.tries, retry_delays_ms.len - 1)];
        r.reconnect.tries += 1;
        r.retry_timer.run(r.loop, &r.retry_c, delay, Run, r, onRetryTimer);
    }

    fn onRetryTimer(r_: ?*Run, _: *xev.Loop, _: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
        const r = r_.?;
        result catch return .disarm;
        if (r.outcome != null) return .disarm;

        const racer = r.startRacer(reconnect_handshake_timeout_ns) catch |err| {
            log.info("reconnecting failed: {t}", .{err});
            r.retry(.failed);
            return .disarm;
        };

        r.racer.stop();
        r.retired.append(r.gpa, r.racer) catch {};
        r.racer = racer;
        var i: usize = 0;
        while (i < r.retired.items.len) {
            if (!r.retired.items[i].isStopped()) {
                i += 1;
                continue;
            }
            destroyRacer(r.gpa, r.retired.swapRemove(i));
        }
        return .disarm;
    }

    fn onSilenceTimer(r_: ?*Run, _: *xev.Loop, _: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
        const r = r_.?;
        result catch return .disarm;
        if (r.outcome != null or !r.attached) return .disarm;

        const conn = r.conn.?;
        const silence = conn.silence();
        if (silence.nanoseconds >= r.options.silence_timeout_ns) {
            log.info("nothing from the server for {d} ms", .{@divTrunc(silence.nanoseconds, std.time.ns_per_ms)});
            conn.close(0);
            return .disarm;
        }
        r.silence_timer.run(r.loop, &r.silence_c, silence_check_ms, Run, r, onSilenceTimer);
        return .disarm;
    }

    fn onNoticeTimer(r_: ?*Run, _: *xev.Loop, _: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
        const r = r_.?;
        result catch return .disarm;
        if (r.outcome != null or !r.reconnect.active or !r.terminal) return .disarm;

        // ?2026l ends a synchronized update the lost connection may have
        // left open. The notice goes on the bottom row in reverse video,
        // between a cursor save and restore.
        var buf: [128]u8 = undefined;
        const notice = std.fmt.bufPrint(&buf, "\x1b[?2026l\x1b7\x1b[{d};1H\x1b[0m\x1b[7m tx: connection lost, reconnecting. ~. detaches \x1b[0m\x1b[K\x1b8", .{r.size.rows}) catch unreachable;
        r.writeTerminal(notice) catch return .disarm;
        r.reconnect.notice_shown = true;
        return .disarm;
    }

    fn offerClipboard(r: *Run) void {
        const provider = r.options.clipboard orelse return;
        if (!r.attached) return;
        if (r.clip_c.state() != .active) r.clip_timer.run(r.loop, &r.clip_c, clipboard.poll_ms, Run, r, onClipTimer);

        const change = provider.change(provider.context);
        if (r.clip.offered == change) return;
        r.clip.offered = change;
        if (r.clip.written == change) return;

        const mimes = provider.types(provider.context, r.gpa) catch return;
        defer r.gpa.free(mimes);
        r.send(.{ .clipboard_offer = .{ .change = change, .mimes = mimes } });
    }

    fn onClipTimer(r_: ?*Run, _: *xev.Loop, _: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
        const r = r_.?;
        result catch return .disarm;
        if (r.outcome != null or !r.attached) return .disarm;
        r.offerClipboard();
        return .disarm;
    }

    /// Answers on a new uni stream: a ClipboardData header, then the data
    /// up to FIN. A read is refused unless the user pasted within
    /// paste_window_ms and the clipboard is still the one offered.
    fn answerClipboard(r: *Run, m: proto.ClipboardRequest) void {
        const conn = r.conn orelse return;
        const provider = r.options.clipboard orelse return;
        const pasted = if (r.clip.pasted_ms) |t| nowMs(r.io) - t <= clipboard.paste_window_ms else false;
        const current = provider.change(provider.context) == m.change;

        const data: ?[]u8 = if (pasted and current) provider.read(provider.context, r.gpa, m.mime) catch null else null;
        defer if (data) |d| r.gpa.free(d);
        if (!pasted) log.debug("refused a read of the clipboard: no paste in the last {d} s", .{clipboard.paste_window_ms / 1000});

        const refused = data == null or data.?.len > clipboard.max_data_len;
        const header: proto.Message = .{ .clipboard_data = .{ .id = m.id, .refused = refused } };
        // server/root.zig reads at most max_answer_header (64) bytes of
        // header.
        var buf: [64]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        proto.encode(&w, header) catch unreachable;
        const stream = conn.openStream(.uni) catch return;
        stream.write(w.buffered()) catch return stream.reset(0);
        if (!refused) stream.write(data.?) catch return stream.reset(0);
        stream.finish();
    }

    fn onCopyData(r: *Run, stream: *Stream, bytes: []const u8, fin: bool) void {
        stream.consume(bytes.len);
        const copy = for (r.clip.copies.items) |copy| {
            if (copy.stream == stream) break copy;
        } else new: {
            const copy = r.gpa.create(Clip.Copy) catch return stream.reset(0);
            copy.* = .{ .stream = stream };
            r.clip.copies.append(r.gpa, copy) catch {
                r.gpa.destroy(copy);
                return stream.reset(0);
            };
            break :new copy;
        };

        if (copy.bytes.items.len + bytes.len > clipboard.max_data_len + max_copy_header) return stream.reset(0);
        copy.bytes.appendSlice(r.gpa, bytes) catch return stream.reset(0);
        if (!fin) return;
        defer r.endCopy(copy);
        r.writeCopy(copy.bytes.items) catch log.warn("a copy from the host was malformed", .{});
    }

    fn writeCopy(r: *Run, bytes: []const u8) !void {
        const provider = r.options.clipboard orelse return;
        const m, const header_len = (try proto.frame.firstMessage(bytes, max_copy_header)) orelse return error.Truncated;
        if (m != .clipboard_copy) return error.WrongType;
        const copy = m.clipboard_copy;

        // The server sends at most server/clipboard.zig's max_copy_types (16)
        // types.
        var items: [16]clipboard.Item = undefined;
        var count: usize = 0;
        var data = bytes[header_len..];
        var mimes = std.mem.splitScalar(u8, copy.mimes, 0);
        var lens = copy.lens;
        while (lens.len >= 8) : (lens = lens[8..]) {
            const mime = mimes.next() orelse return error.WrongType;
            const len = std.mem.readInt(u64, lens[0..8], .big);
            if (len > data.len or count == items.len) return error.WrongType;
            items[count] = .{ .mime = mime, .data = data[0..len] };
            count += 1;
            data = data[len..];
        }
        if (data.len != 0 or count == 0) return error.WrongType;

        r.clip.written = provider.write(provider.context, items[0..count]);
        r.clip.offered = r.clip.written;
    }

    fn endCopy(r: *Run, copy: *Clip.Copy) void {
        const index = std.mem.indexOfScalar(*Clip.Copy, r.clip.copies.items, copy) orelse return;
        _ = r.clip.copies.swapRemove(index);
        copy.bytes.deinit(r.gpa);
        r.gpa.destroy(copy);
    }

    fn dropCopies(r: *Run) void {
        for (r.clip.copies.items) |copy| {
            copy.bytes.deinit(r.gpa);
            r.gpa.destroy(copy);
        }
        r.clip.copies.clearRetainingCapacity();
    }

    fn sendInput(r: *Run, bytes: []const u8) void {
        r.send(.{ .input = .{ .bytes = bytes } });
        r.sent_input.appendSlice(r.gpa, bytes) catch return;
        if (r.sent_input.items.len > max_sent_input) {
            const drop = r.sent_input.items.len - max_sent_input;
            r.sent_input.replaceRangeAssumeCapacity(0, drop, &.{});
            r.sent_input_offset += drop;
        }
    }

    /// offset is Attached.input_offset, the count of input bytes the session
    /// has received. What was sent after it goes again, as far as
    /// sent_input reaches.
    fn resendInput(r: *Run, offset: u64) void {
        const end = r.sent_input_offset + r.sent_input.items.len;
        if (offset >= end) return;
        if (offset < r.sent_input_offset) log.warn("{d} bytes of input were lost", .{r.sent_input_offset - offset});
        const start: usize = @intCast(@max(offset, r.sent_input_offset) - r.sent_input_offset);
        r.send(.{ .input = .{ .bytes = r.sent_input.items[start..] } });
    }

    fn reconnected(r: *Run) void {
        log.info("reconnected after {d} tries", .{r.reconnect.tries});
        cancelTimer(r.loop, &r.retry_c, &r.retry_cancel_c);
        cancelTimer(r.loop, &r.notice_c, &r.notice_cancel_c);
        r.reconnect = .{};
    }

    fn onReaderEvent(ctx: ?*anyopaque, event: tty.Reader.Event) void {
        const r = fromCtx(ctx);
        {
            r.inbox.mutex.lockUncancelable(r.io);
            defer r.inbox.mutex.unlock(r.io);
            switch (event) {
                .data => |bytes| {
                    while (r.options.command == .exec and r.inbox.input.items.len >= max_pending_stdin and !r.inbox.closed) {
                        r.inbox.room.waitUncancelable(r.io, &r.inbox.mutex);
                    }
                    r.inbox.input.appendSlice(r.gpa, bytes) catch {};
                },
                .end_of_file, .failed => r.inbox.input_ended = true,
            }
        }
        r.wake.notify() catch {};
    }

    fn onWriterEvent(ctx: ?*anyopaque, event: tty.Writer.Event) void {
        const r = fromCtx(ctx);
        {
            r.inbox.mutex.lockUncancelable(r.io);
            defer r.inbox.mutex.unlock(r.io);
            switch (event) {
                .above_high_water => {},
                .below_low_water => r.inbox.below_low_water = true,
                .failed => r.inbox.output_failed = true,
            }
        }
        r.wake.notify() catch {};
    }

    fn onStdoutEvent(ctx: ?*anyopaque, event: tty.Writer.Event) void {
        onExecWriterEvent(ctx, event, .stdout);
    }

    fn onStderrEvent(ctx: ?*anyopaque, event: tty.Writer.Event) void {
        onExecWriterEvent(ctx, event, .stderr);
    }

    fn onExecWriterEvent(ctx: ?*anyopaque, event: tty.Writer.Event, which: enum { stdout, stderr }) void {
        const r = fromCtx(ctx);
        {
            r.inbox.mutex.lockUncancelable(r.io);
            defer r.inbox.mutex.unlock(r.io);
            switch (event) {
                .above_high_water => {},
                .below_low_water => switch (which) {
                    .stdout => r.inbox.stdout_low = true,
                    .stderr => r.inbox.stderr_low = true,
                },
                .failed => r.inbox.output_failed = true,
            }
        }
        r.wake.notify() catch {};
    }

    fn onSignal(ctx: ?*anyopaque, event: tty.Signals.Event) void {
        const r = fromCtx(ctx);
        {
            r.inbox.mutex.lockUncancelable(r.io);
            defer r.inbox.mutex.unlock(r.io);
            switch (event) {
                .resize => |size| r.inbox.resize = size,
                .terminate => r.inbox.terminate = true,
            }
        }
        r.wake.notify() catch {};
    }

    fn onWake(r_: ?*Run, _: *xev.Loop, _: *xev.Completion, result: xev.Async.WaitError!void) xev.CallbackAction {
        const r = r_.?;
        result catch return .disarm;

        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(r.gpa);
        var signature: ?(SignError![]u8) = null;
        const exec = r.options.command == .exec;
        const resize, const terminate, const input_ended, const below_low_water, const output_failed, const stdout_low, const stderr_low = taken: {
            r.inbox.mutex.lockUncancelable(r.io);
            defer r.inbox.mutex.unlock(r.io);
            const box = &r.inbox;
            if (!exec) {
                input = box.input;
                box.input = .empty;
            }
            signature = box.signature;
            box.signature = null;
            defer {
                box.resize = null;
                box.terminate = false;
                box.input_ended = false;
                box.below_low_water = false;
                box.output_failed = false;
                box.stdout_low = false;
                box.stderr_low = false;
            }
            break :taken .{ box.resize, box.terminate, box.input_ended, box.below_low_water, box.output_failed, box.stdout_low, box.stderr_low };
        };

        if (exec) {
            if (signature) |sig| r.onSignature(sig);
            if (input_ended) r.exec.input_ended = true;
            r.pumpStdin();

            for ([_]struct { bool, *Exec.Output }{
                .{ stdout_low, &r.exec.stdout },
                .{ stderr_low, &r.exec.stderr },
            }) |entry| {
                const low, const output = entry;
                if (!low or output.held == 0) continue;
                if (output.stream) |stream| stream.consume(output.held);
                output.held = 0;
            }

            if (terminate or output_failed) r.finish(.ended);
            return if (r.outcome == null) .rearm else .disarm;
        }

        if (signature) |sig| r.onSignature(sig);

        r.forwardInput(input.items);

        if (resize) |size| {
            r.size = size;
            if (r.attached) r.sendResize();
        }

        if (below_low_water and r.held > 0) {
            if (r.stream) |stream| stream.consume(r.held);
            r.held = 0;
        }

        if (terminate or input_ended or output_failed) r.finish(.{ .detached = r.session_id });
        return if (r.outcome == null) .rearm else .disarm;
    }

    fn forwardInput(r: *Run, input: []const u8) void {
        if (clipboard.hasPaste(input)) r.clip.pasted_ms = nowMs(r.io);

        // Escape.feed can emit one byte more than its input.
        var out: [4097]u8 = undefined;
        var rest = input;

        while (rest.len > 0 and r.outcome == null) {
            const chunk = rest[0..@min(rest.len, out.len - 1)];
            rest = rest[chunk.len..];

            const result = r.escape.feed(chunk, &out);
            if (result.forward.len > 0) {
                if (!r.attached) {
                    if (r.held_input.items.len + result.forward.len <= max_held_input) {
                        r.held_input.appendSlice(r.gpa, result.forward) catch {};
                    }
                } else {
                    r.sendInput(result.forward);
                }
            }
            if (result.action) |action| switch (action) {
                .disconnect => r.finish(.{ .detached = r.session_id }),
            };
        }
    }
};

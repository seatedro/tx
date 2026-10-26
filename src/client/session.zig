//! The `tx` client's connection to one session.
//!
//! After the handshake, the client logs in. It probes its keys in turn,
//! from the SSH agent and from key files, and signs the login transcript
//! with the first one the server accepts. Signing runs on its own thread:
//! the agent may wait for the user to approve it, and a key file may need
//! its passphrase. The signature and `Attach` go out together. The
//! terminal enters raw mode once the login succeeds, so a passphrase
//! prompt finds it as the user left it.
//!
//! Like the ssh client, it writes the session's output to the user's
//! terminal unchanged and forwards what the user types. Output written to
//! the terminal is acknowledged to QUIC flow control only while the
//! writer's queue is below its high-water mark, so a terminal that can't
//! keep up slows the server down.
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
const passphrase = @import("passphrase.zig");

const Endpoint = transport.endpoint.Endpoint;
const Conn = transport.endpoint.Conn;
const Stream = transport.endpoint.Stream;
const CloseReason = transport.endpoint.CloseReason;

const log = std.log.scoped(.client);

pub const Options = struct {
    server: IpAddress,
    /// The server keys the client accepts.
    host_keys: []const [32]u8,
    /// The account to log in as.
    user: []const u8,
    /// The keys to log in with, probed in order. At least one.
    identities: []const Identity,
    /// The SSH agent's socket, for identities from the agent.
    agent: ?[]const u8 = null,
    /// Asks for an encrypted key file's passphrase. Runs on the signer's
    /// thread before the terminal enters raw mode, and gives up with null
    /// when `cancel_fd` becomes readable.
    passphrase: *const fn (path: []const u8, buf: []u8, cancel_fd: posix.fd_t) ?[]u8 = askPassphrase,
    /// Print the session's ID once attached.
    show_session_id: bool = false,
    /// Null starts a new session.
    session_id: ?u64 = null,
    /// The user's terminal.
    in_fd: posix.fd_t = posix.STDIN_FILENO,
    out_fd: posix.fd_t = posix.STDOUT_FILENO,
    term: []const u8,
    colorterm: ?[]const u8 = null,
    /// Null disables `~.`.
    escape_char: ?u8 = '~',
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
    keep_alive_ns: u64 = 10 * std.time.ns_per_s,
};

pub const Identity = struct {
    key: auth.ssh.PublicKey,
    source: union(enum) {
        agent,
        /// An OpenSSH private key file.
        file: []const u8,
    },
};

/// Prompts on the controlling terminal, as ssh does.
fn askPassphrase(path: []const u8, buf: []u8, cancel_fd: posix.fd_t) ?[]u8 {
    var prompt_buf: [std.fs.max_path_bytes + 64]u8 = undefined;
    const prompt = std.fmt.bufPrint(&prompt_buf, "Enter passphrase for key '{s}': ", .{path}) catch "Enter passphrase: ";
    return passphrase.ask(prompt, buf, cancel_fd) catch null;
}

pub const Outcome = union(enum) {
    /// The program exited.
    exited: Exit,
    /// `~.`, a terminating signal, or the user's terminal going away. The
    /// session keeps running.
    detached: ?u64,
    /// The connection closed before the session ended.
    disconnected: CloseReason,
    /// The server presented a key that isn't in `Options.host_keys`.
    host_key_refused: [32]u8,
    /// The server answered with `proto.Error`.
    refused: Refusal,

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

/// Output queued for the user's terminal above which flow control credit
/// is held back, and below which it is returned.
const writer_options = .{
    .capacity = 4 << 20,
    .high_water = 1 << 20,
    .low_water = 256 << 10,
};

/// Less than `writer_options.capacity - high_water`, so that output already
/// in flight when the queue crosses its high-water mark still fits.
const stream_window = 2 << 20;

/// The largest message body accepted from the server.
const max_message = 1 << 20;

/// Runs one session until it exits or detaches. The user's terminal is in
/// raw mode from the login on.
pub fn run(gpa: Allocator, io: Io, options: Options) !Outcome {
    std.debug.assert(options.identities.len > 0);
    transport.crypto.init(io);

    // Before any thread starts. Threads inherit the mask, and the signal
    // thread receives them.
    const old_mask = tty.blockSignals();
    defer {
        var ignored: posix.sigset_t = undefined;
        _ = std.c.pthread_sigmask(posix.SIG.SETMASK, &old_mask, &ignored);
    }

    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();

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
    tls: transport.quic.Client,
    endpoint: Endpoint,
    conn: ?*Conn = null,
    /// The terminal's attributes from before the session. Raw mode is
    /// applied once `terminal` is set.
    raw: tty.RawMode,
    /// Raw mode is on, and the reader and writer run. Set after the login.
    terminal: bool = false,
    /// The size sent in `Hello`.
    hello_size: tty.Size = undefined,
    /// The one stream to the server, opened after the handshake.
    stream: ?*Stream = null,
    decoder: proto.Decoder,
    escape: escape.Escape,

    /// The threads put events in `inbox` and notify `wake`. `onWake` takes
    /// them on the loop thread.
    inbox: Inbox = .{},
    wake: xev.Async,
    wake_c: xev.Completion = .{},
    writer: tty.Writer = undefined,
    reader: tty.Reader = undefined,
    signals: tty.Signals = undefined,
    /// Received bytes whose flow control credit is held while the writer is
    /// above its high-water mark.
    held: usize = 0,
    session_id: ?u64 = null,
    /// Input typed before the server confirmed the attach.
    early_input: std.ArrayList(u8) = .empty,
    /// The identity in `options.identities` being probed or signed with.
    key_index: usize = 0,
    /// Set while a signature is being made.
    signer: ?Signer = null,
    outcome: ?Outcome = null,
    /// An error `run` returns, for a failure with no outcome of its own.
    failure: ?anyerror = null,

    /// A signature in progress.
    const Signer = struct {
        thread: std.Thread,
        identity: Identity,
        data: auth.sshsig.SignedData,
        /// For an agent identity. Shutting it down ends a request the user
        /// hasn't answered.
        agent: ?auth.Agent,
        /// Ends a passphrase prompt nobody is answering.
        cancel: Wake,
    };

    const SignError = auth.agent.Error || error{
        /// The user gave up on the passphrase, or the session ended.
        Canceled,
        WrongPassphrase,
        /// The key file can't be read or parsed.
        KeyFile,
    };

    /// What the reader, writer and signal threads pass to the loop thread.
    const Inbox = struct {
        mutex: Io.Mutex = .init,
        input: std.ArrayList(u8) = .empty,
        resize: ?tty.Size = null,
        terminate: bool = false,
        input_ended: bool = false,
        below_low_water: bool = false,
        output_failed: bool = false,
        /// The signature blob, owned, or why there is none.
        signature: ?(SignError![]u8) = null,
    };

    fn init(r: *Run, gpa: Allocator, io: Io, loop: *xev.Loop, options: Options) !void {
        r.* = .{
            .gpa = gpa,
            .io = io,
            .loop = loop,
            .options = options,
            .size = terminalSize(options),
            .tls = try .init(.{ .keys = options.host_keys }),
            .endpoint = undefined,
            .raw = try .save(options.in_fd),
            .decoder = .init(gpa, max_message),
            .escape = .{ .char = options.escape_char },
            .wake = try .init(),
        };
        errdefer r.wake.deinit();
        errdefer r.decoder.deinit();
        errdefer r.tls.deinit();

        // Any local address of the server's family. The kernel picks the
        // port.
        const local: IpAddress = switch (options.server) {
            .ip4 => try .parseIp4("0.0.0.0", 0),
            .ip6 => try .parseIp6("::", 0),
        };
        try r.endpoint.init(gpa, io, loop, .{
            .local = local,
            .role = .{ .client = &r.tls },
            .idle_timeout_ns = options.idle_timeout_ns,
            .keep_alive_ns = options.keep_alive_ns,
            .stream_window = stream_window,
            .connection_window = stream_window,
            .handler = .{
                .ctx = r,
                .connected = onConnected,
                .data = onData,
                .closed = onClosed,
            },
        });
        r.wake.wait(loop, &r.wake_c, Run, r, onWake);

        // From the start, so a terminating signal during the login ends it.
        // Restoring the saved attributes before raw mode turns echo back on
        // after a passphrase prompt.
        try r.signals.start(.{ .fd = options.in_fd, .raw_mode = &r.raw, .context = r, .callback = onSignal });
        r.conn = try r.endpoint.connect(options.server);
    }

    /// Enters raw mode and starts reading and writing the terminal.
    fn startTerminal(r: *Run) !void {
        try r.raw.apply();
        errdefer r.raw.restore();

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

    /// Stops the threads, writes what is queued for the terminal, and closes
    /// the connection.
    fn deinit(r: *Run) void {
        if (r.terminal) r.reader.stop();
        r.signals.stop();
        if (r.terminal) r.writer.stop(.drain);

        // Ends a signature the user hasn't approved, or a passphrase they
        // haven't typed.
        if (r.signer) |*signer| {
            if (signer.agent) |*agent| agent.stream.shutdown(r.io, .both) catch {};
            signer.cancel.notify();
            r.finishSigning();
        }
        if (r.inbox.signature) |result| if (result) |sig| r.gpa.free(sig) else |_| {};

        // Stop the endpoint, then run the loop until its completions finish.
        r.endpoint.stop();
        // `onWake` disarms once the outcome is set. Cancelling the wait would
        // end it with an ECANCELED that libxev's poll doesn't map.
        if (r.wake_c.state() == .active) r.wake.notify() catch {};
        r.loop.run(.until_done) catch {};
        r.endpoint.deinit();
        r.wake.deinit();
        r.decoder.deinit();
        r.tls.deinit();
        r.inbox.input.deinit(r.gpa);
        r.early_input.deinit(r.gpa);
        if (r.terminal) r.raw.restore();
    }

    fn fromCtx(ctx: ?*anyopaque) *Run {
        return @ptrCast(@alignCast(ctx.?));
    }

    /// Records the outcome and closes the connection. The first outcome
    /// wins.
    fn finish(r: *Run, outcome: Outcome) void {
        if (r.outcome == null) r.outcome = outcome;
        if (r.conn) |conn| conn.close(0);
    }

    /// Encodes `message` onto the stream. The stream copies it.
    fn send(r: *Run, message: proto.Message) void {
        const stream = r.stream orelse return;
        const buf = r.gpa.alloc(u8, proto.encodedLen(message)) catch return r.finish(.{ .disconnected = .failed });
        defer r.gpa.free(buf);
        var w: Io.Writer = .fixed(buf);
        proto.encode(&w, message) catch unreachable;
        stream.write(buf) catch r.finish(.{ .disconnected = .failed });
    }

    /// 80x24 when the terminal doesn't report a size, as ssh does.
    fn terminalSize(options: Options) tty.Size {
        // stdout first: stdin may be redirected while stdout is the
        // terminal.
        const size = tty.getSize(options.out_fd) catch tty.getSize(options.in_fd) catch return .{ .cols = 80, .rows = 24 };
        if (size.cols == 0 or size.rows == 0) return .{ .cols = 80, .rows = 24 };
        return size;
    }

    /// The cell size in pixels, from the grid's size. Null when the
    /// terminal doesn't report pixels.
    fn cellSize(size: tty.Size) struct { ?u32, ?u32 } {
        if (size.width_px == 0 or size.height_px == 0 or size.cols == 0 or size.rows == 0) return .{ null, null };
        return .{ size.width_px / size.cols, size.height_px / size.rows };
    }

    fn onConnected(ctx: ?*anyopaque, conn: *Conn) void {
        const r = fromCtx(ctx);
        r.stream = conn.openStream(.bidi) catch return r.finish(.{ .disconnected = .failed });

        // Hello and the first probe go together. The server answers both,
        // in order.
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
        } });
        r.probe();
    }

    /// Asks whether the server accepts the current key.
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
            // `Name` truncates a message longer than it holds.
            var buf: [512]u8 = undefined;
            return r.refuse(std.fmt.bufPrint(&buf, "the server accepted none of the keys for {s}", .{r.options.user}) catch unreachable);
        }
        r.probe();
    }

    /// Starts the agent signing the transcript with the current key.
    fn startSigning(r: *Run) void {
        const conn = r.conn orelse return;

        // The transcript as this end sees the connection.
        var transcript: auth.login.Transcript = .{
            .exporter = undefined,
            .host_key = r.tls.presentedKey().?,
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

    /// Runs on the signer's thread.
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

    /// Signs with the key in an OpenSSH private key file, asking for its
    /// passphrase if it has one. Runs on the signer's thread.
    fn signWithFile(r: *Run, path: []const u8, signer: *const Signer) SignError![]u8 {
        const text = Io.Dir.cwd().readFileAlloc(r.io, path, r.gpa, .limited(64 << 10)) catch return error.KeyFile;
        defer {
            std.crypto.secureZero(u8, text);
            r.gpa.free(text);
        }
        var file = auth.private_key.PrivateKeyFile.parse(r.gpa, text) catch return error.KeyFile;
        defer file.deinit(r.gpa);

        // Three tries, as ssh gives.
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

    /// Joins the signer's thread, which has finished or is about to.
    fn finishSigning(r: *Run) void {
        const signer = &r.signer.?;
        signer.thread.join();
        if (signer.agent) |*agent| agent.close();
        signer.cancel.deinit();
        r.signer = null;
    }

    /// Sends the signature and the attach together. The server attaches
    /// only if the login succeeds.
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

        r.send(.{ .auth_signature = .{ .user = r.options.user, .key = identity.key.blob(), .signature = sig } });
        r.send(.{ .attach = .{ .session_id = r.options.session_id } });
    }

    fn onAuthOk(r: *Run) void {
        r.startTerminal() catch |err| {
            r.failure = err;
            r.finish(.{ .disconnected = .failed });
        };
    }

    /// Ends the run for a reason of the client's own, with code 0.
    fn sendResize(r: *Run) void {
        const cell_w, const cell_h = cellSize(r.size);
        r.send(.{ .resize = .{ .cols = r.size.cols, .rows = r.size.rows, .cell_width_px = cell_w, .cell_height_px = cell_h } });
    }

    fn refuse(r: *Run, message: []const u8) void {
        r.finish(.{ .refused = .{ .code = 0, .message = .init(message) } });
    }

    fn onData(ctx: ?*anyopaque, stream: *Stream, bytes: []const u8, fin: bool) void {
        const r = fromCtx(ctx);

        r.decoder.feed(bytes);
        while (r.outcome == null) {
            const message = r.decoder.next() catch return r.finish(.{ .disconnected = .failed });
            r.handle(message orelse break);
        }

        // Returning credit lets the server send more. While the terminal is
        // behind, the credit waits for `below_low_water`.
        if (r.terminal and r.writer.aboveHighWater()) r.held += bytes.len else stream.consume(bytes.len);

        // The server finishes the stream only after Exit or Error.
        if (fin) r.finish(.{ .disconnected = .{ .peer = .{ .application = 0 } } });
    }

    fn handle(r: *Run, message: proto.Message) void {
        switch (message) {
            .hello_reply => |m| if (m.revision != proto.revision) r.refuse("the server speaks another protocol revision"),
            .auth_probe_reply => |m| r.onProbeReply(m),
            .auth_ok => r.onAuthOk(),
            // Input typed before this was held, since the server had no
            // session to give it to.
            .attached => |m| {
                if (!r.terminal) return r.refuse("the server attached before the login");
                r.session_id = m.session_id;

                // The terminal changed size since `Hello`.
                if (!std.meta.eql(r.size, r.hello_size)) r.sendResize();

                if (r.options.show_session_id) {
                    var buf: [64]u8 = undefined;
                    const line = std.fmt.bufPrint(&buf, "tx: session {d}\r\n", .{m.session_id}) catch unreachable;
                    r.writer.write(line) catch {};
                }
                if (r.early_input.items.len > 0) r.send(.{ .input = .{ .bytes = r.early_input.items } });
                r.early_input.clearAndFree(r.gpa);
            },
            // Acked once queued for the terminal.
            .output => |m| {
                if (!r.terminal) return r.refuse("the server sent output before the login");
                r.writer.write(m.bytes) catch |err| switch (err) {
                    error.Failed => return r.finish(.{ .detached = r.session_id }),
                    error.QueueFull => log.warn("output dropped: the terminal queue is full", .{}),
                };
                r.send(.{ .ack = .{ .seq = m.seq } });
            },
            .exit => |m| r.finish(.{ .exited = .{
                .status = m.status,
                .signal = if (m.signal) |s| .init(s) else null,
            } }),
            .@"error" => |m| r.finish(.{ .refused = .{ .code = m.code, .message = .init(m.message) } }),
            else => {},
        }
    }

    fn onClosed(ctx: ?*anyopaque, conn: *Conn, reason: CloseReason) void {
        const r = fromCtx(ctx);
        if (r.conn == conn) {
            r.conn = null;
            r.stream = null;
        }
        if (r.outcome != null) return;

        // A refused key fails the handshake after the server presented it.
        if (reason == .handshake_failed) if (r.tls.presentedKey()) |key| {
            for (r.options.host_keys) |k| {
                if (std.mem.eql(u8, &k, &key)) break;
            } else return r.finish(.{ .host_key_refused = key });
        };
        r.outcome = .{ .disconnected = reason };
    }

    // The next three run on the reader, writer and signal threads. Each
    // records the event in `inbox` and wakes the loop.

    fn onReaderEvent(ctx: ?*anyopaque, event: tty.Reader.Event) void {
        const r = fromCtx(ctx);
        {
            r.inbox.mutex.lockUncancelable(r.io);
            defer r.inbox.mutex.unlock(r.io);
            switch (event) {
                .data => |bytes| r.inbox.input.appendSlice(r.gpa, bytes) catch {},
                .end_of_file, .failed => r.inbox.input_ended = true,
            }
        }
        r.wake.notify() catch {};
    }

    /// Runs with the writer's queue locked: it only records the event.
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

        // Take everything from the inbox at once and handle it without the
        // lock. Notifications may have been coalesced.
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(r.gpa);
        var signature: ?(SignError![]u8) = null;
        const resize, const terminate, const input_ended, const below_low_water, const output_failed = taken: {
            r.inbox.mutex.lockUncancelable(r.io);
            defer r.inbox.mutex.unlock(r.io);
            const box = &r.inbox;
            input = box.input;
            box.input = .empty;
            signature = box.signature;
            box.signature = null;
            defer {
                box.resize = null;
                box.terminate = false;
                box.input_ended = false;
                box.below_low_water = false;
                box.output_failed = false;
            }
            break :taken .{ box.resize, box.terminate, box.input_ended, box.below_low_water, box.output_failed };
        };

        if (signature) |sig| r.onSignature(sig);

        r.forwardInput(input.items);

        // Before the attach, the server has no terminal to resize.
        // `.attached` sends the size then.
        if (resize) |size| {
            r.size = size;
            if (r.session_id != null) r.sendResize();
        }

        // The terminal caught up: return the credit held back in `onData`.
        if (below_low_water and r.held > 0) {
            if (r.stream) |stream| stream.consume(r.held);
            r.held = 0;
        }

        // The session keeps running on the server.
        if (terminate or input_ended or output_failed) r.finish(.{ .detached = r.session_id });
        return if (r.outcome == null) .rearm else .disarm;
    }

    /// Runs input through the escape handler and sends it, or holds it
    /// until the attach completes.
    fn forwardInput(r: *Run, input: []const u8) void {
        // `Escape.feed` can add one byte to its input.
        var out: [4097]u8 = undefined;
        var rest = input;

        // Stops after `~.`: what follows it isn't sent.
        while (rest.len > 0 and r.outcome == null) {
            const chunk = rest[0..@min(rest.len, out.len - 1)];
            rest = rest[chunk.len..];

            const result = r.escape.feed(chunk, &out);
            if (result.forward.len > 0) {
                if (r.session_id == null) {
                    r.early_input.appendSlice(r.gpa, result.forward) catch {};
                } else {
                    r.send(.{ .input = .{ .bytes = result.forward } });
                }
            }
            if (result.action) |action| switch (action) {
                .disconnect => r.finish(.{ .detached = r.session_id }),
            };
        }
    }
};

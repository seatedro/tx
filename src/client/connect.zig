//! Races connections to a host's addresses, as Happy Eyeballs (RFC 8305)
//! does for TCP.
//!
//! Attempts start in the order of `Options.addresses`, one every
//! `attempt_delay_ms`, or at once when the one before fails. The first to
//! complete its handshake wins: the others are closed, and from then on the
//! winner's events go to `Options.handler`. When every attempt has failed,
//! `handler.closed` reports the last failure.
//!
//! Each attempt has its own endpoint and TLS context, so the attempts don't
//! share a socket, a source port or a presented key.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const xev = @import("xev");
const transport = @import("transport");

const quic = transport.quic;
const Endpoint = transport.endpoint.Endpoint;
const Conn = transport.endpoint.Conn;
const Stream = transport.endpoint.Stream;
const Handler = transport.endpoint.Handler;
const CloseReason = transport.endpoint.CloseReason;

const log = std.log.scoped(.connect);

/// RFC 8305 §5 recommends 250 ms.
pub const attempt_delay_ms = 250;

pub const Options = struct {
    /// Tried in order. At least one. Must outlive the racer.
    addresses: []const IpAddress,
    accept: quic.Client.Accept,
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
    /// Null leaves a handshake to the idle timeout.
    handshake_timeout_ns: ?u64 = null,
    keep_alive_ns: ?u64 = null,
    stream_window: u64 = 8 << 20,
    connection_window: u64 = 32 << 20,
    /// The server's knock key, if it has one. See `transport.knock`.
    knock: ?*const transport.knock.Key = null,
    /// Gets the winner's events, and `closed` once every attempt failed.
    handler: Handler,
};

/// The racer must not move while the loop runs.
pub const Racer = struct {
    gpa: Allocator,
    io: Io,
    loop: *xev.Loop,
    options: Options,
    /// The attempts started, each kept until `deinit`.
    attempts: std.ArrayList(*Attempt) = .empty,
    /// The index in `Options.addresses` of the next address to try.
    next: usize = 0,
    winner: ?*Attempt = null,
    /// Attempts started that haven't failed.
    live: usize = 0,
    stopping: bool = false,
    /// Starts the next attempt.
    timer: xev.Timer,
    timer_c: xev.Completion = .{},
    timer_reset_c: xev.Completion = .{},
    timer_cancel_c: xev.Completion = .{},

    const Attempt = struct {
        racer: *Racer,
        address: IpAddress,
        tls: quic.Client,
        endpoint: Endpoint,
        failure: ?CloseReason = null,

        fn of(ctx: ?*anyopaque) *Attempt {
            return @ptrCast(@alignCast(ctx.?));
        }

        fn isWinner(a: *const Attempt) bool {
            return a.racer.winner == a;
        }
    };

    /// Starts the first attempt. Fails if no address can be tried.
    pub fn init(r: *Racer, gpa: Allocator, io: Io, loop: *xev.Loop, options: Options) !void {
        std.debug.assert(options.addresses.len > 0);
        r.* = .{ .gpa = gpa, .io = io, .loop = loop, .options = options, .timer = try .init() };
        r.startNext(null);
        if (r.live == 0) return error.NoUsableAddress;
    }

    /// Closes every attempt. Run the loop until it has no active
    /// completions, then call `deinit`.
    pub fn stop(r: *Racer) void {
        r.stopping = true;
        for (r.attempts.items) |a| a.endpoint.stop();
        r.cancelTimer();
    }

    pub fn deinit(r: *Racer) void {
        for (r.attempts.items) |a| {
            a.endpoint.deinit();
            a.tls.deinit();
            r.gpa.destroy(a);
        }
        r.attempts.deinit(r.gpa);
        r.timer.deinit();
        r.* = undefined;
    }

    /// True once every attempt's endpoint has stopped and the timer is
    /// idle. The racer can then be freed.
    pub fn isStopped(r: *const Racer) bool {
        for (r.attempts.items) |a| if (!a.endpoint.isStopped()) return false;
        return r.timer_c.state() == .dead and r.timer_reset_c.state() == .dead and r.timer_cancel_c.state() == .dead;
    }

    /// The key the winner's server presented.
    pub fn presentedKey(r: *const Racer) ?[32]u8 {
        const winner = r.winner orelse return null;
        return winner.tls.presentedKey();
    }

    /// The address the winner connected to.
    pub fn address(r: *const Racer) ?IpAddress {
        const winner = r.winner orelse return null;
        return winner.address;
    }

    /// A key a server presented that `Options.accept` refused, if an
    /// attempt failed on one.
    pub fn refusedKey(r: *const Racer) ?[32]u8 {
        for (r.attempts.items) |a| {
            const failure = a.failure orelse continue;
            if (failure != .handshake_failed) continue;
            const key = a.tls.presentedKey() orelse continue;
            if (!accepts(r.options.accept, key)) return key;
        }
        return null;
    }

    fn accepts(accept: quic.Client.Accept, key: [32]u8) bool {
        return switch (accept) {
            .any => true,
            .keys => |keys| for (keys) |k| {
                if (std.mem.eql(u8, &k, &key)) break true;
            } else false,
        };
    }

    /// Starts the attempt for the next address, and arms the timer for the
    /// one after it. Addresses that can't be tried, such as IPv6 on a
    /// machine without it, are passed over. `closing` is the connection of
    /// the attempt that just failed, if one did.
    fn startNext(r: *Racer, closing: ?*Conn) void {
        while (r.next < r.options.addresses.len and !r.stopping) {
            const addr = r.options.addresses[r.next];
            r.next += 1;
            if (r.startAttempt(addr)) {
                r.live += 1;
                // A pending timer is moved: the delay counts from this
                // attempt.
                if (r.next < r.options.addresses.len) {
                    r.timer.reset(r.loop, &r.timer_c, &r.timer_reset_c, attempt_delay_ms, Racer, r, onTimer);
                }
                return;
            } else |err| {
                log.info("can't try {f}: {t}", .{ addr, err });
            }
        }

        // Nothing left to try, and no attempt is running.
        if (r.live == 0 and r.winner == null and !r.stopping) {
            if (closing) |conn| r.allFailed(conn);
        }
    }

    fn startAttempt(r: *Racer, addr: IpAddress) !void {
        // Reserved first: once the endpoint starts, its completions point
        // into the attempt, which is then kept until `deinit`.
        try r.attempts.ensureUnusedCapacity(r.gpa, 1);

        const a = try r.gpa.create(Attempt);
        errdefer r.gpa.destroy(a);
        a.* = .{ .racer = r, .address = addr, .tls = try .init(r.options.accept), .endpoint = undefined };
        errdefer a.tls.deinit();

        // Any local address of the server's family. The kernel picks the
        // port.
        const local: IpAddress = switch (addr) {
            .ip4 => try .parseIp4("0.0.0.0", 0),
            .ip6 => try .parseIp6("::", 0),
        };
        try a.endpoint.init(r.gpa, r.io, r.loop, .{
            .local = local,
            .role = .{ .client = &a.tls },
            .idle_timeout_ns = r.options.idle_timeout_ns,
            .handshake_timeout_ns = r.options.handshake_timeout_ns,
            .keep_alive_ns = r.options.keep_alive_ns,
            .stream_window = r.options.stream_window,
            .connection_window = r.options.connection_window,
            .knock = r.options.knock,
            .handler = .{
                .ctx = a,
                .connected = onConnected,
                .streamOpened = onStreamOpened,
                .data = onData,
                .acked = onAcked,
                .reset = onReset,
                .streamClosed = onStreamClosed,
                .closed = onClosed,
            },
        });
        r.attempts.appendAssumeCapacity(a);

        // Fails only on a local error, before anything is sent.
        _ = a.endpoint.connect(addr) catch |err| {
            a.failure = .failed;
            a.endpoint.stop();
            return err;
        };
    }

    fn cancelTimer(r: *Racer) void {
        if (r.timer_c.state() != .active or r.timer_cancel_c.state() == .active) return;
        r.timer_cancel_c = .{ .op = .{ .cancel = .{ .c = &r.timer_c } } };
        r.loop.add(&r.timer_cancel_c);
    }

    fn onTimer(r_: ?*Racer, _: *xev.Loop, _: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
        const r = r_.?;
        result catch return .disarm;
        if (r.winner == null and !r.stopping) r.startNext(null);
        return .disarm;
    }

    /// Every attempt failed. The last failure is reported, with `conn`,
    /// the connection of the attempt that failed last.
    fn allFailed(r: *Racer, conn: *Conn) void {
        var reason: CloseReason = .failed;
        for (r.attempts.items) |a| reason = a.failure orelse reason;
        if (r.options.handler.closed) |f| f(r.options.handler.ctx, conn, reason);
    }

    // Endpoint callbacks. Before a winner, `connected` and `closed` settle
    // the race. After, the winner's events pass through and the others'
    // are dropped.

    fn onConnected(ctx: ?*anyopaque, conn: *Conn) void {
        const a = Attempt.of(ctx);
        const r = a.racer;
        if (r.winner != null) return conn.close(0);

        r.winner = a;
        r.cancelTimer();
        for (r.attempts.items) |other| {
            if (other != a) other.endpoint.stop();
        }

        if (r.options.handler.connected) |f| f(r.options.handler.ctx, conn);
    }

    fn onClosed(ctx: ?*anyopaque, conn: *Conn, reason: CloseReason) void {
        const a = Attempt.of(ctx);
        const r = a.racer;
        if (a.isWinner()) {
            if (r.options.handler.closed) |f| f(r.options.handler.ctx, conn, reason);
            return;
        }
        if (r.winner != null or a.failure != null) return;

        a.failure = reason;
        r.live -= 1;

        // A failed attempt makes room for the next one at once.
        r.startNext(conn);
    }

    fn onStreamOpened(ctx: ?*anyopaque, stream: *Stream) void {
        const a = Attempt.of(ctx);
        if (!a.isWinner()) return stream.reset(0);
        if (a.racer.options.handler.streamOpened) |f| f(a.racer.options.handler.ctx, stream);
    }

    fn onData(ctx: ?*anyopaque, stream: *Stream, bytes: []const u8, fin: bool) void {
        const a = Attempt.of(ctx);
        if (!a.isWinner()) return;
        if (a.racer.options.handler.data) |f| f(a.racer.options.handler.ctx, stream, bytes, fin);
    }

    fn onAcked(ctx: ?*anyopaque, stream: *Stream) void {
        const a = Attempt.of(ctx);
        if (!a.isWinner()) return;
        if (a.racer.options.handler.acked) |f| f(a.racer.options.handler.ctx, stream);
    }

    fn onReset(ctx: ?*anyopaque, stream: *Stream, app_error_code: u64) void {
        const a = Attempt.of(ctx);
        if (!a.isWinner()) return;
        if (a.racer.options.handler.reset) |f| f(a.racer.options.handler.ctx, stream, app_error_code);
    }

    fn onStreamClosed(ctx: ?*anyopaque, stream: *Stream) void {
        const a = Attempt.of(ctx);
        if (!a.isWinner()) return;
        if (a.racer.options.handler.streamClosed) |f| f(a.racer.options.handler.ctx, stream);
    }
};

/// `addresses` reordered as RFC 8305 §4 describes: alternating families,
/// starting with the family of the first.
pub fn interleave(out: []IpAddress, addresses: []const IpAddress) []IpAddress {
    std.debug.assert(out.len >= addresses.len);
    if (addresses.len == 0) return out[0..0];

    const first_family = std.meta.activeTag(addresses[0]);
    var firsts: usize = 0;
    var others: usize = 0;
    var n: usize = 0;
    while (n < addresses.len) {
        // Take the next address of the family whose turn it is, or of the
        // other family once one runs out.
        const want_first = n % 2 == 0;
        const next = nextOf(addresses, first_family, want_first, &firsts, &others) orelse
            nextOf(addresses, first_family, !want_first, &firsts, &others).?;
        out[n] = next;
        n += 1;
    }
    return out[0..n];
}

fn nextOf(
    addresses: []const IpAddress,
    first_family: std.meta.Tag(IpAddress),
    first: bool,
    firsts: *usize,
    others: *usize,
) ?IpAddress {
    const index = if (first) firsts else others;
    while (index.* < addresses.len) {
        const a = addresses[index.*];
        index.* += 1;
        if ((std.meta.activeTag(a) == first_family) == first) return a;
    }
    return null;
}

const testing = std.testing;

test "addresses alternate families, starting with the first's" {
    const v6a: IpAddress = try .parseIp6("2001:db8::1", 1);
    const v6b: IpAddress = try .parseIp6("2001:db8::2", 1);
    const v4a: IpAddress = try .parseIp4("192.0.2.1", 1);
    const v4b: IpAddress = try .parseIp4("192.0.2.2", 1);
    const v4c: IpAddress = try .parseIp4("192.0.2.3", 1);

    var buf: [8]IpAddress = undefined;
    const got = interleave(&buf, &.{ v6a, v6b, v4a, v4b, v4c });
    try testing.expectEqualSlices(IpAddress, &.{ v6a, v4a, v6b, v4b, v4c }, got);

    const v4_first = interleave(&buf, &.{ v4a, v6a, v6b });
    try testing.expectEqualSlices(IpAddress, &.{ v4a, v6a, v6b }, v4_first);

    try testing.expectEqualSlices(IpAddress, &.{v4a}, interleave(&buf, &.{v4a}));
}

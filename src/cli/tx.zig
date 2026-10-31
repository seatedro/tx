//! tx: a session on a txd server.
//!
//! Usage: tx [SSH OPTIONS] [--attach ID | --new | --list | --kill ID]
//!           DESTINATION [COMMAND...]
//!        tx --version
//!
//! tx takes ssh's options, as ssh reads them, so that tools that run ssh
//! can run tx (see `args.zig`). `-p` is txd's port. It connects to the
//! host, and logs in as the user, that ssh's config gives the destination
//! (see `ssh_config.zig`). With neither `-l` nor a user in the
//! destination or ssh's config, the login names no user, and txd logs in
//! to the account it runs as. tx never runs ssh.
//!
//! With none of `--attach`, `--new`, `--list` and `--kill`, tx attaches to
//! the host's detached session if it has exactly one, and starts a session
//! if it has none.
//!
//! With a command, tx runs it instead, as ssh does: the words after the
//! host, joined with spaces, go to the user's shell with `-c`. The
//! command's stdin, stdout and stderr are tx's, and tx exits with its exit
//! status.
//!
//! With `-t`, the command runs on a terminal: it is a new session's
//! program, attached as any session is. As with ssh, it gets SIGHUP when
//! tx goes: at once when tx exits or detaches, and after a grace period
//! when the connection is lost and tx doesn't come back (see
//! `session.session.hangup_grace_ms`). `-T`, no terminal, is the default,
//! and is accepted for ssh's sake.
//!
//! The server's key is checked against `~/.config/tx/known_hosts` and
//! `~/.ssh/known_hosts`. For a host the first doesn't list, tx learns the
//! key the server presents, and trusts it if the second lists it, as it
//! does for a txd that uses sshd's key, or else asks, as ssh does. A txd
//! that runs as the user has a key of its own, which `txd --install`
//! prints. The key is added to the first file.
//!
//! When nothing answers, tx says how to install txd on the host.
//!
//! A new session gets the client's `TERM`, `COLORTERM`, `LANG` and `LC_*`,
//! and the terminfo entry for its `TERM`, from `infocmp -x`, which txd
//! compiles for the session on a host that may lack it.
//!
//! The login uses the SSH agent's Ed25519 and RSA keys, then
//! `~/.ssh/id_ed25519`.
//!
//! Exits with the program's exit status, or 255 for tx's own failures, as
//! ssh does.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const client = @import("client");
const auth = @import("auth");
const proto = @import("proto");
const build_options = @import("build_options");
const transport = @import("transport");
const paths = @import("paths.zig");
const ssh_config = @import("ssh_config.zig");
const args_pkg = @import("args.zig");

const CloseReason = transport.endpoint.CloseReason;

/// txd's port.
const default_port = 8739;

const usage_text =
    \\usage: tx [SSH OPTIONS] [--attach ID | --new | --list | --kill ID] DESTINATION [COMMAND...]
    \\       tx --version
    \\
    \\The ssh options that take effect: -p PORT (txd's), -l USER, -t, -T, -4, -6,
    \\-i KEY_FILE, -e CHAR, -n, -G, -V and -o with Port, User, IdentityFile and
    \\RequestTTY. DESTINATION is [USER@]HOST or ssh://[USER@]HOST[:PORT].
;

/// How long tx waits for an answer from the server.
const connect_timeout_ns = 15 * std.time.ns_per_s;

/// What sets up txd on a host.
const install_command = "curl -fsSL https://github.com/seatedro/tx/releases/latest/download/install.sh | sh -s -- --txd";

/// Key files tried after the agent's keys, without `-i`.
const default_key_files = [_][]const u8{"~/.ssh/id_ed25519"};

pub fn main(init: std.process.Init) !u8 {
    // First, so every thread inherits the mask: name lookups can start
    // threads, and a terminating signal must reach the session's signal
    // thread, which restores the terminal.
    _ = client.tty.blockSignals();

    const gpa = init.gpa;
    const io = init.io;
    const environ = init.environ_map;
    const arena = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena);

    const args = switch (try args_pkg.parse(arena, argv[1..])) {
        .ok => |a| a,
        .usage => |problem| return usage(problem),
        .unsupported => |option| return fail("{s} isn't supported", .{option}),
    };
    if (args.version) {
        Io.File.stdout().writeStreamingAll(io, "tx " ++ build_options.version ++ "\n") catch return 255;
        return 0;
    }
    for (args.ignored) |letter| std.debug.print("tx: ignoring -{c}, which tx doesn't support yet\n", .{letter});

    // The host and user from ssh's config, as `tx pulsar` should reach
    // what `ssh pulsar` does. A user given to tx wins, as it does in ssh.
    const configured = ssh_config.resolve(arena, io, "ssh", &.{}, args.user, args.host);
    const host = configured.hostname orelse args.host;
    const user = args.user orelse configured.user;
    const port = args.port orelse default_port;
    if (args.print_config) return printConfig(io, environ, user, host, args.port);

    // What to do once logged in. A command runs in a session of its own
    // with a terminal.
    var command: client.session.Command = .attach;
    var session_id: ?u64 = null;
    var session_command: ?[]const u8 = null;
    switch (args.mode) {
        .auto => if (args.command) |words| {
            if (args.tty == true) session_command = words else command = .{ .exec = words };
        },
        .attach => |id| session_id = id,
        .new => {},
        .list => command = .list,
        .kill => |id| command = .{ .kill = id },
    }

    // The destination as given, for messages.
    var destination_buf: [512]u8 = undefined;
    const destination = if (args.user) |u| std.fmt.bufPrint(&destination_buf, "{s}@{s}", .{ u, args.host }) catch args.host else args.host;

    // The host's name in tx's known_hosts, and the file.
    var name_buf: [512]u8 = undefined;
    const known_name = auth.known_hosts.hostName(&name_buf, host, port, default_port) catch return fail("host name too long", .{});
    const tx_known_hosts = try paths.config(gpa, environ, "known_hosts");
    defer gpa.free(tx_known_hosts);

    // With no user given, the login names none, and txd logs in to the
    // account it runs as.
    const login_user = user orelse "";
    if (login_user.len > auth.login.max_user_len) return fail("invalid user name", .{});

    var address_buf: [max_addresses]IpAddress = undefined;
    const addresses = resolve(io, host, port, args.family, &address_buf) catch |err| return fail("can't resolve {s}: {t}", .{ host, err });

    // The keys, before the network: without one there's no login.
    // An empty `SSH_AUTH_SOCK` means no agent, as in ssh.
    const agent_path = if (environ.get("SSH_AUTH_SOCK")) |path| if (path.len > 0) path else null else null;
    const key_files = if (args.key_files.len > 0) args.key_files else &default_key_files;
    var identities = try findIdentities(gpa, io, environ, agent_path, key_files);
    defer identities.deinit(gpa);
    if (identities.list.items.len == 0) {
        return fail("no keys to log in with: the SSH agent has no Ed25519 or RSA keys, and there is no ~/.ssh/id_ed25519", .{});
    }

    // The keys known_hosts lists for the host, or the one it presents
    // that ssh's known_hosts lists or the user accepts.
    const trust = trustedKeys(gpa, io, environ, tx_known_hosts, known_name, addresses) catch |err| {
        return fail("checking the host key failed: {t}", .{err});
    };
    const host_keys = switch (trust) {
        .keys => |keys| keys,
        .declined => return 255,
        .no_answer => |reason| {
            noAnswer(host, args.host, port, reason);
            return 255;
        },
    };
    defer gpa.free(host_keys);

    const term = environ.get("TERM") orelse "xterm-256color";

    // The terminal's colors, for the session's terminal to answer with
    // while no client is attached.
    var typed: std.ArrayList(u8) = .empty;
    const colors: client.report.Colors = if (command == .attach and !std.mem.eql(u8, term, "dumb") and std.c.isatty(std.posix.STDIN_FILENO) != 0)
        try client.report.ask(std.posix.STDIN_FILENO, &typed, arena)
    else
        .{};
    // The macOS pasteboard, for programs on the host. Elsewhere there's
    // none yet.
    var pasteboard: ?client.pasteboard.Pasteboard = if (builtin.os.tag.isDarwin() and command == .attach) client.pasteboard.Pasteboard.general() else null;
    const options: client.session.Options = .{
        .servers = addresses,
        .host_keys = host_keys,
        .user = login_user,
        .agent = agent_path,
        .identities = identities.list.items,
        .command = command,
        .session_id = session_id,
        .session_command = session_command,
        .reuse_detached = args.mode == .auto and args.command == null,
        .show_session_id = session_command == null,
        .term = term,
        .terminfo = if (command == .attach) terminfoSource(arena, io, term) else null,
        .colors = colors,
        .typed = typed.items,
        .colorterm = environ.get("COLORTERM"),
        .locale = try localeVariables(arena, environ),
        .escape_char = args.escape_char,
        .in_fd = if (args.no_stdin) try openNull() else std.posix.STDIN_FILENO,
        .handshake_timeout_ns = connect_timeout_ns,
        .clipboard = if (pasteboard) |*p| p.provider() else null,
    };

    switch (client.session.run(gpa, io, options) catch |err| return fail("{t}", .{err})) {
        .exited => |exit| return exit.status,
        .detached => |id| {
            // The command that reattaches, with the port if it isn't the
            // default.
            var port_buf: [16]u8 = undefined;
            const port_arg = if (port == default_port) "" else std.fmt.bufPrint(&port_buf, "-p {d} ", .{port}) catch unreachable;
            // Before the attach, there's no session to come back to, and a
            // command on a terminal got SIGHUP.
            const n = id orelse return fail("interrupted before the session started", .{});
            if (session_command != null) return 255;
            std.debug.print("tx: detached from session {d}; reattach with tx {s}--attach {d} {s}\n", .{ n, port_arg, n, destination });
            return 0;
        },
        .no_connection => |reason| {
            noAnswer(host, args.host, port, reason);
            return 255;
        },
        .disconnected => |reason| return fail("connection closed: {t}", .{reason}),
        .host_key_refused => |key| {
            std.debug.print(
                \\tx: the host key for {s} has changed, or someone is impersonating the host.
                \\tx: it presented {s}
                \\tx: if the change is expected, remove the host's line from {s}
                \\
            , .{ known_name, auth.Fingerprint.init(key).slice(), tx_known_hosts });
            return 255;
        },
        .refused => |refusal| {
            if (refusal.code == @backingInt(proto.ErrorCode.several_detached)) {
                return fail("{s}; pick one with --attach ID, or start another with --new", .{refusal.message.slice()});
            }
            return fail("{s}", .{refusal.message.slice()});
        },
        .listed => |listed| {
            defer gpa.free(listed);
            printListing(io, listed) catch |err| return fail("writing the list failed: {t}", .{err});
            return 0;
        },
        .killed => |id| {
            std.debug.print("tx: killed session {d}\n", .{id});
            return 0;
        },
        .ended => return 255,
    }
}

/// Says that nothing answered, and how to set up txd on `named`, the host
/// as the user wrote it.
fn noAnswer(host: []const u8, named: []const u8, port: u16, reason: CloseReason) void {
    std.debug.print(
        \\tx: no answer from txd on {s} port {d}: {t}
        \\tx: to install txd and keep it running there, run this on {s}:
        \\    {s}
        \\
    , .{ host, port, reason, named, install_command });
}

/// The environment's `LANG` and `LC_*` variables, as `proto.Hello.locale`
/// carries them. Empty ones are left out. Null if there are none.
fn localeVariables(arena: Allocator, environ: *const std.process.Environ.Map) !?[]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = environ.iterator();
    while (it.next()) |entry| {
        if (!proto.isLocaleName(entry.key_ptr.*) or entry.value_ptr.len == 0) continue;
        try out.print(arena, "{s}={s}\x00", .{ entry.key_ptr.*, entry.value_ptr.* });
    }
    return if (out.items.len == 0) null else out.items;
}

test localeVariables {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var environ: std.process.Environ.Map = .init(std.testing.allocator);
    defer environ.deinit();
    try std.testing.expectEqual(null, try localeVariables(arena.allocator(), &environ));

    try environ.put("LANG", "en_US.UTF-8");
    try environ.put("LC_TIME", "en_GB.UTF-8");
    try environ.put("LC_ALL", "");
    try environ.put("PATH", "/bin");
    const items = (try localeVariables(arena.allocator(), &environ)).?;
    try std.testing.expectEqual(2, std.mem.count(u8, items, "\x00"));
    try std.testing.expect(std.mem.indexOf(u8, items, "LANG=en_US.UTF-8\x00") != null);
    try std.testing.expect(std.mem.indexOf(u8, items, "LC_TIME=en_GB.UTF-8\x00") != null);
}

/// One line per session, under a header.
fn printListing(io: Io, listed: []const client.session.Outcome.Listed) !void {
    var buf: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    if (listed.len == 0) {
        try w.writeAll("no sessions\n");
        return w.flush();
    }

    try w.print("{s:>4}  {s:<9}  {s:<9}  {s:<22}  {s}\n", .{ "ID", "SIZE", "UP", "CLIENT", "TITLE" });
    for (listed) |s| {
        var size_buf: [16]u8 = undefined;
        const size = std.fmt.bufPrint(&size_buf, "{d}x{d}", .{ s.cols, s.rows }) catch unreachable;
        var up_buf: [16]u8 = undefined;
        const client_text = if (s.attached_from) |*from| from.slice() else "detached";
        const title = if (s.title) |*t| t.slice() else "";
        try w.print("{d:>4}  {s:<9}  {s:<9}  {s:<22}  {s}\n", .{ s.session_id, size, formatDuration(&up_buf, s.running_s), client_text, title });
    }
    try w.flush();
}

/// `45s`, `12m`, `3h05m` or `2d04h`.
fn formatDuration(buf: []u8, seconds: u64) []const u8 {
    const m = seconds / 60;
    const h = m / 60;
    const d = h / 24;
    return (if (d > 0)
        std.fmt.bufPrint(buf, "{d}d{d:0>2}h", .{ d, h % 24 })
    else if (h > 0)
        std.fmt.bufPrint(buf, "{d}h{d:0>2}m", .{ h, m % 60 })
    else if (m > 0)
        std.fmt.bufPrint(buf, "{d}m", .{m})
    else
        std.fmt.bufPrint(buf, "{d}s", .{seconds})) catch unreachable;
}

test formatDuration {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("45s", formatDuration(&buf, 45));
    try std.testing.expectEqualStrings("12m", formatDuration(&buf, 12 * 60 + 5));
    try std.testing.expectEqualStrings("3h05m", formatDuration(&buf, 3 * 3600 + 5 * 60));
    try std.testing.expectEqualStrings("2d04h", formatDuration(&buf, 2 * 86400 + 4 * 3600 + 59));
}

/// The most addresses of a host tx tries.
const max_addresses = 8;

/// The addresses `host` resolves to, in the order to try them: the
/// resolver's order, with the two families alternating.
/// With `family`, the addresses of the other are left out.
fn resolve(io: Io, host: []const u8, port: u16, family: ?args_pkg.Family, out: *[max_addresses]IpAddress) ![]IpAddress {
    if (IpAddress.parse(host, port)) |address| {
        if (!inFamily(address, family)) return error.UnknownHostName;
        out[0] = address;
        return out[0..1];
    } else |_| {}

    const name: Io.net.HostName = try .init(host);
    // With room for 16 results, the lookup doesn't block on the queue.
    var buf: [16]Io.net.HostName.LookupResult = undefined;
    var results: Io.Queue(Io.net.HostName.LookupResult) = .init(&buf);
    try name.lookup(io, &results, .{ .port = port });

    // The resolver can list an address more than once.
    var found: [max_addresses]IpAddress = undefined;
    var n: usize = 0;
    while (results.getOne(io)) |result| switch (result) {
        .address => |address| {
            if (!inFamily(address, family)) continue;
            for (found[0..n]) |f| {
                if (std.meta.eql(f, address)) break;
            } else if (n < found.len) {
                found[n] = address;
                n += 1;
            }
        },
        .canonical_name => {},
    } else |err| switch (err) {
        error.Closed => {},
        error.Canceled => |e| return e,
    }
    if (n == 0) return error.UnknownHostName;
    return client.connect.interleave(out, found[0..n]);
}

const Identities = struct {
    list: std.ArrayList(client.session.Identity) = .empty,
    /// The paths of key file identities.
    paths: std.ArrayList([]u8) = .empty,

    fn deinit(ids: *Identities, gpa: Allocator) void {
        for (ids.paths.items) |p| gpa.free(p);
        ids.paths.deinit(gpa);
        ids.list.deinit(gpa);
    }

    fn has(ids: *const Identities, key: *const auth.ssh.PublicKey) bool {
        for (ids.list.items) |*id| if (id.key.eql(key)) return true;
        return false;
    }
};

fn inFamily(address: IpAddress, family: ?args_pkg.Family) bool {
    return switch (family orelse return true) {
        .ip4 => address == .ip4,
        .ip6 => address == .ip6,
    };
}

/// The agent's Ed25519 keys in its order, then the key files that hold
/// other keys. A key file's public key reads without its passphrase.
fn findIdentities(gpa: Allocator, io: Io, environ: *const std.process.Environ.Map, agent_path: ?[]const u8, key_files: []const []const u8) !Identities {
    var ids: Identities = .{};
    errdefer ids.deinit(gpa);

    // An agent that can't be reached leaves the key files.
    if (agent_path) |path| agent: {
        var agent: auth.Agent = auth.Agent.connect(io, path) catch |err| {
            std.debug.print("tx: can't connect to the SSH agent: {t}\n", .{err});
            break :agent;
        };
        defer agent.close();
        var agent_ids = agent.identities(gpa) catch |err| {
            std.debug.print("tx: can't list the SSH agent's keys: {t}\n", .{err});
            break :agent;
        };
        defer agent_ids.deinit(gpa);
        for (agent_ids.blobs) |blob| {
            // Types tx doesn't verify, such as ECDSA, are left out.
            const key = auth.ssh.PublicKey.parse(blob) catch continue;
            try ids.list.append(gpa, .{ .key = key, .source = .agent });
        }
    }

    for (key_files) |file| {
        const path = keyFilePath(gpa, environ, file) catch continue;
        const key = keyFilePublicKey(gpa, io, path) catch |err| {
            if (err != error.FileNotFound) std.debug.print("tx: skipping {s}: {t}\n", .{ path, err });
            gpa.free(path);
            continue;
        };

        // The agent may hold the same key.
        if (ids.has(&key)) {
            gpa.free(path);
            continue;
        }

        // `ids.paths` owns the path from here.
        ids.list.ensureUnusedCapacity(gpa, 1) catch |err| {
            gpa.free(path);
            return err;
        };
        ids.paths.append(gpa, path) catch |err| {
            gpa.free(path);
            return err;
        };
        ids.list.appendAssumeCapacity(.{ .key = key, .source = .{ .file = path } });
    }
    return ids;
}

/// `~/` is the home directory, as ssh reads it in `-i` and `IdentityFile`.
fn keyFilePath(gpa: Allocator, environ: *const std.process.Environ.Map, file: []const u8) ![]u8 {
    if (std.mem.startsWith(u8, file, "~/")) return paths.home(gpa, environ, file[2..]);
    return gpa.dupe(u8, file);
}

/// `-G`: the configuration, as OpenSSH prints it. git runs `-G` to tell
/// OpenSSH from other ssh programs, and passes a port only to OpenSSH.
fn printConfig(io: Io, environ: *const std.process.Environ.Map, user: ?[]const u8, host: []const u8, port: ?u16) u8 {
    var buf: [1024]u8 = undefined;
    var w = Io.File.stdout().writerStreaming(io, &buf);
    w.interface.print("user {s}\nhostname {s}\nport {d}\n", .{
        user orelse paths.userName(environ) orelse "",
        host,
        port orelse default_port,
    }) catch return 255;
    w.interface.flush() catch return 255;
    return 0;
}

/// The terminfo source for `term`, from `infocmp -x`. Null when there's none
/// to send, as without ncurses' tools.
fn terminfoSource(arena: Allocator, io: Io, term: []const u8) ?[]const u8 {
    const result = std.process.run(arena, io, .{
        .argv = &.{ "infocmp", "-x", term },
        .stdout_limit = .limited(server_terminfo_limit),
        .stderr_limit = .limited(4096),
    }) catch return null;
    return if (result.term.success()) result.stdout else null;
}

/// The longest terminfo source txd takes.
const server_terminfo_limit = 64 << 10;

/// `-n`: stdin from /dev/null.
fn openNull() !std.posix.fd_t {
    const fd = std.c.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    if (fd == -1) return error.CantOpenDevNull;
    return fd;
}

fn keyFilePublicKey(gpa: Allocator, io: Io, path: []const u8) !auth.ssh.PublicKey {
    const text = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 << 10));
    defer {
        std.crypto.secureZero(u8, text);
        gpa.free(text);
    }
    var file = try auth.private_key.PrivateKeyFile.parse(gpa, text);
    defer file.deinit(gpa);
    return .fromEd25519(file.public_key);
}

const Trust = union(enum) {
    keys: []auth.Key,
    /// The user declined the key, or it is revoked.
    declined,
    /// The host didn't answer.
    no_answer: CloseReason,
};

/// The keys tx accepts from the host: the ones tx's known_hosts lists, with
/// those ssh's lists. For a host tx's doesn't list, the key the host
/// presents, if ssh's known_hosts lists it or the user accepts it, which is
/// then recorded in `tx_known_hosts`.
fn trustedKeys(
    gpa: Allocator,
    io: Io,
    environ: *const std.process.Environ.Map,
    tx_known_hosts: []const u8,
    name: []const u8,
    addresses: []const IpAddress,
) !Trust {
    var known: auth.known_hosts.Known = .{};
    defer known.deinit(gpa);
    try auth.known_hosts.readFile(io, gpa, tx_known_hosts, name, &known);
    const recorded = known.keys.items.len > 0;
    if (paths.home(gpa, environ, ".ssh/known_hosts")) |ssh_known_hosts| {
        defer gpa.free(ssh_known_hosts);
        try auth.known_hosts.readFile(io, gpa, ssh_known_hosts, name, &known);
    } else |_| {}

    if (recorded) {
        const trusted = try known.trusted(gpa);
        if (trusted.len > 0) return .{ .keys = trusted };
        gpa.free(trusted);
    }

    // First contact: the key the host presents.
    const found = switch (try client.scan.hostKey(gpa, io, addresses, connect_timeout_ns)) {
        .found => |found| found,
        .failed => |reason| return .{ .no_answer = reason },
    };
    const key = found.key;
    switch (firstContact(&known, key)) {
        .revoked => {
            std.debug.print("tx: {s} presented a revoked key, {s}\n", .{ name, auth.Fingerprint.init(key).slice() });
            return .declined;
        },
        .listed => std.debug.print("tx: {s}'s key is one ~/.ssh/known_hosts lists\n", .{name}),
        .unknown => if (!try confirm(io, name, found.address, key)) {
            std.debug.print("tx: host key verification failed\n", .{});
            return .declined;
        },
    }
    try auth.known_hosts.append(io, tx_known_hosts, name, key);
    std.debug.print("tx: added {s} to {s}\n", .{ name, tx_known_hosts });

    const keys = try gpa.alloc(auth.Key, 1);
    keys[0] = key;
    return .{ .keys = keys };
}

/// What first contact makes of the key a host presents, from what the
/// known_hosts files list for the host.
fn firstContact(known: *const auth.known_hosts.Known, key: auth.Key) enum { revoked, listed, unknown } {
    if (known.isRevoked(key)) return .revoked;
    for (known.keys.items) |k| if (std.mem.eql(u8, &k, &key)) return .listed;
    return .unknown;
}

test firstContact {
    const gpa = std.testing.allocator;
    const sshd_key: auth.Key = @splat(1);
    const txd_key: auth.Key = @splat(2);
    var known: auth.known_hosts.Known = .{};
    defer known.deinit(gpa);
    try known.keys.append(gpa, sshd_key);

    // A txd that uses sshd's key, which ssh's known_hosts lists, or one
    // with a key of its own.
    try std.testing.expectEqual(.listed, firstContact(&known, sshd_key));
    try std.testing.expectEqual(.unknown, firstContact(&known, txd_key));

    try known.revoked.append(gpa, txd_key);
    try std.testing.expectEqual(.revoked, firstContact(&known, txd_key));
}

/// Asks on the controlling terminal whether to trust `key`, as ssh does.
/// The answer is `yes`, `no`, or the key's fingerprint.
fn confirm(io: Io, name: []const u8, address: IpAddress, key: auth.Key) !bool {
    const fingerprint = auth.Fingerprint.init(key);

    const tty = Io.Dir.openFileAbsolute(io, "/dev/tty", .{ .mode = .read_write }) catch {
        std.debug.print("tx: {s} isn't in known_hosts, and there's no terminal to ask on. Its key is {s}\n", .{ name, fingerprint.slice() });
        return false;
    };
    defer tty.close(io);

    var write_buf: [1024]u8 = undefined;
    var tw = tty.writerStreaming(io, &write_buf);
    const w = &tw.interface;
    try w.print(
        \\The authenticity of host '{s} ({f})' can't be established.
        \\ED25519 key fingerprint is {s}.
        \\
    , .{ name, address, fingerprint.slice() });
    try w.writeAll("Are you sure you want to continue connecting (yes/no/[fingerprint])? ");

    var read_buf: [256]u8 = undefined;
    var tr = tty.readerStreaming(io, &read_buf);
    while (true) {
        try w.flush();

        // End of input declines.
        const line = (tr.interface.takeDelimiter('\n') catch return false) orelse return false;
        const answer = std.mem.trim(u8, line, " \t\r");
        if (std.ascii.eqlIgnoreCase(answer, "yes") or std.mem.eql(u8, answer, fingerprint.slice())) return true;
        if (std.ascii.eqlIgnoreCase(answer, "no")) return false;
        try w.writeAll("Please type 'yes', 'no' or the fingerprint: ");
    }
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print("tx: " ++ format ++ "\n", args);
    return 255;
}

fn usage(reason: []const u8) u8 {
    std.debug.print("tx: {s}\n" ++ usage_text ++ "\n", .{reason});
    return 255;
}

test {
    // Analyzes `main`, and through it the crypto module, whose exports the
    // linked C code needs.
    _ = &main;
    _ = args_pkg;
    _ = @import("getopt.zig");
    _ = ssh_config;
}

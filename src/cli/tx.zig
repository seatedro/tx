//! tx: a session on a tx-session server.
//!
//! Usage: tx [-p PORT] [-l USER] [--attach ID | --new | --list | --kill ID]
//!           [--server COMMAND] [--ssh PATH] [USER@]HOST
//!
//! With none of `--attach`, `--new`, `--list` and `--kill`, tx attaches to
//! the host's detached session if it has exactly one, and starts a session
//! if it has none.
//!
//! The server's key is checked against `~/.config/tx/known_hosts` and
//! `~/.ssh/known_hosts`. For a host in neither, tx reads the key over ssh
//! with `tx-session --print-host-key`, so ssh's own host check vouches for
//! it. If that fails, tx asks, as ssh does. The key is added to the first
//! file.
//!
//! The login uses the SSH agent's Ed25519 and RSA keys, then
//! `~/.ssh/id_ed25519`.
//!
//! Exits with the program's exit status, or 255 for tx's own failures, as
//! ssh does.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const client = @import("client");
const auth = @import("auth");
const proto = @import("proto");
const paths = @import("paths.zig");

/// tx-session's default port.
const default_port = 8739;

const usage_text = "usage: tx [-p PORT] [-l USER] [--attach ID | --new | --list | --kill ID] [--server COMMAND] [--ssh PATH] [USER@]HOST";

/// Key files tried after the agent's keys, under HOME.
const default_key_files = [_][]const u8{".ssh/id_ed25519"};

pub fn main(init: std.process.Init) !u8 {
    // First, so every thread inherits the mask: name lookups can start
    // threads, and a terminating signal must reach the session's signal
    // thread, which restores the terminal.
    _ = client.tty.blockSignals();

    const gpa = init.gpa;
    const io = init.io;
    const environ = init.environ_map;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // Options, then one destination.
    var port: u16 = default_port;
    var user: ?[]const u8 = null;
    var session_id: ?u64 = null;
    var command: client.session.Command = .attach;
    var new = false;
    // `--attach`, `--new`, `--list` and `--kill` exclude each other.
    var modes: usize = 0;
    var server_command: []const u8 = "tx-session";
    var ssh_path: []const u8 = "ssh";
    var destination: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-p") and i + 1 < args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, args[i], 10) catch return usage("invalid port");
        } else if (std.mem.eql(u8, arg, "-l") and i + 1 < args.len) {
            i += 1;
            user = args[i];
        } else if (std.mem.eql(u8, arg, "--attach") and i + 1 < args.len) {
            i += 1;
            session_id = std.fmt.parseInt(u64, args[i], 10) catch return usage("invalid session id");
            modes += 1;
        } else if (std.mem.eql(u8, arg, "--new")) {
            new = true;
            modes += 1;
        } else if (std.mem.eql(u8, arg, "--list")) {
            command = .list;
            modes += 1;
        } else if (std.mem.eql(u8, arg, "--kill") and i + 1 < args.len) {
            i += 1;
            command = .{ .kill = std.fmt.parseInt(u64, args[i], 10) catch return usage("invalid session id") };
            modes += 1;
        } else if (std.mem.eql(u8, arg, "--server") and i + 1 < args.len) {
            i += 1;
            server_command = args[i];
        } else if (std.mem.eql(u8, arg, "--ssh") and i + 1 < args.len) {
            i += 1;
            ssh_path = args[i];
        } else if (destination == null and !std.mem.startsWith(u8, arg, "-")) {
            destination = arg;
        } else return usage("unknown argument");
    }

    if (modes > 1) return usage("--attach, --new, --list and --kill don't go together");

    // `user@host`. A `-l` user wins, as in ssh.
    var host = destination orelse return usage("no host");
    if (std.mem.lastIndexOfScalar(u8, host, '@')) |at| {
        if (user == null) user = host[0..at];
        host = host[at + 1 ..];
    }
    const login_user = user orelse paths.userName(environ) orelse return fail("can't tell the local user name; use -l", .{});
    if (login_user.len == 0 or login_user.len > auth.login.max_user_len) return fail("invalid user name", .{});

    var address_buf: [max_addresses]IpAddress = undefined;
    const addresses = resolve(io, host, port, &address_buf) catch |err| return fail("can't resolve {s}: {t}", .{ host, err });

    // The keys, before the network: without one there's no login.
    // An empty `SSH_AUTH_SOCK` means no agent, as in ssh.
    const agent_path = if (environ.get("SSH_AUTH_SOCK")) |path| if (path.len > 0) path else null else null;
    var identities = try findIdentities(gpa, io, environ, agent_path);
    defer identities.deinit(gpa);
    if (identities.list.items.len == 0) return fail("no keys to log in with: the SSH agent has no Ed25519 or RSA keys, and there is no ~/.ssh/id_ed25519", .{});

    // ssh logs in to the same account, unless its config says otherwise.
    var ssh_buf: [512]u8 = undefined;
    const ssh_destination = if (user) |u| std.fmt.bufPrint(&ssh_buf, "{s}@{s}", .{ u, host }) catch host else host;

    // The keys known_hosts lists for the host, or the one the user accepts.
    var name_buf: [512]u8 = undefined;
    const known_name = auth.known_hosts.hostName(&name_buf, host, port, default_port) catch return fail("host name too long", .{});
    const tx_known_hosts = try paths.config(gpa, environ, "known_hosts");
    defer gpa.free(tx_known_hosts);
    const host_keys = trustedKeys(gpa, io, environ, tx_known_hosts, known_name, addresses, .{
        .ssh = ssh_path,
        .destination = ssh_destination,
        .server_command = server_command,
    }) catch |err| switch (err) {
        error.Declined => return 255,
        else => return fail("checking the host key failed: {t}", .{err}),
    };
    defer gpa.free(host_keys);

    const outcome = client.session.run(gpa, io, .{
        .servers = addresses,
        .host_keys = host_keys,
        .user = login_user,
        .agent = agent_path,
        .identities = identities.list.items,
        .command = command,
        .session_id = session_id,
        .reuse_detached = session_id == null and !new,
        .show_session_id = true,
        .term = environ.get("TERM") orelse "xterm-256color",
        .colorterm = environ.get("COLORTERM"),
    }) catch |err| return fail("{t}", .{err});

    switch (outcome) {
        .exited => |exit| return exit.status,
        .detached => |id| {
            // The command that reattaches, with the port if it isn't the
            // default.
            var port_buf: [16]u8 = undefined;
            const port_arg = if (port == default_port) "" else std.fmt.bufPrint(&port_buf, "-p {d} ", .{port}) catch unreachable;
            // Before the attach, there's no session to come back to.
            const n = id orelse return fail("interrupted before the session started", .{});
            std.debug.print("tx: detached from session {d}; reattach with tx {s}--attach {d} {s}\n", .{ n, port_arg, n, destination.? });
            return 0;
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
    }
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
fn resolve(io: Io, host: []const u8, port: u16, out: *[max_addresses]IpAddress) ![]IpAddress {
    if (IpAddress.parse(host, port)) |address| {
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

/// The agent's Ed25519 keys in its order, then the default key files that
/// hold other keys. A key file's public key reads without its passphrase.
fn findIdentities(gpa: Allocator, io: Io, environ: *const std.process.Environ.Map, agent_path: ?[]const u8) !Identities {
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

    for (default_key_files) |sub_path| {
        const path = paths.home(gpa, environ, sub_path) catch continue;
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

/// Where to read the host key over ssh.
const SshSource = struct {
    /// The ssh client.
    ssh: []const u8,
    /// `host` or `user@host`, as ssh takes it.
    destination: []const u8,
    /// tx-session on the remote side.
    server_command: []const u8,
};

/// Reads tx-session's host key from the remote account over ssh. ssh's own
/// host key check vouches for the connection, so the key needs no prompt.
fn hostKeyOverSsh(gpa: Allocator, io: Io, source: SshSource) !auth.Key {
    const command = try std.fmt.allocPrint(gpa, "{s} --print-host-key", .{source.server_command});
    defer gpa.free(command);

    // ssh asks for passwords and its own host keys on the terminal, not on
    // stdin.
    const result = try std.process.run(gpa, io, .{
        .argv = &.{ source.ssh, "-T", "-o", "ConnectTimeout=10", "--", source.destination, command },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(16 << 10),
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    const ok = switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        const message = std.mem.trim(u8, result.stderr, " \t\r\n");
        if (message.len > 0) std.debug.print("{s}\n", .{message});
        return error.SshFailed;
    }

    // `ssh-ed25519 AAAA...`.
    var fields = std.mem.tokenizeAny(u8, result.stdout, " \t\r\n");
    const key_type = fields.next() orelse return error.NoKeyPrinted;
    const text = fields.next() orelse return error.NoKeyPrinted;
    return auth.ssh.parseKeyText(key_type, text);
}

/// The keys tx accepts from the host. When no file lists one, reads the
/// host's key over ssh, or else learns it and asks the user, and records
/// it in `tx_known_hosts`.
fn trustedKeys(
    gpa: Allocator,
    io: Io,
    environ: *const std.process.Environ.Map,
    tx_known_hosts: []const u8,
    name: []const u8,
    addresses: []const IpAddress,
    ssh: SshSource,
) ![]auth.Key {
    var known: auth.known_hosts.Known = .{};
    defer known.deinit(gpa);
    try auth.known_hosts.readFile(io, gpa, tx_known_hosts, name, &known);
    if (paths.home(gpa, environ, ".ssh/known_hosts")) |ssh_known_hosts| {
        defer gpa.free(ssh_known_hosts);
        try auth.known_hosts.readFile(io, gpa, ssh_known_hosts, name, &known);
    } else |_| {}

    const trusted = try known.trusted(gpa);
    if (trusted.len > 0) return trusted;
    gpa.free(trusted);

    // First contact, over ssh if it can log in.
    if (hostKeyOverSsh(gpa, io, ssh)) |key| {
        if (known.isRevoked(key)) {
            std.debug.print("tx: {s} has a revoked key, {s}\n", .{ name, auth.Fingerprint.init(key).slice() });
            return error.Declined;
        }
        try auth.known_hosts.append(io, tx_known_hosts, name, key);
        std.debug.print("tx: added {s} to {s}, with the key read over ssh\n", .{ name, tx_known_hosts });

        const keys = try gpa.alloc(auth.Key, 1);
        keys[0] = key;
        return keys;
    } else |err| {
        std.debug.print("tx: can't read the host key over ssh: {t}\n", .{err});
    }

    // Otherwise the server's own word, checked by the user.
    const found = switch (try client.scan.hostKey(gpa, io, addresses, 10 * std.time.ns_per_s)) {
        .found => |found| found,
        .failed => |reason| {
            std.debug.print("tx: can't reach {s}: {t}\n", .{ name, reason });
            return error.Declined;
        },
    };
    const key = found.key;
    if (known.isRevoked(key)) {
        std.debug.print("tx: {s} presented a revoked key, {s}\n", .{ name, auth.Fingerprint.init(key).slice() });
        return error.Declined;
    }

    if (!try confirm(io, name, found.address, key)) {
        std.debug.print("tx: host key verification failed\n", .{});
        return error.Declined;
    }
    try auth.known_hosts.append(io, tx_known_hosts, name, key);
    std.debug.print("tx: added {s} to {s}\n", .{ name, tx_known_hosts });

    const keys = try gpa.alloc(auth.Key, 1);
    keys[0] = key;
    return keys;
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
}

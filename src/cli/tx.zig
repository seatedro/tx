//! tx's main. It takes ssh's command line (args.zig), so git and rsync can
//! run it as their ssh, and resolves the host from tx's and ssh's config
//! (ssh_config.zig). It picks login keys from the SSH agent and key files,
//! decides which txd host keys to trust (tailscale.zig on first contact),
//! then runs client.session and reports how it ended. As in ssh, the exit
//! status is the remote command's, or 255 when tx fails.

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
const tailscale = @import("tailscale.zig");
const args_pkg = @import("args.zig");

const CloseReason = transport.endpoint.CloseReason;

/// txd's default port, also in txd.zig. known_hosts names omit it.
const default_port = 8739;

const usage_text =
    \\usage: tx [SSH OPTIONS] [--attach ID | --new | --list | --kill ID] DESTINATION [COMMAND...]
    \\       tx --version
    \\
    \\The ssh options that take effect: -p PORT (txd's), -l USER, -t, -T, -4, -6,
    \\-i KEY_FILE, -F CONFIG_FILE, -e CHAR, -n, -G, -V and -o with Port, User,
    \\IdentityFile and RequestTTY. DESTINATION is [USER@]HOST or
    \\ssh://[USER@]HOST[:PORT].
;

const connect_timeout_ns = 15 * std.time.ns_per_s;

/// Printed when txd doesn't answer. With --txd, install.sh also runs
/// txd --install.
const install_command = "curl -fsSL https://github.com/seatedro/tx/releases/latest/download/install.sh | sh -s -- --txd";

/// Used when no -i or IdentityFile names a key file. tx reads only Ed25519
/// private key files.
const default_key_files = [_][]const u8{"~/.ssh/id_ed25519"};

pub fn main(init: std.process.Init) !u8 {
    // Blocks the signals tty.Signals takes with sigwait, before any thread
    // starts. signal_mask is the mask from before, for Match exec's shell.
    const signal_mask = client.tty.blockSignals();

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

    const configured = switch (try ssh_config.resolve(arena, io, .{
        .host = args.host,
        .user = args.user,
        .port = args.port,
        .default_port = default_port,
        .identity_files = args.key_files,
        .default_identity_files = &default_key_files,
        .ssh_config = args.ssh_config,
        .environ = environ,
        .signal_mask = signal_mask,
    })) {
        .ok => |resolved| resolved,
        .bad => |problem| return fail("{s}", .{problem}),
    };
    for (configured.warnings) |warning| std.debug.print("tx: {s}\n", .{warning});
    const host = configured.hostname;
    const user = configured.user;
    const port = configured.port;
    if (args.print_config) return printConfig(io, environ, configured);
    if (configured.proxy_jump) |jump| {
        std.debug.print("tx: ignoring ProxyJump {s}, which tx doesn't support yet; connecting directly\n", .{jump});
    }

    // Under -t a command runs as a session's program, on a terminal. Without
    // -t it runs on its own with stdin, stdout and stderr streams, as ssh
    // runs a command without a pty.
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

    // The destination as typed, for the reattach hint.
    var destination_buf: [512]u8 = undefined;
    const destination = if (args.user) |u| std.fmt.bufPrint(&destination_buf, "{s}@{s}", .{ u, args.host }) catch args.host else args.host;

    var name_buf: [512]u8 = undefined;
    const known_name = auth.known_hosts.hostName(&name_buf, host, port, default_port) catch return fail("host name too long", .{});
    const tx_known_hosts = try paths.config(gpa, environ, "known_hosts");
    defer gpa.free(tx_known_hosts);

    // An empty user logs in to the account txd runs as.
    const login_user = user orelse "";
    if (login_user.len > auth.login.max_user_len) return fail("invalid user name", .{});

    var address_buf: [max_addresses]IpAddress = undefined;
    const addresses = resolve(io, host, port, args.family, &address_buf) catch |err| return fail("can't resolve {s}: {t}", .{ host, err });

    const agent_path = agentPath(environ, configured.identity_agent);
    var identities = try findIdentities(gpa, io, agent_path, configured.identity_files, configured.identities_only);
    defer identities.deinit(gpa);
    if (identities.list.items.len == 0) {
        if (configured.identities_only) return fail("no keys to log in with: of the SSH agent's keys, IdentitiesOnly allows only the ones the key files name, and no key file holds an Ed25519 key", .{});
        return fail("no keys to log in with: the SSH agent has no Ed25519 or RSA keys, and no key file holds an Ed25519 key", .{});
    }

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

    // report.ask reads the terminal's colors for the session. Input typed
    // while it waits for the replies lands in typed, and the session sends it
    // once attached.
    var typed: std.ArrayList(u8) = .empty;
    const colors: client.report.Colors = if (command == .attach and !std.mem.eql(u8, term, "dumb") and std.c.isatty(std.posix.STDIN_FILENO) != 0)
        try client.report.ask(std.posix.STDIN_FILENO, &typed, arena)
    else
        .{};
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
            var port_buf: [16]u8 = undefined;
            const port_arg = if (port == default_port) "" else std.fmt.bufPrint(&port_buf, "-p {d} ", .{port}) catch unreachable;
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
            // server/root.zig's message lists the detached sessions.
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

/// host is the resolved host name, and named is the host as typed.
fn noAnswer(host: []const u8, named: []const u8, port: u16, reason: CloseReason) void {
    std.debug.print(
        \\tx: no answer from txd on {s} port {d}: {t}
        \\tx: to install txd and keep it running there, run this on {s}:
        \\    {s}
        \\
    , .{ host, port, reason, named, install_command });
}

/// The locale variables that have values, as NAME=value entries that each end
/// in NUL. The server's clientEnviron reads this format.
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

const max_addresses = 8;

fn resolve(io: Io, host: []const u8, port: u16, family: ?args_pkg.Family, out: *[max_addresses]IpAddress) ![]IpAddress {
    if (IpAddress.parse(host, port)) |address| {
        if (!inFamily(address, family)) return error.UnknownHostName;
        out[0] = address;
        return out[0..1];
    } else |_| {}

    // HostName.lookup doesn't block on a queue with room for 16 results. The
    // results are read after it returns.
    const name: Io.net.HostName = try .init(host);
    var buf: [16]Io.net.HostName.LookupResult = undefined;
    var results: Io.Queue(Io.net.HostName.LookupResult) = .init(&buf);
    try name.lookup(io, &results, .{ .port = port });

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
    // Alternates the address families for connect.zig's race.
    return client.connect.interleave(out, found[0..n]);
}

/// paths owns the file names that list's .file sources point at.
const Identities = struct {
    list: std.ArrayList(client.session.Identity) = .empty,
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

fn agentPath(environ: *const std.process.Environ.Map, configured: ?ssh_config.IdentityAgent) ?[]const u8 {
    if (configured) |agent| return switch (agent) {
        .none => null,
        .path => |path| path,
    };
    const path = environ.get("SSH_AUTH_SOCK") orelse return null;
    return if (path.len > 0) path else null;
}

test agentPath {
    var environ: std.process.Environ.Map = .init(std.testing.allocator);
    defer environ.deinit();
    try std.testing.expectEqual(null, agentPath(&environ, null));
    try environ.put("SSH_AUTH_SOCK", "");
    try std.testing.expectEqual(null, agentPath(&environ, null));
    try environ.put("SSH_AUTH_SOCK", "/env.sock");
    try std.testing.expectEqualStrings("/env.sock", agentPath(&environ, null).?);

    try std.testing.expectEqualStrings("/config.sock", agentPath(&environ, .{ .path = "/config.sock" }).?);
    try std.testing.expectEqual(null, agentPath(&environ, .none));
}

/// The agent's keys, then the keys of key files that the agent doesn't hold.
/// The session offers them in this order. With IdentitiesOnly, the agent's
/// keys are limited to the ones key_files name.
fn findIdentities(gpa: Allocator, io: Io, agent_path: ?[]const u8, key_files: []const []const u8, identities_only: bool) !Identities {
    var ids: Identities = .{};
    errdefer ids.deinit(gpa);

    var named: std.ArrayList(auth.ssh.PublicKey) = .empty;
    defer named.deinit(gpa);
    if (identities_only) for (key_files) |file| {
        if (namedKey(gpa, io, file)) |key| try named.append(gpa, key);
    };

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
            const key = auth.ssh.PublicKey.parse(blob) catch continue;
            if (identities_only and !containsKey(named.items, &key)) continue;
            try ids.list.append(gpa, .{ .key = key, .source = .agent });
        }
    }

    for (key_files) |file| {
        const key = keyFilePublicKey(gpa, io, file) catch |err| {
            // No warning for a missing file, or for one tx can't read, such as
            // an RSA key file, when the agent holds its key.
            const in_agent = if (publicKeyOf(gpa, io, file)) |public_key| ids.has(&public_key) else |_| false;
            if (err != error.FileNotFound and !in_agent) std.debug.print("tx: skipping {s}: {t}\n", .{ file, err });
            continue;
        };

        if (ids.has(&key)) continue;

        const path = try gpa.dupe(u8, file);
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

test "IdentitiesOnly limits the agent's keys to the ones the key files name" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const keys = [_]std.crypto.sign.Ed25519.KeyPair{ .generate(io), .generate(io) };
    const agent_path = try std.fs.path.join(a, &.{ dir, "agent.sock" });
    var agent: auth.agent.TestAgent = undefined;
    try agent.start(io, agent_path, &keys);
    defer agent.stop(agent_path);

    try tmp.dir.writeFile(io, .{
        .sub_path = "second.pub",
        .data = try std.fmt.allocPrint(a, "ssh-ed25519 {s} second\n", .{auth.ssh.KeyText.init(keys[1].public_key.toBytes()).slice()}),
    });
    const beside = [_][]const u8{try std.fs.path.join(a, &.{ dir, "second" })};
    const public = [_][]const u8{try std.fs.path.join(a, &.{ dir, "second.pub" })};

    var all = try findIdentities(gpa, io, agent_path, &beside, false);
    defer all.deinit(gpa);
    try std.testing.expectEqual(2, all.list.items.len);

    for ([_][]const []const u8{ &beside, &public }) |key_files| {
        var only = try findIdentities(gpa, io, agent_path, key_files, true);
        defer only.deinit(gpa);
        try std.testing.expectEqual(1, only.list.items.len);
        try std.testing.expectEqual(keys[1].public_key.toBytes(), only.list.items[0].key.ed25519Key());
        try std.testing.expectEqual(.agent, only.list.items[0].source);
    }
}

fn containsKey(keys: []const auth.ssh.PublicKey, key: *const auth.ssh.PublicKey) bool {
    for (keys) |*k| if (k.eql(key)) return true;
    return false;
}

/// The key a key file names for IdentitiesOnly: the public key in a private
/// key file, else a public key at path or at path.pub.
fn namedKey(gpa: Allocator, io: Io, path: []const u8) ?auth.ssh.PublicKey {
    if (keyFilePublicKey(gpa, io, path)) |key| return key else |_| {}
    return publicKeyOf(gpa, io, path) catch null;
}

fn publicKeyOf(gpa: Allocator, io: Io, path: []const u8) !auth.ssh.PublicKey {
    if (publicKeyFile(gpa, io, path)) |key| return key else |_| {}
    const pub_path = try std.mem.concat(gpa, u8, &.{ path, ".pub" });
    defer gpa.free(pub_path);
    return publicKeyFile(gpa, io, pub_path);
}

fn publicKeyFile(gpa: Allocator, io: Io, path: []const u8) !auth.ssh.PublicKey {
    const text = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 << 10));
    // path may name a private key file.
    defer {
        std.crypto.secureZero(u8, text);
        gpa.free(text);
    }
    var fields = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const key_type = fields.next() orelse return error.Malformed;
    const encoded = fields.next() orelse return error.Malformed;
    return auth.ssh.parsePublicKeyText(key_type, encoded);
}

fn printConfig(io: Io, environ: *const std.process.Environ.Map, configured: ssh_config.Resolved) u8 {
    var buf: [1024]u8 = undefined;
    var w = Io.File.stdout().writerStreaming(io, &buf);
    writeConfig(&w.interface, paths.userName(environ), configured) catch return 255;
    w.interface.flush() catch return 255;
    return 0;
}

/// The settings tx resolves, in ssh -G's format.
fn writeConfig(w: *Io.Writer, local_user: ?[]const u8, configured: ssh_config.Resolved) Io.Writer.Error!void {
    try w.print("user {s}\nhostname {s}\nport {d}\n", .{ configured.user orelse local_user orelse "", configured.hostname, configured.port });
    for (configured.identity_files) |file| try w.print("identityfile {s}\n", .{file});
    try w.print("identitiesonly {s}\n", .{if (configured.identities_only) "yes" else "no"});
    if (configured.identity_agent) |agent| switch (agent) {
        .none => try w.writeAll("identityagent none\n"),
        .path => |path| try w.print("identityagent {s}\n", .{path}),
    };
    if (configured.proxy_jump) |jump| try w.print("proxyjump {s}\n", .{jump});
}

test writeConfig {
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeConfig(&w, "local", .{
        .hostname = "real.example.com",
        .user = null,
        .port = 8739,
        .identity_files = &.{ "/keys/a", "/keys/b" },
        .identities_only = true,
        .identity_agent = .none,
        .proxy_jump = "bastion",
        .warnings = &.{},
    });
    try std.testing.expectEqualStrings(
        \\user local
        \\hostname real.example.com
        \\port 8739
        \\identityfile /keys/a
        \\identityfile /keys/b
        \\identitiesonly yes
        \\identityagent none
        \\proxyjump bastion
        \\
    , w.buffered());
}

/// The terminfo entry for term, with extended capabilities, for the server to
/// compile with tic. null when infocmp fails or the entry is too long.
fn terminfoSource(arena: Allocator, io: Io, term: []const u8) ?[]const u8 {
    const result = std.process.run(arena, io, .{
        .argv = &.{ "infocmp", "-x", term },
        .stdout_limit = .limited(server_terminfo_limit),
        .stderr_limit = .limited(4096),
    }) catch return null;
    return if (result.term.success()) result.stdout else null;
}

/// server/terminfo.zig's max_source_len. The server refuses longer entries.
const server_terminfo_limit = 64 << 10;

fn openNull() !std.posix.fd_t {
    const fd = std.c.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    if (fd == -1) return error.CantOpenDevNull;
    return fd;
}

/// The public key an OpenSSH private key file stores in the clear, read
/// without the passphrase.
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
    /// Allocated with gpa.
    keys: []auth.Key,
    declined,
    no_answer: CloseReason,
};

/// The host keys to accept from txd. When tx's known_hosts has no trusted key
/// for name, tx connects once to learn txd's key. It accepts the key if
/// ~/.ssh/known_hosts lists it, Tailscale says the address is one of the
/// user's nodes, or the user says yes, and records it in tx's known_hosts.
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
    // Keys from ~/.ssh/known_hosts alone don't skip first contact. txd has a
    // host key of its own, and a different key listed there doesn't refuse it.
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
        .unknown => {
            var arena: std.heap.ArenaAllocator = .init(gpa);
            defer arena.deinit();
            if (tailscale.ownNode(arena.allocator(), io, found.address)) |node| {
                std.debug.print("tx: Tailscale says {s} is {s}, a node of yours\n", .{ name, node });
            } else if (!try confirm(io, name, found.address, key)) {
                std.debug.print("tx: host key verification failed\n", .{});
                return .declined;
            }
        },
    }
    try auth.known_hosts.append(io, tx_known_hosts, name, key);
    std.debug.print("tx: added {s} to {s}\n", .{ name, tx_known_hosts });

    const keys = try gpa.alloc(auth.Key, 1);
    keys[0] = key;
    return .{ .keys = keys };
}

/// Called when tx's known_hosts has no trusted key for the host. A listed key
/// is then one that ~/.ssh/known_hosts lists.
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

    try std.testing.expectEqual(.listed, firstContact(&known, sshd_key));
    try std.testing.expectEqual(.unknown, firstContact(&known, txd_key));

    try known.revoked.append(gpa, txd_key);
    try std.testing.expectEqual(.revoked, firstContact(&known, txd_key));
}

/// Asks in ssh's words whether to trust key. "yes" or the fingerprint accepts
/// it, and "no" or the end of input declines.
fn confirm(io: Io, name: []const u8, address: IpAddress, key: auth.Key) !bool {
    const fingerprint = auth.Fingerprint.init(key);

    // /dev/tty reaches the user when stdin and stdout are pipes.
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

// cli-test's root is this file. These references bring in the other files'
// tests.
test {
    _ = &main;
    _ = args_pkg;
    _ = @import("getopt.zig");
    _ = ssh_config;
    _ = tailscale;
}

//! tx-session: serves the user's sessions over QUIC.
//!
//! Usage: tx-session [--listen ADDRESS:PORT] [--key PATH]
//!
//! Personal mode: clients log in as the user running tx-session, with a key
//! from `~/.config/tx/authorized_keys` if that file exists, or else from
//! `~/.ssh/authorized_keys`. It listens on every address by default.
const std = @import("std");
const Io = std.Io;
const xev = @import("xev");
const server_pkg = @import("server");
const transport = @import("transport");
const auth = @import("auth");
const keyfile = @import("keyfile.zig");
const paths = @import("paths.zig");

/// Below the ephemeral port ranges of Linux and macOS.
pub const default_port = 8739;

/// Variables a session inherits from tx-session's environment.
const inherited = [_][]const u8{ "HOME", "USER", "LOGNAME", "SHELL", "PATH", "TZ", "LANG" };

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // Options. IPv6's any address takes IPv4 connections too, unless the
    // system turns that off.
    var listen: Io.net.IpAddress = try .parseIp6("::", default_port);
    var key_path: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--listen") and i + 1 < args.len) {
            i += 1;
            listen = Io.net.IpAddress.parseLiteral(args[i]) catch return usage("invalid address");
        } else if (std.mem.eql(u8, arg, "--key") and i + 1 < args.len) {
            i += 1;
            key_path = args[i];
        } else return usage("unknown argument");
    }

    transport.crypto.init(io);

    // The first run creates the key.
    const path = key_path orelse try paths.state(gpa, init.environ_map, "host_key");
    defer if (key_path == null) gpa.free(path);
    const identity = try keyfile.loadOrCreate(io, path);

    const user = paths.userName(init.environ_map) orelse {
        std.debug.print("tx-session: can't tell the user name\n", .{});
        return 1;
    };
    const tx_authorized_keys = try paths.config(gpa, init.environ_map, "authorized_keys");
    defer gpa.free(tx_authorized_keys);
    const ssh_authorized_keys = try paths.home(gpa, init.environ_map, ".ssh/authorized_keys");
    defer gpa.free(ssh_authorized_keys);

    // Sessions get a small environment, like the one sshd gives: the
    // allowlist, the locale, and TX_SESSION. Each session adds TERM and
    // COLORTERM from its client.
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    for (inherited) |name| if (init.environ_map.get(name)) |value| try environ.put(name, value);
    var it = init.environ_map.iterator();
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "LC_")) try environ.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    try environ.put("TX_SESSION", "1");

    // A login shell: argv[0] is the shell's name with a leading "-".
    const shell = init.environ_map.get("SHELL") orelse "/bin/sh";
    const login_name = try std.fmt.allocPrint(gpa, "-{s}", .{std.fs.path.basename(shell)});
    defer gpa.free(login_name);

    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();

    var server: server_pkg.Server = undefined;
    try server.init(gpa, io, &loop, .{
        .listen = listen,
        .identity = identity,
        .user = user,
        .authorized_keys = &.{ tx_authorized_keys, ssh_authorized_keys },
        .environ = &environ,
        .argv = &.{login_name},
        .program = shell,
        .cwd = if (init.environ_map.get("HOME")) |home| .{ .path = home } else .inherit,
    });
    defer server.deinit();

    std.log.info("listening on {f} for {s}, host key {s}", .{ server.address(), user, auth.Fingerprint.init(identity.public_key.toBytes()).slice() });
    try loop.run(.until_done);
    return 0;
}

fn usage(reason: []const u8) u8 {
    std.debug.print("tx-session: {s}\nusage: tx-session [--listen ADDRESS:PORT] [--key PATH]\n", .{reason});
    return 2;
}

//! txd: serves the user's sessions over QUIC.
//!
//! Usage: txd [--listen ADDRESS:PORT] [--key PATH] [--print-host-key]
//!            [--install]
//!
//! Personal mode: clients log in as the user running txd, with a key
//! from `~/.config/tx/authorized_keys` if that file exists, or else from
//! `~/.ssh/authorized_keys`. It listens on every address by default.
//!
//! `--print-host-key` prints the public host key as `ssh-ed25519 AAAA...`
//! and exits, creating the key if there is none. `tx` runs it over ssh to
//! learn a new host's key.
//!
//! `--install` sets up a service that keeps txd running with the
//! given `--listen` and `--key`, starts it if it isn't running, and exits;
//! see `install.zig`. With `--print-host-key`, the key is printed first.
const std = @import("std");
const Io = std.Io;
const xev = @import("xev");
const server_pkg = @import("server");
const transport = @import("transport");
const auth = @import("auth");
const install = @import("install.zig");
const keyfile = @import("keyfile.zig");
const paths = @import("paths.zig");

/// Below the ephemeral port ranges of Linux and macOS.
pub const default_port = 8739;

/// Variables a session inherits from txd's environment.
const inherited = [_][]const u8{ "HOME", "USER", "LOGNAME", "SHELL", "PATH", "TZ", "LANG" };

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // Options. `::` covers every IPv4 and IPv6 address.
    var listen: Io.net.IpAddress = try .parseIp6("::", default_port);
    var key_path: ?[]const u8 = null;
    var print_host_key = false;
    var install_service = false;
    // `--listen` and `--key` as given, for the service.
    var listen_arg: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--listen") and i + 1 < args.len) {
            i += 1;
            listen = Io.net.IpAddress.parseLiteral(args[i]) catch return usage("invalid address");
            listen_arg = args[i];
        } else if (std.mem.eql(u8, arg, "--key") and i + 1 < args.len) {
            i += 1;
            key_path = args[i];
        } else if (std.mem.eql(u8, arg, "--print-host-key")) {
            print_host_key = true;
        } else if (std.mem.eql(u8, arg, "--install")) {
            install_service = true;
        } else return usage("unknown argument");
    }

    transport.crypto.init(io);

    // The first run creates the key.
    const path = key_path orelse try paths.state(gpa, init.environ_map, "host_key");
    defer if (key_path == null) gpa.free(path);
    const identity = try keyfile.loadOrCreate(io, path);

    if (print_host_key) {
        var buf: [256]u8 = undefined;
        var w = Io.File.stdout().writerStreaming(io, &buf);
        try w.interface.print("{s} {s}\n", .{ auth.ssh.ed25519, auth.ssh.KeyText.init(identity.public_key.toBytes()).slice() });
        try w.interface.flush();
        if (!install_service) return 0;
    }

    const user = paths.userName(init.environ_map) orelse {
        std.debug.print("txd: can't tell the user name\n", .{});
        return 1;
    };

    if (install_service) {
        const arena = init.arena.allocator();
        const exe = try install.exePath(arena, io, init.environ_map, args[0]);

        var service_args: std.ArrayList([]const u8) = .empty;
        if (listen_arg) |text| try service_args.appendSlice(arena, &.{ "--listen", text });
        if (key_path) |p| {
            // The service may start in another directory.
            const cwd = try std.process.currentPathAlloc(io, arena);
            try service_args.appendSlice(arena, &.{ "--key", try std.fs.path.resolve(arena, &.{ cwd, p }) });
        }

        install.install(gpa, io, init.environ_map, .{
            .exe = exe,
            .args = service_args.items,
            .listen = listen,
            .user = user,
        }) catch |err| {
            std.debug.print("txd: --install failed: {t}\n", .{err});
            return 1;
        };
        return 0;
    }
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
    server.init(gpa, io, &loop, .{
        .listen = listen,
        .identity = identity,
        .user = user,
        .authorized_keys = &.{ tx_authorized_keys, ssh_authorized_keys },
        .environ = &environ,
        .argv = &.{login_name},
        .program = shell,
        .cwd = if (init.environ_map.get("HOME")) |home| .{ .path = home } else .inherit,
    }) catch |err| switch (err) {
        error.AddressInUse => {
            std.debug.print("txd: port {d} is in use, by another txd or another program\n", .{listen.getPort()});
            return 1;
        },
        else => |e| return e,
    };
    defer server.deinit();

    std.log.info("serving {s}, host key {s}", .{ user, auth.Fingerprint.init(identity.public_key.toBytes()).slice() });
    try loop.run(.until_done);
    return 0;
}

fn usage(reason: []const u8) u8 {
    std.debug.print("txd: {s}\nusage: txd [--listen ADDRESS:PORT] [--key PATH] [--print-host-key] [--install]\n", .{reason});
    return 2;
}

test {
    _ = &main;
    _ = install;
}

//! txd: serves the user's sessions over QUIC.
//!
//! Usage: txd [--listen ADDRESS:PORT] [--key PATH] [--open]
//!            [--print-host-key] [--print-spa-key] [--install]
//!        txd [--listen ADDRESS:PORT] --uninstall
//!        txd --version
//!        txd --session --fd N
//!
//! Personal mode: clients log in as the user running txd, with a key
//! from `~/.config/tx/authorized_keys` if that file exists, or else from
//! `~/.ssh/authorized_keys`. It listens on every address by default.
//!
//! `--print-host-key` prints the public host key as `ssh-ed25519 AAAA...`
//! and exits, creating the key if there is none. `tx` runs it over ssh to
//! learn a new host's key.
//!
//! txd answers only clients that hold its SPA key (see
//! `transport.spa`), kept in `spa_key` next to the default host key.
//! To anyone else the port looks closed. `--print-spa-key` prints
//! `spa-key KEY TIME`, the key in base64 and txd's clock in Unix seconds,
//! creating the key if there is none. `tx` runs it over ssh with
//! `--print-host-key`. `--open` answers every client.
//!
//! `--install` sets up a service that keeps txd running with the
//! given `--listen`, `--key` and `--open`, starts it if it isn't running,
//! and exits; see `install.zig`. With `--print-host-key` or
//! `--print-spa-key`, those are printed first. `--uninstall` stops txd,
//! ends its sessions, and removes the service and txd's files.
//!
//! `--session` runs one session, on the socket txd passes as fd N. txd
//! starts it; see `session.process`.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const xev = @import("xev");
const server_pkg = @import("server");
const session = @import("session");
const transport = @import("transport");
const auth = @import("auth");
const build_options = @import("build_options");
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

    // A session process, started by txd.
    if (args.len == 4 and std.mem.eql(u8, args[1], "--session") and std.mem.eql(u8, args[2], "--fd")) {
        const fd = std.fmt.parseInt(std.posix.fd_t, args[3], 10) catch return usage("invalid fd");
        return session.process.run(gpa, io, fd);
    }

    // Options. `::` covers every IPv4 and IPv6 address.
    var listen: Io.net.IpAddress = try .parseIp6("::", default_port);
    var key_path: ?[]const u8 = null;
    var print_host_key = false;
    var print_spa_key = false;
    var open = false;
    var install_service = false;
    var uninstall = false;
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
        } else if (std.mem.eql(u8, arg, "--print-spa-key")) {
            print_spa_key = true;
        } else if (std.mem.eql(u8, arg, "--open")) {
            open = true;
        } else if (std.mem.eql(u8, arg, "--install")) {
            install_service = true;
        } else if (std.mem.eql(u8, arg, "--uninstall")) {
            uninstall = true;
        } else if (std.mem.eql(u8, arg, "--version")) {
            Io.File.stdout().writeStreamingAll(io, "txd " ++ build_options.version ++ "\n") catch return 1;
            return 0;
        } else return usage("unknown argument");
    }

    const user = paths.userName(init.environ_map) orelse {
        std.debug.print("txd: can't tell the user name\n", .{});
        return 1;
    };

    // Before the keys, which it removes.
    if (uninstall) {
        if (install_service or print_host_key or print_spa_key or key_path != null or open) return usage("--uninstall goes with --listen only");
        install.uninstall(gpa, io, init.environ_map, user, listen) catch |err| {
            std.debug.print("txd: --uninstall failed: {t}\n", .{err});
            return 1;
        };
        return 0;
    }

    transport.crypto.init(io);

    // The first run creates the key.
    const path = key_path orelse try paths.state(gpa, init.environ_map, "host_key");
    defer if (key_path == null) gpa.free(path);
    const identity = try keyfile.loadOrCreate(io, path);
    const spa_path = try paths.state(gpa, init.environ_map, "spa_key");
    defer gpa.free(spa_path);
    var spa_key = try keyfile.loadOrCreateSecret(io, spa_path);
    defer std.crypto.secureZero(u8, &spa_key);

    if (print_host_key or print_spa_key) {
        var buf: [256]u8 = undefined;
        var w = Io.File.stdout().writerStreaming(io, &buf);
        if (print_host_key) {
            try w.interface.print("{s} {s}\n", .{ auth.ssh.ed25519, auth.ssh.KeyText.init(identity.public_key.toBytes()).slice() });
        }
        if (print_spa_key) {
            var text: [std.base64.standard.Encoder.calcSize(spa_key.len)]u8 = undefined;
            _ = std.base64.standard.Encoder.encode(&text, &spa_key);
            try w.interface.print("spa-key {s} {d}\n", .{ &text, Io.Clock.real.now(io).toSeconds() });
        }
        try w.interface.flush();
        if (!install_service) return 0;
    }

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
        if (open) try service_args.append(arena, "--open");

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
    // COLORTERM from its client, and the client's LANG and LC_* in place of
    // txd's.
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    for (inherited) |name| if (init.environ_map.get(name)) |value| try environ.put(name, value);
    var it = init.environ_map.iterator();
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "LC_")) try environ.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    try environ.put("TX_SESSION", "1");

    // Next to txd's own builds, which `--uninstall` removes.
    const terminfo_dir = try paths.home(gpa, init.environ_map, ".local/share/tx/terminfo");
    defer gpa.free(terminfo_dir);

    // A login shell: argv[0] is the shell's name with a leading "-".
    const shell = init.environ_map.get("SHELL") orelse "/bin/sh";
    const login_name = try std.fmt.allocPrint(gpa, "-{s}", .{std.fs.path.basename(shell)});
    defer gpa.free(login_name);

    const runtime_dir = try paths.runtime(gpa, init.environ_map);
    defer gpa.free(runtime_dir);
    // On Linux, the binary this process runs even once it has been
    // replaced, so that the sessions it starts speak its revision.
    const session_exe = if (builtin.os.tag == .linux)
        try gpa.dupe(u8, "/proc/self/exe")
    else
        try std.process.executablePathAlloc(io, gpa);
    defer gpa.free(session_exe);

    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();

    var server: server_pkg.Server = undefined;
    server.init(gpa, io, &loop, .{
        .listen = listen,
        .runtime_dir = runtime_dir,
        .session_exe = session_exe,
        .identity = identity,
        .user = user,
        .authorized_keys = &.{ tx_authorized_keys, ssh_authorized_keys },
        .environ = &environ,
        .argv = &.{login_name},
        .program = shell,
        .shell = shell,
        .terminfo_dir = terminfo_dir,
        .cwd = if (init.environ_map.get("HOME")) |home| .{ .path = home } else .inherit,
        .spa_key = if (open) null else spa_key,
    }) catch |err| switch (err) {
        error.AddressInUse => {
            std.debug.print("txd: port {d} is in use, by another txd or another program\n", .{listen.getPort()});
            return 1;
        },
        error.InsecureRuntimeDir => {
            std.debug.print("txd: {s} is another user's, or others can reach it\n", .{runtime_dir});
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
    std.debug.print("txd: {s}\nusage: txd [--listen ADDRESS:PORT] [--key PATH] [--open] [--print-host-key] [--print-spa-key] [--install]\n       txd [--listen ADDRESS:PORT] --uninstall\n       txd --version\n       txd --session --fd N\n", .{reason});
    return 2;
}

test {
    _ = &main;
    _ = install;
}

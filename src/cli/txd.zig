//! txd's main. `txd --session --fd N` runs a session process, as
//! session/spawn.zig execs it. `--uninstall` removes the service
//! (install.zig). Otherwise txd loads or creates its host key (keyfile.zig),
//! then installs the service or runs the server from src/server. Its files
//! live under the directories in paths.zig.

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
const Scope = server_pkg.addresses.Scope;

/// Matches default_port in src/cli/tx.zig, the port tx connects to when none
/// is given.
pub const default_port = 8739;

/// The variables sessions take from txd's environment, besides LC_*.
const inherited = [_][]const u8{ "HOME", "USER", "LOGNAME", "SHELL", "PATH", "TZ", "LANG" };

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // session/spawn.zig execs session processes with these arguments.
    if (args.len == 4 and std.mem.eql(u8, args[1], "--session") and std.mem.eql(u8, args[2], "--fd")) {
        const fd = std.fmt.parseInt(std.posix.fd_t, args[3], 10) catch return usage("invalid fd");
        return session.process.run(gpa, io, fd);
    }

    // The server's wildcard `::` covers IPv4 addresses too.
    var listen: Io.net.IpAddress = try .parseIp6("::", default_port);
    var scope: ?Scope = null;
    var key_path: ?[]const u8 = null;
    var print_host_key = false;
    var install_service = false;
    var uninstall = false;
    var listen_arg: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--listen") and i + 1 < args.len) {
            i += 1;
            if (parseTailnet(args[i])) |port| {
                listen.setPort(port orelse return usage("invalid port"));
                scope = .tailnet;
            } else {
                listen = Io.net.IpAddress.parseLiteral(args[i]) catch return usage("invalid address");
                scope = .all;
            }
            listen_arg = args[i];
        } else if (std.mem.eql(u8, arg, "--key") and i + 1 < args.len) {
            i += 1;
            key_path = args[i];
        } else if (std.mem.eql(u8, arg, "--print-host-key")) {
            print_host_key = true;
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

    if (uninstall) {
        if (install_service or print_host_key or key_path != null) return usage("--uninstall goes with --listen only");
        install.uninstall(gpa, io, init.environ_map, user, listen) catch |err| {
            std.debug.print("txd: --uninstall failed: {t}\n", .{err});
            return 1;
        };
        return 0;
    }

    // The TLS backend takes its randomness from io and panics without it.
    transport.crypto.init(io);

    const path = key_path orelse try paths.state(gpa, init.environ_map, "host_key");
    defer if (key_path == null) gpa.free(path);
    const identity = try keyfile.loadOrCreate(io, path);
    const fingerprint = auth.Fingerprint.init(identity.public_key.toBytes());

    if (print_host_key) {
        var buf: [256]u8 = undefined;
        var w = Io.File.stdout().writerStreaming(io, &buf);
        try w.interface.print("{s} {s}\n", .{ auth.ssh.ed25519, auth.ssh.KeyText.init(identity.public_key.toBytes()).slice() });
        try w.interface.flush();
        if (!install_service) return 0;
    }

    const listen_scope = scope orelse if (server_pkg.addresses.hasTailnet(gpa) catch false) Scope.tailnet else Scope.all;

    if (install_service) {
        const arena = init.arena.allocator();
        const exe = try install.exePath(arena, io, init.environ_map, args[0]);

        // The service always gets a --listen, which fixes the scope chosen now.
        var service_args: std.ArrayList([]const u8) = .empty;
        const listen_text = listen_arg orelse switch (listen_scope) {
            .tailnet => "tailnet",
            .all => try std.fmt.allocPrint(arena, "{f}", .{listen}),
        };
        try service_args.appendSlice(arena, &.{ "--listen", listen_text });

        // systemd and launchd start the service in another working directory.
        if (key_path) |p| {
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
        switch (listen_scope) {
            .tailnet => std.debug.print("txd: listening on the tailnet only, port {d}\n", .{listen.getPort()}),
            .all => std.debug.print("txd: listening on {f}\n", .{listen}),
        }
        std.debug.print("txd: host key {s}, which tx shows the first time it connects\n", .{fingerprint.slice()});
        return 0;
    }

    const tx_authorized_keys = try paths.config(gpa, init.environ_map, "authorized_keys");
    defer gpa.free(tx_authorized_keys);
    const ssh_authorized_keys = try paths.home(gpa, init.environ_map, ".ssh/authorized_keys");
    defer gpa.free(ssh_authorized_keys);

    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    for (inherited) |name| if (init.environ_map.get(name)) |value| try environ.put(name, value);
    var it = init.environ_map.iterator();
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "LC_")) try environ.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    try environ.put("TX_SESSION", "1");

    const terminfo_dir = try paths.home(gpa, init.environ_map, ".local/share/tx/terminfo");
    defer gpa.free(terminfo_dir);

    const shell = init.environ_map.get("SHELL") orelse "/bin/sh";

    // A '-' in front of argv[0] makes the shell a login shell.
    const login_name = try std.fmt.allocPrint(gpa, "-{s}", .{std.fs.path.basename(shell)});
    defer gpa.free(login_name);

    const runtime_dir = try paths.runtime(gpa, init.environ_map);
    defer gpa.free(runtime_dir);
    const wayland_socket = try std.fs.path.join(gpa, &.{ runtime_dir, "wayland-1" });
    defer gpa.free(wayland_socket);

    // On Linux, /proc/self/exe names the binary this txd runs, even after the
    // file at its path is replaced. Session processes then run the server's
    // own build.
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
        .scope = listen_scope,
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
        .wayland_socket = wayland_socket,
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

    std.log.info("serving {s}{s}, host key {s}", .{ user, if (listen_scope == .tailnet) " on the tailnet" else "", fingerprint.slice() });
    try loop.run(.until_done);
    return 0;
}

/// The port of a `tailnet` or `tailnet:PORT` argument. null when text is
/// neither form; an inner null when PORT isn't a valid port.
fn parseTailnet(text: []const u8) ?(?u16) {
    if (std.mem.eql(u8, text, "tailnet")) return default_port;
    if (!std.mem.startsWith(u8, text, "tailnet:")) return null;
    return std.fmt.parseInt(u16, text["tailnet:".len..], 10) catch @as(?u16, null);
}

test parseTailnet {
    try std.testing.expectEqual(@as(?(?u16), default_port), parseTailnet("tailnet"));
    try std.testing.expectEqual(@as(?(?u16), 9000), parseTailnet("tailnet:9000"));
    try std.testing.expectEqual(@as(?(?u16), @as(?u16, null)), parseTailnet("tailnet:x"));
    try std.testing.expectEqual(@as(?(?u16), null), parseTailnet("[::]:8739"));
}

fn usage(reason: []const u8) u8 {
    std.debug.print("txd: {s}\nusage: txd [--listen ADDRESS:PORT | --listen tailnet[:PORT]] [--key PATH] [--print-host-key] [--install]\n       txd [--listen ...] --uninstall\n       txd --version\n       txd --session --fd N\n", .{reason});
    return 2;
}

test {
    _ = &main;
    _ = install;
}

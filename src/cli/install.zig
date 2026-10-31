//! `txd --install`: keeps txd running for the user, and
//! starts it if it isn't running. `install.sh --txd` runs it after it
//! installs txd.
//!
//! On Linux with a systemd user manager, it installs the user service
//! `txd.service` and turns on lingering, so that the user's manager
//! starts at boot and keeps running after they log out. On macOS, it
//! installs the LaunchAgent `txd`, which starts at each login.
//! Elsewhere, when lingering can't be turned on, or when launchctl fails,
//! it starts txd in the background, where it runs until the
//! machine restarts.
//!
//! Running it again starts the server only if nothing has its port. A
//! service file that names another binary or other options is rewritten.
//! A server that has the port keeps running, with its sessions, and the
//! new file applies from its next start. One that doesn't, such as after a
//! change of port, restarts with the new file.
//!
//! Each session runs in a process of its own (see `session.spawn`), and
//! the service manager stops only txd: sessions outlive a restart of the
//! service, and the next txd finds them.
//!
//! `txd --uninstall` undoes it all; see `uninstall`.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const PosixAddress = Io.Threaded.PosixAddress;
const Environ = std.process.Environ;
const proto = @import("proto");
const session = @import("session");
const runtime_dir = @import("server").runtime_dir;
const paths = @import("paths.zig");

/// The systemd unit and the launchd label.
const name = "txd";

/// How long a started server has to bind its port.
const start_timeout_ms = 5000;

/// In the state directory: the pid of a server started in the background,
/// and a file that says `install` turned on lingering.
const pid_file = name ++ ".pid";
const linger_file = "linger";

pub const Options = struct {
    /// The path of the txd binary the service runs.
    exe: []const u8,
    /// The server's arguments, after `exe`.
    args: []const []const u8,
    /// The address the server binds.
    listen: IpAddress,
    user: []const u8,
};

pub fn install(gpa: Allocator, io: Io, environ: *const Environ.Map, options: Options) !void {
    const start = switch (builtin.os.tag) {
        .macos => try launchd(gpa, io, environ, options) orelse try background(gpa, io, environ, options),
        .linux => try systemd(gpa, io, environ, options) orelse try background(gpa, io, environ, options),
        else => try background(gpa, io, environ, options),
    };
    if (start == .serving) return;

    var waited: u64 = 0;
    while (!serving(options.listen)) : (waited += 50) {
        if (waited >= start_timeout_ms) {
            std.debug.print("txd: the server started, but hasn't bound {f} after {d} s\n", .{ options.listen, start_timeout_ms / 1000 });
            return error.NotServing;
        }
        try io.sleep(.fromMilliseconds(50), .awake);
    }
    std.debug.print("txd: started the server on {f}\n", .{options.listen});
}

const Start = enum {
    /// A server already had the port.
    serving,
    /// A server was started, and may not have bound its port yet.
    started,
};

/// How long `serving` waits for a refusal.
const probe_timeout_ms = 200;

/// True when something has bound the port of `address`. For a wildcard,
/// the port is checked on 127.0.0.1, which txd binds too.
///
/// A datagram to a port nobody has bound draws an ICMP port unreachable,
/// which a connected socket reports as ECONNREFUSED. Binding the port would
/// tell as well, but while the check holds it, a server that is starting
/// can fail to bind.
fn serving(address: IpAddress) bool {
    const to: IpAddress = if (isWildcard(address)) .{ .ip4 = .loopback(address.getPort()) } else address;
    var addr: PosixAddress = undefined;
    const addr_len = Io.Threaded.addressToPosix(&to, &addr);

    const fd = std.c.socket(addr.any.family, std.c.SOCK.DGRAM, 0);
    if (fd < 0) return false;
    defer _ = std.c.close(fd);
    if (std.c.connect(fd, &addr.any, addr_len) != 0) return false;

    // One byte, which a QUIC server drops.
    const probe = [1]u8{0};
    if (std.c.send(fd, &probe, probe.len, 0) < 0) return false;

    var fds = [_]std.c.pollfd{.{ .fd = fd, .events = std.c.POLL.IN, .revents = 0 }};
    if (std.c.poll(&fds, fds.len, probe_timeout_ms) <= 0) return true;
    var byte: u8 = undefined;
    if (std.c.recv(fd, &byte, 1, 0) >= 0) return true;
    return std.posix.errno(-1) != .CONNREFUSED;
}

fn isWildcard(address: IpAddress) bool {
    return switch (address) {
        .ip4 => |a| std.mem.allEqual(u8, &a.bytes, 0),
        .ip6 => |a| std.mem.allEqual(u8, &a.bytes, 0),
    };
}

/// Null when no systemd user manager answers, or lingering is off and
/// can't be turned on.
fn systemd(gpa: Allocator, io: Io, environ: *const Environ.Map, options: Options) !?Start {
    if (!try succeeds(gpa, io, &.{ "systemctl", "--user", "--quiet", "show-environment" }, .quiet)) return null;

    // Without lingering, the user's manager stops at their last logout,
    // with its services, such as when the ssh session this runs in ends.
    const linger = try output(gpa, io, &.{ "loginctl", "show-user", options.user, "--property=Linger", "--value" }, .quiet);
    defer if (linger) |text| gpa.free(text);
    const lingering = if (linger) |text| std.mem.eql(u8, std.mem.trim(u8, text, " \n"), "yes") else false;
    if (!lingering) {
        if (!try succeeds(gpa, io, &.{ "loginctl", "enable-linger", options.user }, .show)) {
            std.debug.print("txd: can't turn on lingering, and without it a systemd service stops at logout. Starting the server in the background.\n", .{});
            return null;
        }
        std.debug.print("txd: turned on lingering for {s}, so the user's services run without a login\n", .{options.user});

        // So that `uninstall` turns it off again.
        const linger_path = try paths.state(gpa, environ, linger_file);
        defer gpa.free(linger_path);
        _ = try writeIfChanged(gpa, io, linger_path, "txd --install turned on lingering.\n");
    }

    // The user manager reads ~/.config/systemd/user whatever this
    // session's XDG_CONFIG_HOME is.
    const path = try paths.home(gpa, environ, ".config/systemd/user/" ++ name ++ ".service");
    defer gpa.free(path);
    const unit = try systemdUnit(gpa, options.exe, options.args);
    defer gpa.free(unit);
    const changed = try writeIfChanged(gpa, io, path, unit);
    if (changed) {
        if (!try succeeds(gpa, io, &.{ "systemctl", "--user", "daemon-reload" }, .show)) return error.SystemctlFailed;
        std.debug.print("txd: installed {s}\n", .{path});
    }
    if (!try succeeds(gpa, io, &.{ "systemctl", "--user", "--quiet", "enable", name ++ ".service" }, .show)) return error.SystemctlFailed;

    if (serving(options.listen)) return .serving;

    // After five failed starts in ten seconds, systemd refuses to start the
    // service until its failures are reset.
    _ = try succeeds(gpa, io, &.{ "systemctl", "--user", "reset-failed", name ++ ".service" }, .quiet);

    // `start` leaves a running server alone, and it may have another port.
    const verb = if (changed) "restart" else "start";
    if (!try succeeds(gpa, io, &.{ "systemctl", "--user", verb, name ++ ".service" }, .show)) {
        std.debug.print("txd: see journalctl --user -u {s}\n", .{name});
        return error.SystemctlFailed;
    }
    return .started;
}

/// The LaunchAgent goes in the GUI login's domain when there is one, and in
/// the user's background domain otherwise. Null when launchctl fails to
/// start it.
fn launchd(gpa: Allocator, io: Io, environ: *const Environ.Map, options: Options) !?Start {
    const uid = std.c.getuid();
    var gui_buf: [32]u8 = undefined;
    const gui = std.fmt.bufPrint(&gui_buf, "gui/{d}", .{uid}) catch unreachable;
    var user_buf: [32]u8 = undefined;
    const user = std.fmt.bufPrint(&user_buf, "user/{d}", .{uid}) catch unreachable;
    const domain = if (try succeeds(gpa, io, &.{ "launchctl", "print", gui }, .quiet)) gui else user;
    var target_buf: [64]u8 = undefined;
    const target = std.fmt.bufPrint(&target_buf, "{s}/" ++ name, .{domain}) catch unreachable;

    const path = try paths.home(gpa, environ, "Library/LaunchAgents/" ++ name ++ ".plist");
    defer gpa.free(path);
    const log_path = try paths.home(gpa, environ, "Library/Logs/" ++ name ++ ".log");
    defer gpa.free(log_path);
    const plist = try launchdPlist(gpa, options.exe, options.args, log_path);
    defer gpa.free(plist);
    const changed = try writeIfChanged(gpa, io, path, plist);
    if (changed) std.debug.print("txd: installed {s}\n", .{path});

    if (serving(options.listen)) return .serving;

    // A loaded job keeps the plist it was loaded with until it is
    // unloaded.
    var loaded = try succeeds(gpa, io, &.{ "launchctl", "print", target }, .quiet);
    if (loaded and changed) {
        _ = try succeeds(gpa, io, &.{ "launchctl", "bootout", target }, .show);
        loaded = false;
    }
    // `launchctl disable` outlasts the job, and stops a bootstrap.
    const started = if (loaded)
        try succeeds(gpa, io, &.{ "launchctl", "kickstart", target }, .show)
    else
        try succeeds(gpa, io, &.{ "launchctl", "enable", target }, .show) and
            try succeeds(gpa, io, &.{ "launchctl", "bootstrap", domain, path }, .show);
    if (!started) {
        std.debug.print("txd: launchctl can't start {s}. Starting the server in the background.\n", .{target});
        return null;
    }
    return .started;
}

/// Starts the server in its own process group, with its output going to
/// `txd.log` in the state directory. It outlives the login that started it
/// unless logind kills a user's processes at logout (`KillUserProcesses`).
fn background(gpa: Allocator, io: Io, environ: *const Environ.Map, options: Options) !Start {
    if (serving(options.listen)) return .serving;

    const log_path = try paths.state(gpa, environ, name ++ ".log");
    defer gpa.free(log_path);
    if (std.fs.path.dirname(log_path)) |dir| try Io.Dir.cwd().createDirPath(io, dir);
    const log_file = try Io.Dir.cwd().createFile(io, log_path, .{});
    defer log_file.close(io);

    const argv = try gpa.alloc([]const u8, options.args.len + 1);
    defer gpa.free(argv);
    argv[0] = options.exe;
    @memcpy(argv[1..], options.args);

    // Not waited for. It is reparented when this process exits.
    const child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .{ .file = log_file },
        .stderr = .{ .file = log_file },
        .pgid = 0,
    });

    // For `uninstall`, which has no service to stop it with.
    const pid_path = try paths.state(gpa, environ, pid_file);
    defer gpa.free(pid_path);
    var pid_buf: [16]u8 = undefined;
    _ = try writeIfChanged(gpa, io, pid_path, std.fmt.bufPrint(&pid_buf, "{d}\n", .{child.id.?}) catch unreachable);
    std.debug.print("txd: the server runs in the background until the machine restarts. Its log is {s}\n", .{log_path});
    return .started;
}

/// Undoes `install`. Stops txd: its service, or the server it started in
/// the background. Turns lingering off if `install` turned it on. Ends the
/// sessions, as `tx --kill` does. Then removes txd's files in the state
/// directory, the default host key and the log, and last
/// `~/.local/share/tx`, with the terminfo entries txd compiled, and the
/// copies of txd that older versions of tx put there over ssh. A key given
/// with `--key`, `~/.config/tx/authorized_keys`, and the tx and txd that
/// were installed stay.
///
/// Each step must succeed before the next. Nothing is removed while
/// something still has the port of `listen`, the address the server was
/// installed with, such as a txd started by hand. After a failure, running
/// it again picks up where it stopped.
pub fn uninstall(gpa: Allocator, io: Io, environ: *const Environ.Map, user: []const u8, listen: IpAddress) !void {
    // The service first, so that nothing starts txd again.
    switch (builtin.os.tag) {
        .macos => try removeLaunchd(gpa, io, environ),
        .linux => try removeSystemd(gpa, io, environ, user),
        else => {},
    }
    try stopBackground(gpa, io, environ);
    if (serving(listen)) {
        std.debug.print("txd: something still has port {d}, such as a txd started by hand. Stop it, then uninstall again.\n", .{listen.getPort()});
        return error.PortInUse;
    }
    try endSessions(gpa, io, environ);

    // The keys and the log, then the directory with txd in it, so that
    // after a failure the next uninstall has a txd to run. The binary
    // running this keeps running.
    const dir = Io.Dir.cwd();
    // `spa_key` is an older txd's.
    for ([_][]const u8{ "host_key", "spa_key", name ++ ".log" }) |file| {
        const path = try paths.state(gpa, environ, file);
        defer gpa.free(path);
        try deleteIfExists(io, path);
    }
    const state_dir = try paths.state(gpa, environ, "");
    defer gpa.free(state_dir);
    // The state directory, if nothing else is in it.
    dir.deleteDir(io, state_dir) catch {};
    std.debug.print("txd: removed txd's keys and log\n", .{});

    const share = try paths.home(gpa, environ, ".local/share/tx");
    defer gpa.free(share);
    if (exists(io, share)) {
        try dir.deleteTree(io, share);
        std.debug.print("txd: removed {s}\n", .{share});
    }
}

/// Stops and removes the user service, and turns lingering off if
/// `install` turned it on.
fn removeSystemd(gpa: Allocator, io: Io, environ: *const Environ.Map, user: []const u8) !void {
    const path = try paths.home(gpa, environ, ".config/systemd/user/" ++ name ++ ".service");
    defer gpa.free(path);
    if (exists(io, path)) {
        // `--now` stops the service too. With `KillMode=process`, its
        // sessions keep running.
        if (!try succeeds(gpa, io, &.{ "systemctl", "--user", "--quiet", "disable", "--now", name ++ ".service" }, .show)) {
            std.debug.print("txd: can't stop {s}.service\n", .{name});
            return error.SystemctlFailed;
        }
        try Io.Dir.cwd().deleteFile(io, path);
        _ = try succeeds(gpa, io, &.{ "systemctl", "--user", "daemon-reload" }, .show);
        _ = try succeeds(gpa, io, &.{ "systemctl", "--user", "reset-failed", name ++ ".service" }, .quiet);
        std.debug.print("txd: removed {s}\n", .{path});
    }

    const linger_path = try paths.state(gpa, environ, linger_file);
    defer gpa.free(linger_path);
    if (exists(io, linger_path)) {
        if (try succeeds(gpa, io, &.{ "loginctl", "disable-linger", user }, .show)) {
            std.debug.print("txd: turned off lingering for {s}\n", .{user});
        }
        try Io.Dir.cwd().deleteFile(io, linger_path);
    }
}

/// Unloads the LaunchAgent from whichever domain has it, and removes it
/// and its log.
fn removeLaunchd(gpa: Allocator, io: Io, environ: *const Environ.Map) !void {
    const uid = std.c.getuid();
    for ([_][]const u8{ "gui", "user" }) |domain| {
        var target_buf: [64]u8 = undefined;
        const target = std.fmt.bufPrint(&target_buf, "{s}/{d}/" ++ name, .{ domain, uid }) catch unreachable;
        if (try succeeds(gpa, io, &.{ "launchctl", "print", target }, .quiet) and
            !try succeeds(gpa, io, &.{ "launchctl", "bootout", target }, .show))
        {
            std.debug.print("txd: can't stop {s}\n", .{target});
            return error.LaunchctlFailed;
        }
    }

    const path = try paths.home(gpa, environ, "Library/LaunchAgents/" ++ name ++ ".plist");
    defer gpa.free(path);
    if (exists(io, path)) {
        try Io.Dir.cwd().deleteFile(io, path);
        std.debug.print("txd: removed {s}\n", .{path});
    }
    const log_path = try paths.home(gpa, environ, "Library/Logs/" ++ name ++ ".log");
    defer gpa.free(log_path);
    try deleteIfExists(io, log_path);
}

/// How long `uninstall` waits for txd and the sessions to exit.
const stop_timeout_ms = 5000;

/// Stops the server `background` started, if it still runs. The pid file
/// goes once that server is gone.
fn stopBackground(gpa: Allocator, io: Io, environ: *const Environ.Map) !void {
    const path = try paths.state(gpa, environ, pid_file);
    defer gpa.free(path);
    const text = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64)) catch |err| switch (err) {
        error.FileNotFound => return,
        else => |e| return e,
    };
    defer gpa.free(text);

    // After a restart the pid may be another program's.
    const pid = std.fmt.parseInt(std.posix.pid_t, std.mem.trim(u8, text, " \n"), 10) catch null;
    if (pid != null and try isTxd(gpa, io, pid.?) and std.c.kill(pid.?, .TERM) == 0) {
        var waited: u64 = 0;
        while (std.c.kill(pid.?, @fromBackingInt(@intCast(0))) == 0) : (waited += 50) {
            if (waited >= stop_timeout_ms) {
                std.debug.print("txd: the server running in the background, pid {d}, didn't stop\n", .{pid.?});
                return error.TxdDidntStop;
            }
            try io.sleep(.fromMilliseconds(50), .awake);
        }
        std.debug.print("txd: stopped the server running in the background\n", .{});
    }
    try Io.Dir.cwd().deleteFile(io, path);
}

/// Whether process `pid` runs a program named txd. ps names it on Linux and
/// macOS alike.
fn isTxd(gpa: Allocator, io: Io, pid: std.posix.pid_t) !bool {
    var pid_buf: [16]u8 = undefined;
    const pid_text = std.fmt.bufPrint(&pid_buf, "{d}", .{pid}) catch unreachable;
    const text = try output(gpa, io, &.{ "ps", "-o", "comm=", "-p", pid_text }, .quiet) orelse return false;
    defer gpa.free(text);
    return std.mem.eql(u8, std.fs.path.basename(std.mem.trim(u8, text, " \n")), name);
}

/// Ends every session and waits for their processes to exit, then removes
/// the runtime directory.
fn endSessions(gpa: Allocator, io: Io, environ: *const Environ.Map) !void {
    const dir = try paths.runtime(gpa, environ);
    defer gpa.free(dir);
    const ids = runtime_dir.ids(gpa, io, dir) catch |err| switch (err) {
        error.FileNotFound => return,
        else => |e| return e,
    };
    defer gpa.free(ids);

    var ended: usize = 0;
    for (ids) |id| {
        killSession(dir, id) catch |err| switch (err) {
            // A socket whose process is gone, as the server treats one.
            error.ConnectionRefused => {
                runtime_dir.remove(dir, id);
                continue;
            },
            // Gone since the listing.
            error.FileNotFound => continue,
            else => {
                std.debug.print("txd: can't reach session {d}: {t}\n", .{ id, err });
                return err;
            },
        };
        ended += 1;
    }

    // A session process removes its socket as its session ends.
    var waited: u64 = 0;
    while (true) : (waited += 50) {
        const left = try runtime_dir.ids(gpa, io, dir);
        defer gpa.free(left);
        if (left.len == 0) break;
        if (waited >= stop_timeout_ms) {
            std.debug.print("txd: these sessions didn't end:", .{});
            for (left) |id| std.debug.print(" {d}", .{id});
            std.debug.print("\n", .{});
            return error.SessionsDidntEnd;
        }
        try io.sleep(.fromMilliseconds(50), .awake);
    }
    if (ended > 0) std.debug.print("txd: ended {d} session{s}\n", .{ ended, if (ended == 1) "" else "s" });
    Io.Dir.cwd().deleteDir(io, dir) catch {};
}

/// Sends `Kill` to session `id`'s process.
fn killSession(dir: []const u8, id: u64) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const fd = try session.unix.connect(try runtime_dir.socketPath(&path_buf, dir, id));
    defer session.unix.close(fd);

    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try proto.encode(&w, .{ .kill = .{ .session_id = id } });
    var rest = w.buffered();
    while (rest.len > 0) {
        const n = std.c.write(fd, rest.ptr, rest.len);
        if (n <= 0) return error.WriteFailed;
        rest = rest[@intCast(n)..];
    }
}

fn exists(io: Io, path: []const u8) bool {
    Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn deleteIfExists(io: Io, path: []const u8) !void {
    Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };
}

/// Whether a failing command's stderr is shown. A check that is expected
/// to fail is quiet.
const Errors = enum { show, quiet };

/// Runs `argv`. A program that isn't installed fails.
fn succeeds(gpa: Allocator, io: Io, argv: []const []const u8, errors: Errors) !bool {
    const text = try output(gpa, io, argv, errors) orelse return false;
    gpa.free(text);
    return true;
}

/// The stdout of `argv`, owned, or null if it fails.
fn output(gpa: Allocator, io: Io, argv: []const []const u8, errors: Errors) !?[]u8 {
    const result = std.process.run(gpa, io, .{
        .argv = argv,
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(64 << 10),
    }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    defer gpa.free(result.stderr);
    if (result.term.success()) return result.stdout;

    gpa.free(result.stdout);
    const message = std.mem.trim(u8, result.stderr, " \t\r\n");
    if (errors == .show and message.len > 0) std.debug.print("{s}: {s}\n", .{ argv[0], message });
    return null;
}

/// Writes `data` to `path`, creating its directory, unless the file holds
/// it already. Returns whether it wrote.
fn writeIfChanged(gpa: Allocator, io: Io, path: []const u8, data: []const u8) !bool {
    const dir = Io.Dir.cwd();
    if (dir.readFileAlloc(io, path, gpa, .limited(1 << 20))) |old| {
        defer gpa.free(old);
        if (std.mem.eql(u8, old, data)) return false;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    }

    if (std.fs.path.dirname(path)) |parent| try dir.createDirPath(io, parent);
    try dir.writeFile(io, .{ .sub_path = path, .data = data });
    return true;
}

/// `KillMode=process` stops only txd, and the session processes stay in
/// the service's cgroup. Shutdown and the end of the user's manager still
/// end them.
fn systemdUnit(gpa: Allocator, exe: []const u8, args: []const []const u8) ![]u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll(
        \\# Written by txd --install.
        \\[Unit]
        \\Description=tx sessions
        \\
        \\[Service]
        \\ExecStart=
    );
    try writeSystemdArg(w, exe);
    for (args) |arg| {
        try w.writeByte(' ');
        try writeSystemdArg(w, arg);
    }
    try w.writeAll(
        \\
        \\Restart=on-failure
        \\KillMode=process
        \\
        \\[Install]
        \\WantedBy=default.target
        \\
    );
    return out.toOwnedSlice();
}

/// A word of `ExecStart`, in double quotes. `%` and `$` are doubled, since
/// systemd expands `%` specifiers and `$` variables inside quotes too.
fn writeSystemdArg(w: *Io.Writer, arg: []const u8) !void {
    try w.writeByte('"');
    for (arg) |byte| switch (byte) {
        '"', '\\' => try w.print("\\{c}", .{byte}),
        '%', '$' => try w.print("{c}{c}", .{ byte, byte }),
        else => try w.writeByte(byte),
    };
    try w.writeByte('"');
}

/// `AbandonProcessGroup` keeps launchd from killing txd's process group
/// when txd exits. Session processes are in sessions of their own already.
fn launchdPlist(gpa: Allocator, exe: []const u8, args: []const []const u8, log_path: []const u8) ![]u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<!-- Written by txd --install. -->
        \\<plist version="1.0">
        \\<dict>
        \\    <key>Label</key>
        \\    <string>
    ++ name ++
        \\</string>
        \\    <key>ProgramArguments</key>
        \\    <array>
        \\
    );
    try writePlistString(w, exe);
    for (args) |arg| try writePlistString(w, arg);
    try w.writeAll(
        \\    </array>
        \\    <key>RunAtLoad</key>
        \\    <true/>
        \\    <key>KeepAlive</key>
        \\    <dict>
        \\        <key>SuccessfulExit</key>
        \\        <false/>
        \\    </dict>
        \\    <key>ProcessType</key>
        \\    <string>Interactive</string>
        \\    <key>AbandonProcessGroup</key>
        \\    <true/>
        \\    <key>StandardErrorPath</key>
        \\
    );
    try w.writeAll("    ");
    try writeXmlString(w, log_path);
    try w.writeAll(
        \\
        \\</dict>
        \\</plist>
        \\
    );
    return out.toOwnedSlice();
}

fn writePlistString(w: *Io.Writer, text: []const u8) !void {
    try w.writeAll("        ");
    try writeXmlString(w, text);
    try w.writeByte('\n');
}

fn writeXmlString(w: *Io.Writer, text: []const u8) !void {
    try w.writeAll("<string>");
    for (text) |byte| switch (byte) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        else => try w.writeByte(byte),
    };
    try w.writeAll("</string>");
}

/// The path of the running binary, without resolving symlinks, so that a
/// service names `/opt/homebrew/bin/txd` and keeps working after an
/// upgrade replaces the binary it points to. Falls back to the resolved
/// path.
pub fn exePath(gpa: Allocator, io: Io, environ: *const Environ.Map, arg0: []const u8) ![]u8 {
    if (std.mem.indexOfScalar(u8, arg0, '/') != null) {
        if (std.fs.path.isAbsolute(arg0)) return gpa.dupe(u8, arg0);
        const cwd = try std.process.currentPathAlloc(io, gpa);
        defer gpa.free(cwd);
        return std.fs.path.join(gpa, &.{ cwd, arg0 });
    }

    // Found in PATH, as the shell found it.
    if (environ.get("PATH")) |search| {
        var dirs = std.mem.tokenizeScalar(u8, search, ':');
        while (dirs.next()) |dir| {
            if (!std.fs.path.isAbsolute(dir)) continue;
            const path = try std.fs.path.join(gpa, &.{ dir, arg0 });
            if (Io.Dir.accessAbsolute(io, path, .{ .execute = true })) return path else |_| gpa.free(path);
        }
    }
    return std.process.executablePathAlloc(io, gpa);
}

const testing = std.testing;

test systemdUnit {
    const unit = try systemdUnit(testing.allocator, "/home/a b/bin/txd", &.{ "--key", "/k/100%\"$x" });
    defer testing.allocator.free(unit);
    try testing.expectEqualStrings(
        \\# Written by txd --install.
        \\[Unit]
        \\Description=tx sessions
        \\
        \\[Service]
        \\ExecStart="/home/a b/bin/txd" "--key" "/k/100%%\"$$x"
        \\Restart=on-failure
        \\KillMode=process
        \\
        \\[Install]
        \\WantedBy=default.target
        \\
    , unit);
}

test launchdPlist {
    const plist = try launchdPlist(testing.allocator, "/opt/tx&co/txd", &.{ "--listen", "[::]:9000" }, "/Users/a/Library/Logs/txd.log");
    defer testing.allocator.free(plist);
    try testing.expectEqualStrings(
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<!-- Written by txd --install. -->
        \\<plist version="1.0">
        \\<dict>
        \\    <key>Label</key>
        \\    <string>txd</string>
        \\    <key>ProgramArguments</key>
        \\    <array>
        \\        <string>/opt/tx&amp;co/txd</string>
        \\        <string>--listen</string>
        \\        <string>[::]:9000</string>
        \\    </array>
        \\    <key>RunAtLoad</key>
        \\    <true/>
        \\    <key>KeepAlive</key>
        \\    <dict>
        \\        <key>SuccessfulExit</key>
        \\        <false/>
        \\    </dict>
        \\    <key>ProcessType</key>
        \\    <string>Interactive</string>
        \\    <key>AbandonProcessGroup</key>
        \\    <true/>
        \\    <key>StandardErrorPath</key>
        \\    <string>/Users/a/Library/Logs/txd.log</string>
        \\</dict>
        \\</plist>
        \\
    , plist);
}

test serving {
    const io = testing.io;
    const bound: IpAddress = .{ .ip4 = .loopback(0) };
    const socket = try bound.bind(io, .{ .mode = .dgram });
    const port = socket.address.getPort();
    try testing.expect(serving(socket.address));
    try testing.expect(serving(.{ .ip6 = .unspecified(port) }));

    socket.close(io);
    try testing.expect(!serving(.{ .ip4 = .loopback(port) }));
    try testing.expect(!serving(.{ .ip6 = .unspecified(port) }));
}

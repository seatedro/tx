//! tx-session: serves the user's sessions over QUIC.
//!
//! Usage: tx-session [--listen ADDRESS:PORT] [--key PATH]
//!
//! Revision 0 authenticates no one, so it listens on loopback addresses only.
const std = @import("std");
const Io = std.Io;
const xev = @import("xev");
const server_pkg = @import("server");
const transport = @import("transport");
const keyfile = @import("keyfile.zig");

pub const default_port = 8739;

/// Variables a session inherits from tx-session's environment.
const inherited = [_][]const u8{ "HOME", "USER", "LOGNAME", "SHELL", "PATH", "TZ", "LANG" };

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var listen: Io.net.IpAddress = try .parseIp4("127.0.0.1", default_port);
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
    if (!isLoopback(listen)) return usage("revision 0 listens on loopback addresses only");

    transport.crypto.init(io);
    const path = key_path orelse try keyfile.defaultPath(gpa, init.environ_map);
    defer if (key_path == null) gpa.free(path);
    const identity = try keyfile.loadOrCreate(io, path);

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
        .environ = &environ,
        .argv = &.{login_name},
        .program = shell,
        .cwd = if (init.environ_map.get("HOME")) |home| .{ .path = home } else .inherit,
    });
    defer server.deinit();
    std.log.info("listening on {f}", .{server.address()});
    try loop.run(.until_done);
    return 0;
}

const ip6_loopback: [16]u8 = blk: {
    var bytes: [16]u8 = @splat(0);
    bytes[15] = 1;
    break :blk bytes;
};

fn isLoopback(address: Io.net.IpAddress) bool {
    return switch (address) {
        .ip4 => |a| a.bytes[0] == 127,
        .ip6 => |a| std.mem.eql(u8, &a.bytes, &ip6_loopback),
    };
}

fn usage(reason: []const u8) u8 {
    std.debug.print("tx-session: {s}\nusage: tx-session [--listen ADDRESS:PORT] [--key PATH]\n", .{reason});
    return 2;
}

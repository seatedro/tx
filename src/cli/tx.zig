//! tx: a session on a tx-session server.
//!
//! Usage: tx [-p PORT] [--key PATH] [--attach ID] ADDRESS
//!
//! Revision 0 connects to a server on this machine and pins the key in its
//! key file. Exits with the program's exit status, or 255 for tx's own
//! failures, as ssh does.
const std = @import("std");
const Io = std.Io;
const client = @import("client");
const keyfile = @import("keyfile.zig");

/// tx-session's default port.
const default_port = 8739;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // Options, then one address.
    var port: u16 = default_port;
    var key_path: ?[]const u8 = null;
    var session_id: ?u64 = null;
    var host: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-p") and i + 1 < args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, args[i], 10) catch return usage("invalid port");
        } else if (std.mem.eql(u8, arg, "--key") and i + 1 < args.len) {
            i += 1;
            key_path = args[i];
        } else if (std.mem.eql(u8, arg, "--attach") and i + 1 < args.len) {
            i += 1;
            session_id = std.fmt.parseInt(u64, args[i], 10) catch return usage("invalid session id");
        } else if (host == null and !std.mem.startsWith(u8, arg, "-")) {
            host = arg;
        } else return usage("unknown argument");
    }

    // No name resolution yet, apart from localhost.
    const name = host orelse return usage("no address");
    const address: Io.net.IpAddress = if (std.mem.eql(u8, name, "localhost"))
        try .parseIp4("127.0.0.1", port)
    else
        Io.net.IpAddress.parse(name, port) catch return usage("revision 0 takes an IP address");

    // The server's key file, read from this machine. It stands in for
    // known_hosts until host key checks exist.
    const path = key_path orelse try keyfile.defaultPath(gpa, init.environ_map);
    defer if (key_path == null) gpa.free(path);
    const identity = keyfile.load(io, path) catch |err| {
        std.debug.print("tx: can't read the server key at {s}: {t}\n", .{ path, err });
        return 255;
    };

    const outcome = client.session.run(gpa, io, .{
        .server = address,
        .pinned = identity.public_key.toBytes(),
        .session_id = session_id,
        .term = init.environ_map.get("TERM") orelse "xterm-256color",
        .colorterm = init.environ_map.get("COLORTERM"),
    }) catch |err| {
        std.debug.print("tx: {t}\n", .{err});
        return 255;
    };

    switch (outcome) {
        .exited => |exit| return exit.status,
        .detached => |id| {
            if (id) |n| std.debug.print("tx: detached from session {d}; reattach with tx --attach {d} {s}\n", .{ n, n, name });
            return 0;
        },
        .disconnected => |reason| {
            std.debug.print("tx: connection closed: {t}\n", .{reason});
            return 255;
        },
        .refused => |refusal| {
            std.debug.print("tx: {s}\n", .{refusal.message.slice()});
            return 255;
        },
    }
}

fn usage(reason: []const u8) u8 {
    std.debug.print("tx: {s}\nusage: tx [-p PORT] [--key PATH] [--attach ID] ADDRESS\n", .{reason});
    return 255;
}

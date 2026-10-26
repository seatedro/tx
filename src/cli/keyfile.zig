//! The server's Ed25519 identity, stored as its 32-byte seed in a file
//! readable only by its owner.
//!
//! Revision 0 has no known_hosts: a client on the same machine reads the
//! server's public key from this file. Remote hosts need the user
//! authentication and host key checks that come next.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Ed25519 = std.crypto.sign.Ed25519;

/// `$XDG_STATE_HOME/tx/host_key`, or `~/.local/state/tx/host_key`.
pub fn defaultPath(gpa: Allocator, environ: *const std.process.Environ.Map) ![]u8 {
    if (environ.get("XDG_STATE_HOME")) |state| return std.fs.path.join(gpa, &.{ state, "tx", "host_key" });
    const home = environ.get("HOME") orelse return error.NoHome;
    return std.fs.path.join(gpa, &.{ home, ".local", "state", "tx", "host_key" });
}

pub fn load(io: Io, path: []const u8) !Ed25519.KeyPair {
    // The seed is the secret: wiped once the key pair is derived.
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);

    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    if (try file.readPositionalAll(io, &seed, 0) != seed.len) return error.InvalidKeyFile;

    return Ed25519.KeyPair.generateDeterministic(seed);
}

/// Loads the key at `path`, creating it and its directory first if the file
/// doesn't exist.
pub fn loadOrCreate(io: Io, path: []const u8) !Ed25519.KeyPair {
    return load(io, path) catch |err| switch (err) {
        error.FileNotFound => {
            if (std.fs.path.dirname(path)) |dir| try Io.Dir.cwd().createDirPath(io, dir);

            const kp = Ed25519.KeyPair.generate(io);
            var seed = kp.secret_key.seed();
            defer std.crypto.secureZero(u8, &seed);

            // Exclusive creation keeps a key another process just wrote.
            // Mode 0600 is set at creation, before the seed is written.
            const file = try Io.Dir.cwd().createFile(io, path, .{
                .exclusive = true,
                .permissions = .fromMode(0o600),
            });
            defer file.close(io);
            try file.writeStreamingAll(io, &seed);
            return kp;
        },
        else => |e| return e,
    };
}

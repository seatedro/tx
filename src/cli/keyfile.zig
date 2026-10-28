//! The server's secrets, each 32 bytes in a file readable only by its
//! owner: the Ed25519 identity, stored as its seed, and the SPA key.
const std = @import("std");
const Io = std.Io;
const Ed25519 = std.crypto.sign.Ed25519;

pub fn load(io: Io, path: []const u8) !Ed25519.KeyPair {
    // The seed is the secret: wiped once the key pair is derived.
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    try read(io, path, &seed);
    return Ed25519.KeyPair.generateDeterministic(seed);
}

/// Loads the key at `path`, creating it and its directory first if the file
/// doesn't exist.
pub fn loadOrCreate(io: Io, path: []const u8) !Ed25519.KeyPair {
    return load(io, path) catch |err| switch (err) {
        error.FileNotFound => {
            const kp = Ed25519.KeyPair.generate(io);
            var seed = kp.secret_key.seed();
            defer std.crypto.secureZero(u8, &seed);
            try create(io, path, &seed);
            return kp;
        },
        else => |e| return e,
    };
}

/// The random secret at `path`, created with its directory if the file
/// doesn't exist.
pub fn loadOrCreateSecret(io: Io, path: []const u8) ![32]u8 {
    var secret: [32]u8 = undefined;
    read(io, path, &secret) catch |err| switch (err) {
        error.FileNotFound => {
            try io.randomSecure(&secret);
            try create(io, path, &secret);
        },
        else => |e| return e,
    };
    return secret;
}

fn read(io: Io, path: []const u8, out: *[32]u8) !void {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    if (try file.readPositionalAll(io, out, 0) != out.len) return error.InvalidKeyFile;
}

fn create(io: Io, path: []const u8, secret: *const [32]u8) !void {
    if (std.fs.path.dirname(path)) |dir| try Io.Dir.cwd().createDirPath(io, dir);

    // Exclusive creation keeps a key another process just wrote.
    // Mode 0600 is set at creation, before the secret is written.
    const file = try Io.Dir.cwd().createFile(io, path, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    try file.writeStreamingAll(io, secret);
}

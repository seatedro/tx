//! txd's host key file. It holds the raw 32-byte Ed25519 seed and is created
//! with mode 0600. txd keeps it at paths.state("host_key") unless --key names
//! another file.

const std = @import("std");
const Io = std.Io;
const Ed25519 = std.crypto.sign.Ed25519;

/// error.InvalidKeyFile when the file is shorter than a seed.
pub fn load(io: Io, path: []const u8) !Ed25519.KeyPair {
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    try read(io, path, &seed);
    return Ed25519.KeyPair.generateDeterministic(seed);
}

/// Creates the file, and its directory, with a new key when it doesn't exist.
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

fn read(io: Io, path: []const u8, out: *[32]u8) !void {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    if (try file.readPositionalAll(io, out, 0) != out.len) return error.InvalidKeyFile;
}

fn create(io: Io, path: []const u8, secret: *const [32]u8) !void {
    if (std.fs.path.dirname(path)) |dir| try Io.Dir.cwd().createDirPath(io, dir);

    // exclusive keeps a key that another txd created since the read.
    const file = try Io.Dir.cwd().createFile(io, path, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    try file.writeStreamingAll(io, secret);
}

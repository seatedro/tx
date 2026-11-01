const std = @import("std");
const primitives = @import("primitives.zig");

// References primitives.zig so its C exports are emitted.
comptime {
    _ = primitives;
}

pub const has_hardware_aes = std.crypto.core.aes.has_hardware_support;

pub fn init(io: std.Io) void {
    primitives.io = io;
}

pub fn random(buf: []u8) void {
    primitives.random(buf);
}

extern fn tx_crypto_test_known_answers() c_int;
extern fn tx_crypto_test_backend_interop(secret_key: *const [64]u8, public_key: *const [32]u8) c_int;
extern fn tx_crypto_test_cloudflare() c_int;

test "known-answer vectors match tx and minicrypto" {
    init(std.testing.io);
    try std.testing.expectEqual(0, tx_crypto_test_known_answers());
}

test "TLS 1.3 handshake between the tx and minicrypto backends" {
    init(std.testing.io);
    const kp = std.crypto.sign.Ed25519.KeyPair.generate(std.testing.io);
    try std.testing.expectEqual(0, tx_crypto_test_backend_interop(
        &kp.secret_key.toBytes(),
        &kp.public_key.toBytes(),
    ));
}

test "X25519MLKEM768 handshake with cloudflare.com" {
    init(std.testing.io);
    const failures = tx_crypto_test_cloudflare();
    if (failures < 0) return error.SkipZigTest;
    try std.testing.expectEqual(0, failures);
}

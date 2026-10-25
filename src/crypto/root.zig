//! tx's cryptography: a picotls backend built on Zig's `std.crypto`, and
//! Ed25519 raw public key authentication for it.
//!
//! The backend's algorithm objects are C (picotls_backend.c, declared in
//! include/tx/picotls_backend.h) because picotls's structs use bitfields;
//! the primitives they call are in primitives.zig.
const std = @import("std");
const primitives = @import("primitives.zig");

comptime {
    // The C backend links against these exports.
    _ = primitives;
}

/// True when AES runs on CPU instructions in this build. Zig picks the AES
/// implementation at compile time from the target's CPU features, so
/// baseline builds get software AES, where ChaCha20-Poly1305 is faster.
pub const has_hardware_aes = std.crypto.core.aes.has_hardware_support;

/// Must be called once before any TLS context is used. picotls requests
/// random bytes through a callback with no context, so the Io is global.
pub fn init(io: std.Io) void {
    primitives.io = io;
}

extern fn tx_crypto_test_known_answers() c_int;
extern fn tx_crypto_test_backend_interop(secret_key: *const [64]u8, public_key: *const [32]u8) c_int;
extern fn tx_crypto_test_cloudflare() c_int;

test "known-answer vectors match tx and minicrypto" {
    init(std.testing.io);
    try std.testing.expectEqual(0, tx_crypto_test_known_answers());
}

test "TLS 1.3 between the tx and minicrypto backends" {
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

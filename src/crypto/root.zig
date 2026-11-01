//! The crypto module. picotls_backend.c implements picotls' cipher, AEAD,
//! hash, key exchange and Ed25519 certificate interfaces over the C exports
//! in primitives.zig, which call std.crypto. transport's tls.c uses them
//! through include/tx/picotls_backend.h, and ngtcp2's picotls glue through
//! include/picotls/openssl.h. The tests drive the C checks in
//! picotls_backend_test.c.

const std = @import("std");
const primitives = @import("primitives.zig");

// References primitives.zig so its C exports are emitted.
comptime {
    _ = primitives;
}

/// Whether std.crypto's AES runs on the target CPU's AES instructions.
/// Fixed at compile time by the target's CPU features.
pub const has_hardware_aes = std.crypto.core.aes.has_hardware_support;

/// Sets the Io that `random` and the TLS backend draw randomness from.
/// Both panic until it is called.
pub fn init(io: std.Io) void {
    primitives.io = io;
}

/// Fills buf from `Io.random` on the Io given to `init`.
pub fn random(buf: []u8) void {
    primitives.random(buf);
}

// Defined in picotls_backend_test.c. Each returns its number of failed checks.
// tx_crypto_test_cloudflare returns -1 when TX_TEST_NETWORK is unset.
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

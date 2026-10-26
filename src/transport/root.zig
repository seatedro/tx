//! tx's network transport: QUIC (ngtcp2) secured by TLS 1.3 (picotls on
//! src/crypto).
pub const quic = @import("quic.zig");

test {
    _ = quic;
}

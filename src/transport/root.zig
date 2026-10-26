//! QUIC (ngtcp2) with TLS 1.3 (picotls on src/crypto).
pub const quic = @import("quic.zig");

test {
    _ = quic;
}

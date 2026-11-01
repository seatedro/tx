//! QUIC transport for tx. quic.zig wraps one ngtcp2 connection with TLS from
//! tls.c, endpoint.zig runs connections over a UDP socket on an xev loop, and
//! pending.zig limits connections that haven't been admitted yet.

pub const quic = @import("quic.zig");
pub const endpoint = @import("endpoint.zig");
pub const pending = @import("pending.zig");
/// crypto.init must run before a quic.Server or pending.Pending is created
/// and before a connection starts. They draw randomness from it.
pub const crypto = @import("crypto");

test {
    _ = quic;
    _ = endpoint;
    _ = pending;
}

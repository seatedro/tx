//! Programs on pseudo-terminals, each feeding a primary terminal that
//! clients replicate.
pub const pty = @import("pty.zig");
pub const host = @import("host.zig");

pub const Pty = pty.Pty;
pub const Host = host.Host;

test {
    _ = pty;
    _ = host;
}

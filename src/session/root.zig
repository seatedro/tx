//! tx's session side: programs on pseudo-terminals, each feeding an
//! authoritative terminal that clients mirror.
pub const pty = @import("pty.zig");
pub const host = @import("host.zig");

pub const Pty = pty.Pty;
pub const Host = host.Host;

test {
    _ = pty;
    _ = host;
}

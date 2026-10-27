//! Programs on pseudo-terminals, each feeding a primary terminal, and the
//! sessions clients attach to.
pub const pty = @import("pty.zig");
pub const host = @import("host.zig");
pub const session = @import("session.zig");

pub const Pty = pty.Pty;
pub const Host = host.Host;
pub const Session = session.Session;

test {
    _ = pty;
    _ = host;
    _ = session;
}

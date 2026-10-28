//! Programs on pseudo-terminals, each feeding a primary terminal, and the
//! sessions clients attach to. Each session runs in its own process (see
//! `process`), and txd reaches it over Unix sockets (see `channel`).
pub const pty = @import("pty.zig");
pub const host = @import("host.zig");
pub const session = @import("session.zig");
pub const unix = @import("unix.zig");
pub const channel = @import("channel.zig");
pub const process = @import("process.zig");
pub const spawn = @import("spawn.zig");

pub const Pty = pty.Pty;
pub const Host = host.Host;
pub const Session = session.Session;
pub const Channel = channel.Channel;

test {
    _ = pty;
    _ = host;
    _ = session;
    _ = unix;
    _ = channel;
    _ = process;
    _ = &spawn.spawn;
}

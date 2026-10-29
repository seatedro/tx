//! A Wayland server with a seat and data control only, so that programs in
//! a session reach the user's clipboard through `wl-paste` and `wl-copy`.
//!
//! `wire` reads and writes messages, `protocol` has the interfaces'
//! opcodes, `server` is the protocol's state, and `socket` puts it on a
//! Unix socket on the loop, on Linux.
const builtin = @import("builtin");

pub const wire = @import("wire.zig");
pub const protocol = @import("protocol.zig");
pub const server = @import("server.zig");
pub const socket = @import("socket.zig");

pub const Server = server.Server;
pub const Connection = server.Connection;
pub const Backend = server.Backend;
pub const Selection = server.Selection;
pub const Listener = socket.Listener;

test {
    _ = wire;
    _ = protocol;
    _ = server;
    if (builtin.os.tag == .linux) _ = socket;
}

//! A Wayland server with clipboards and no display. Programs on its unix
//! socket find a seat with no input devices, a compositor whose surfaces are
//! never shown, an output, and the wlr and ext data-control protocols.
//! wire.zig is the message encoding and protocol.zig the opcodes. server.zig
//! holds each connection's objects and the two selections, and reaches the
//! user's clipboard through a Backend. socket.zig serves a Server on an xev
//! loop, and pipe.zig moves clipboard data through pipes. socket.zig and
//! pipe.zig make Linux syscalls and are used on Linux only.

const builtin = @import("builtin");

pub const wire = @import("wire.zig");
pub const protocol = @import("protocol.zig");
pub const server = @import("server.zig");
pub const socket = @import("socket.zig");
pub const pipe = @import("pipe.zig");

pub const Server = server.Server;
pub const Connection = server.Connection;
pub const Backend = server.Backend;
pub const Selection = server.Selection;
pub const Listener = socket.Listener;

test {
    _ = wire;
    _ = protocol;
    _ = server;
    if (builtin.os.tag == .linux) {
        _ = socket;
        _ = pipe;
    }
}

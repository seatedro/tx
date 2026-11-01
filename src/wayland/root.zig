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

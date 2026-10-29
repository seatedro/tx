//! A Wayland server with a seat and data control only, so that programs in
//! a session reach the user's clipboard through `wl-paste` and `wl-copy`.
//!
//! `wire` reads and writes messages, and `protocol` has the interfaces'
//! opcodes.
pub const wire = @import("wire.zig");
pub const protocol = @import("protocol.zig");

test {
    _ = wire;
    _ = protocol;
}

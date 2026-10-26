//! tx's terminal replication: an authoritative libghostty-vt Terminal fed
//! the program's output, the log of everything it consumed, and mirrors
//! that restore from its snapshot and replay that log to the same state.
pub const log = @import("log.zig");
pub const authority = @import("authority.zig");
pub const mirror = @import("mirror.zig");

pub const Log = log.Log;
pub const Record = log.Record;
pub const Authority = authority.Authority;
pub const Mirror = mirror.Mirror;

test {
    _ = log;
    _ = authority;
    _ = mirror;
}

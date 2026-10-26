//! tx's terminal replication: a primary libghostty-vt Terminal fed
//! the program's output, the log of everything it consumed, and replicas
//! that restore from its snapshot and replay that log to the same state.
//!
//! replication_test.zig checks that claim at every cut point of its corpora,
//! and lists the libghostty-vt limitations where it doesn't hold.
pub const log = @import("log.zig");
pub const primary = @import("primary.zig");
pub const replica = @import("replica.zig");
pub const state = @import("state.zig");

pub const Log = log.Log;
pub const Record = log.Record;
pub const Primary = primary.Primary;
pub const Replica = replica.Replica;

test {
    _ = log;
    _ = primary;
    _ = replica;
    _ = state;
    _ = @import("replication_test.zig");
}

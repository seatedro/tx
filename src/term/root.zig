//! Terminal replication. A `Primary` is the libghostty-vt Terminal fed the
//! program's output plus a `Log` of what it consumed. A `Replica` restores
//! from its snapshot and replays the log to reach the same state.
//!
//! replication_test.zig checks this at every cut point of its corpora and
//! lists the libghostty-vt limitations that break it.
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

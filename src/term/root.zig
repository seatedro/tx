//! A session's terminal state on the server. A `Primary` is the
//! libghostty-vt Terminal fed the program's output plus a `Log` of what it
//! consumed; the client stream is built from the log. A `Replica` restores a
//! primary's state from its snapshot and replays the log to catch up.
//!
//! replication_test.zig checks snapshot restore at every cut point of its
//! corpora and lists the libghostty-vt limitations that break it.
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

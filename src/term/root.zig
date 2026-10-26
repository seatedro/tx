//! A session's terminal state on the server. A `Primary` is the
//! libghostty-vt Terminal fed the program's output plus a `Log` of what it
//! consumed; the client stream is built from the log.
pub const log = @import("log.zig");
pub const primary = @import("primary.zig");
pub const state = @import("state.zig");

pub const Log = log.Log;
pub const Record = log.Record;
pub const Primary = primary.Primary;

test {
    _ = log;
    _ = primary;
    _ = state;
}

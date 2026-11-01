//! Terminal state for a session. A Primary (primary.zig) runs the program's
//! output through a ghostty-vt Terminal and records it in a Log (log.zig).
//! rebuild.zig writes the escape sequences that bring another terminal to the
//! Primary's state. state.zig dumps a Terminal as text so two terminals can be
//! compared, such as a Primary and a copy fed its rebuild or its log.

pub const log = @import("log.zig");
pub const primary = @import("primary.zig");
pub const rebuild = @import("rebuild.zig");
pub const state = @import("state.zig");

/// Only this module imports ghostty-vt. Other modules name its types through vt.
pub const vt = @import("ghostty-vt");

pub const Log = log.Log;
pub const Record = log.Record;
pub const Primary = primary.Primary;

test {
    _ = log;
    _ = primary;
    _ = rebuild;
    _ = state;
}

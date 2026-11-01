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

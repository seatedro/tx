//! The client module, the tx side of a connection to txd. session.run is
//! the client's whole run; the other files are its parts, exported for
//! cli/tx.zig and the end-to-end tests.

pub const tty = @import("tty.zig");
pub const escape = @import("escape.zig");
pub const session = @import("session.zig");
pub const scan = @import("scan.zig");
pub const connect = @import("connect.zig");
pub const passphrase = @import("passphrase.zig");
pub const report = @import("report.zig");
pub const clipboard = @import("clipboard.zig");
pub const pasteboard = @import("pasteboard.zig");

pub const RawMode = tty.RawMode;
pub const Reader = tty.Reader;
pub const Writer = tty.Writer;
pub const Signals = tty.Signals;
pub const Escape = escape.Escape;

test {
    _ = tty;
    _ = escape;
    _ = session;
    _ = scan;
    _ = connect;
    _ = passphrase;
    _ = report;
    _ = clipboard;
    _ = pasteboard;
    // No test here calls run; referencing it gets it compiled.
    _ = &session.run;
}

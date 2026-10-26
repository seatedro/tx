//! The `tx` client's side of the user's terminal.
pub const tty = @import("tty.zig");
pub const escape = @import("escape.zig");
pub const session = @import("session.zig");
pub const scan = @import("scan.zig");
pub const passphrase = @import("passphrase.zig");

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
    _ = passphrase;
    // Analyzes the transport and crypto modules, whose exports the linked
    // C code needs.
    _ = &session.run;
}

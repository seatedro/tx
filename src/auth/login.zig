//! What a client signs to log in, and how the server checks it.
//!
//! The client signs an SSHSIG in namespace `tx-auth-v1@tx` over:
//!
//!     string  exporter    the connection's TLS exporter value
//!     string  host_key    the server's public key blob
//!     string  user        the account to log in as
//!     string  alpn        the connection's ALPN protocol ID
//!     uint32  revision    the protocol revision
//!
//! Each side derives the exporter value from its own TLS state, and the
//! server never sends it. A signature is valid for one connection to one
//! server, and the namespace keeps it from passing as an SSH login.
const std = @import("std");
const Writer = std.Io.Writer;
const ssh = @import("ssh.zig");
const sshsig = @import("sshsig.zig");

pub const namespace = "tx-auth-v1@tx";

/// The TLS exporter label (RFC 8446 §7.5), with an empty context.
pub const exporter_label = "EXPORTER-tx-auth";
pub const exporter_len = 32;

/// The longest user name a login carries. POSIX's LOGIN_NAME_MAX on Linux
/// is 256, terminator included.
pub const max_user_len = 255;

pub const max_alpn_len = 255;

pub const Transcript = struct {
    exporter: [exporter_len]u8,
    host_key: ssh.Key,
    user: []const u8,
    alpn: []const u8,
    revision: u32,

    const max_len = 4 + exporter_len + 4 + ssh.key_blob_len + 4 + max_user_len + 4 + max_alpn_len + 4;

    /// The SSHSIG input. Asserts the lengths are within bounds; the caller
    /// checks a user name it received.
    pub fn signedData(t: Transcript) sshsig.SignedData {
        std.debug.assert(t.user.len <= max_user_len);
        std.debug.assert(t.alpn.len <= max_alpn_len);

        var buf: [max_len]u8 = undefined;
        var w: Writer = .fixed(&buf);
        ssh.writeString(&w, &t.exporter) catch unreachable;
        ssh.writeString(&w, &ssh.keyBlob(t.host_key)) catch unreachable;
        ssh.writeString(&w, t.user) catch unreachable;
        ssh.writeString(&w, t.alpn) catch unreachable;
        w.writeInt(u32, t.revision, .big) catch unreachable;
        return .init(namespace, w.buffered());
    }

    /// Checks a client's signature blob made with `key`.
    pub fn verify(t: Transcript, key: *const ssh.PublicKey, signature_blob: []const u8) sshsig.VerifyError!void {
        return sshsig.verify(key, signature_blob, &t.signedData());
    }
};

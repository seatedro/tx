//! The login transcript. A client logs in by signing it as SSHSIG data with a
//! key that authorized_keys lists. The server rebuilds the transcript with its
//! own host key and verifies the signature. The TLS exporter in the transcript
//! ties a signature to one connection.

const std = @import("std");
const Writer = std.Io.Writer;
const ssh = @import("ssh.zig");
const sshsig = @import("sshsig.zig");

/// The SSHSIG namespace of login signatures.
pub const namespace = "tx-auth-v1@tx";

/// The TLS exporter label for Transcript.exporter, passed to
/// quic.Connection.exportSecret.
pub const exporter_label = "EXPORTER-tx-auth";
pub const exporter_len = 32;

/// The longest user name a Transcript holds. tx refuses longer names before it
/// connects.
pub const max_user_len = 255;

/// TLS caps an ALPN protocol name at 255 bytes (RFC 7301).
pub const max_alpn_len = 255;

/// What a login signature covers. Both ends fill it from their side of the
/// connection, with alpn set to quic.alpn and revision to proto.revision.
pub const Transcript = struct {
    exporter: [exporter_len]u8,
    /// The server's host key. The client uses the key the server presented in
    /// the TLS handshake.
    host_key: ssh.Key,
    /// The account the client asks for. Empty asks for the account txd runs as.
    user: []const u8,
    alpn: []const u8,
    revision: u32,

    const max_len = 4 + exporter_len + 4 + ssh.key_blob_len + 4 + max_user_len + 4 + max_alpn_len + 4;

    /// The SSHSIG data the client signs and the server verifies.
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

    pub fn verify(t: Transcript, key: *const ssh.PublicKey, signature_blob: []const u8) sshsig.VerifyError!void {
        return sshsig.verify(key, signature_blob, &t.signedData());
    }
};

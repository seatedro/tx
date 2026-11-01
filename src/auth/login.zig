const std = @import("std");
const Writer = std.Io.Writer;
const ssh = @import("ssh.zig");
const sshsig = @import("sshsig.zig");

pub const namespace = "tx-auth-v1@tx";

pub const exporter_label = "EXPORTER-tx-auth";
pub const exporter_len = 32;

pub const max_user_len = 255;

pub const max_alpn_len = 255;

pub const Transcript = struct {
    exporter: [exporter_len]u8,
    host_key: ssh.Key,
    user: []const u8,
    alpn: []const u8,
    revision: u32,

    const max_len = 4 + exporter_len + 4 + ssh.key_blob_len + 4 + max_user_len + 4 + max_alpn_len + 4;

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

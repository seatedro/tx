//! The proof a client gives to resume its session on a new connection. The
//! session sends the client a fresh random key in Attached each time the client
//! attaches or resumes, and the proof is an HMAC under the latest key. txd lets
//! Resume through before login, and the session process's check of the proof
//! authenticates the client.

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const key_len = 32;
pub const proof_len = HmacSha256.mac_length;

/// The TLS exporter label for the exporter a proof covers. txd exports it on
/// the resuming connection and hands it to the session in Connect.
pub const exporter_label = "EXPORTER-tx-resume";
pub const exporter_len = 32;

/// HMAC-SHA256 under key of exporter followed by session_id as a big-endian u64.
pub fn proof(key: *const [key_len]u8, exporter: *const [exporter_len]u8, session_id: u64) [proof_len]u8 {
    var mac: HmacSha256 = .init(key);
    mac.update(exporter);
    var id: [8]u8 = undefined;
    std.mem.writeInt(u64, &id, session_id, .big);
    mac.update(&id);
    var out: [proof_len]u8 = undefined;
    mac.final(&out);
    return out;
}

/// Compares got with proof() in constant time. A proof of the wrong length
/// fails.
pub fn verify(key: *const [key_len]u8, exporter: *const [exporter_len]u8, session_id: u64, got: []const u8) bool {
    if (got.len != proof_len) return false;
    const want = proof(key, exporter, session_id);
    return std.crypto.timing_safe.eql([proof_len]u8, want, got[0..proof_len].*);
}

const testing = std.testing;

test "a proof is checked against its key, connection and session" {
    const key: [key_len]u8 = @splat(1);
    const exporter: [exporter_len]u8 = @splat(2);
    const p = proof(&key, &exporter, 7);
    try testing.expect(verify(&key, &exporter, 7, &p));

    const other_key: [key_len]u8 = @splat(3);
    const other_exporter: [exporter_len]u8 = @splat(4);
    try testing.expect(!verify(&other_key, &exporter, 7, &p));
    try testing.expect(!verify(&key, &other_exporter, 7, &p));
    try testing.expect(!verify(&key, &exporter, 8, &p));
    try testing.expect(!verify(&key, &exporter, 7, p[0..16]));
}

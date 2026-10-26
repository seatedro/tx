//! SSH signatures over a message, as `ssh-keygen -Y sign` makes them
//! (OpenSSH's PROTOCOL.sshsig).
//!
//! The key signs `"SSHSIG", string namespace, string reserved, string
//! hash_algorithm, string H(message)`. The namespace keeps a signature for
//! one purpose from being valid for another, such as an SSH login, whose
//! signed data starts with a session ID string.
const std = @import("std");
const Writer = std.Io.Writer;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Ed25519 = std.crypto.sign.Ed25519;
const ssh = @import("ssh.zig");

const magic = "SSHSIG";
const hash_algorithm = "sha512";

/// The longest namespace `SignedData` holds.
pub const max_namespace_len = 64;

/// The bytes a key signs for `message` in `namespace`.
pub const SignedData = struct {
    buf: [magic.len + 4 + max_namespace_len + 4 + 4 + hash_algorithm.len + 4 + Sha512.digest_length]u8,
    len: usize,

    pub fn init(namespace: []const u8, message: []const u8) SignedData {
        std.debug.assert(namespace.len <= max_namespace_len);

        var digest: [Sha512.digest_length]u8 = undefined;
        Sha512.hash(message, &digest, .{});

        var d: SignedData = undefined;
        var w: Writer = .fixed(&d.buf);
        w.writeAll(magic) catch unreachable;
        ssh.writeString(&w, namespace) catch unreachable;
        // Reserved, empty.
        ssh.writeString(&w, "") catch unreachable;
        ssh.writeString(&w, hash_algorithm) catch unreachable;
        ssh.writeString(&w, &digest) catch unreachable;
        d.len = w.end;
        return d;
    }

    pub fn slice(d: *const SignedData) []const u8 {
        return d.buf[0..d.len];
    }
};

pub const VerifyError = ssh.ParseError || error{BadSignature};

/// Checks `signature_blob`, an SSH signature blob, against `key`.
pub fn verify(key: ssh.Key, signature_blob: []const u8, data: *const SignedData) VerifyError!void {
    const sig = try ssh.parseSignatureBlob(signature_blob);
    const public_key = Ed25519.PublicKey.fromBytes(key) catch return error.BadSignature;
    Ed25519.Signature.fromBytes(sig).verify(data.slice(), public_key) catch return error.BadSignature;
}

/// The signature blob for an Ed25519 signature.
pub fn signatureBlob(sig: [64]u8) [ssh.signature_blob_len]u8 {
    var blob: [ssh.signature_blob_len]u8 = undefined;
    var w: Writer = .fixed(&blob);
    ssh.writeString(&w, ssh.ed25519) catch unreachable;
    ssh.writeString(&w, &sig) catch unreachable;
    return blob;
}

const testing = std.testing;

test "a signature from ssh-keygen -Y sign verifies" {
    // `printf 'tx sshsig test' | ssh-keygen -Y sign -f k -n tx-auth-v1@tx`,
    // with the signature taken out of the armored output.
    const key = try ssh.parseKeyText(ssh.ed25519, "AAAAC3NzaC1lZDI1NTE5AAAAICwLzobQsiT0GtH1xeKcMJ3KbPb38YiHHQef9Jr2O9+G");
    var sig: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sig, "d939b4aac26b13710399f6911c58b4c7459aea9b373e548d13b1fac75f5e5b025bb747754d575770bd9719695328b3f128d767f85f658bfef6af78b907f76201");
    const blob = signatureBlob(sig);

    try verify(key, &blob, &.init("tx-auth-v1@tx", "tx sshsig test"));
    try testing.expectError(error.BadSignature, verify(key, &blob, &.init("file", "tx sshsig test")));
    try testing.expectError(error.BadSignature, verify(key, &blob, &.init("tx-auth-v1@tx", "tx sshsig test!")));
}

test "a signature made here verifies" {
    const kp = Ed25519.KeyPair.generate(testing.io);
    const data: SignedData = .init("ns", "message");
    const blob = signatureBlob((try kp.sign(data.slice(), null)).toBytes());
    try verify(kp.public_key.toBytes(), &blob, &data);

    const other = Ed25519.KeyPair.generate(testing.io);
    try testing.expectError(error.BadSignature, verify(other.public_key.toBytes(), &blob, &data));
}

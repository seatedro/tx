//! SSHSIG signed data (OpenSSH's PROTOCOL.sshsig) and verification of the SSH
//! signature blobs made over it. The signed bytes are the ones
//! `ssh-keygen -Y sign` signs. A login signature is made over the SignedData of
//! login.zig's transcript.

const std = @import("std");
const Writer = std.Io.Writer;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const rsa = std.crypto.Certificate.rsa;
const Ed25519 = std.crypto.sign.Ed25519;
const ssh = @import("ssh.zig");

const magic = "SSHSIG";
const hash_algorithm = "sha512";

pub const max_namespace_len = 64;

/// The SSHSIG data a key signs for message under namespace. Per
/// PROTOCOL.sshsig, the preamble and namespace stop a signature over it from
/// verifying as SSH authentication or under another namespace.
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
        // The reserved field.
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

/// Checks signature_blob over data with key. Ed25519 keys take ssh-ed25519
/// signatures and RSA keys take rsa-sha2-512 or rsa-sha2-256. Other signature
/// types are UnsupportedType.
pub fn verify(key: *const ssh.PublicKey, signature_blob: []const u8, data: *const SignedData) VerifyError!void {
    switch (key.kind) {
        .ed25519 => {
            const sig = try ssh.parseSignatureBlob(signature_blob);
            const public_key = Ed25519.PublicKey.fromBytes(key.ed25519Key()) catch return error.BadSignature;
            Ed25519.Signature.fromBytes(sig).verify(data.slice(), public_key) catch return error.BadSignature;
        },
        .rsa => try verifyRsa(key.rsaParts(), signature_blob, data.slice()),
    }
}

fn verifyRsa(key: ssh.PublicKey.RsaParts, signature_blob: []const u8, data: []const u8) VerifyError!void {
    var r: ssh.Reader = .init(signature_blob);
    const sig_type = try r.string();
    const sig = try r.string();
    try r.end();

    const public_key = rsa.PublicKey.fromBytes(key.e, key.n) catch return error.BadSignature;

    // PKCS1v1_5Signature.verify takes the modulus length at comptime. These
    // are ssh.rsa_modulus_lens, which PublicKey.parse enforces.
    switch (key.n.len) {
        inline 128, 256, 384, 512 => |len| {
            // A signature may be shorter than the modulus. OpenSSH's verifier
            // left-pads it with zeros to the modulus length.
            if (sig.len > len) return error.BadSignature;
            var padded: [len]u8 = @splat(0);
            @memcpy(padded[len - sig.len ..], sig);

            // PROTOCOL.sshsig rules out the SHA-1 "ssh-rsa" for RSA keys.
            if (std.mem.eql(u8, sig_type, "rsa-sha2-512")) {
                rsa.PKCS1v1_5Signature.verify(len, &padded, data, public_key, Sha512) catch return error.BadSignature;
            } else if (std.mem.eql(u8, sig_type, "rsa-sha2-256")) {
                rsa.PKCS1v1_5Signature.verify(len, &padded, data, public_key, Sha256) catch return error.BadSignature;
            } else return error.UnsupportedType;
        },
        else => unreachable,
    }
}

/// Encodes a raw Ed25519 signature as an ssh-ed25519 signature blob, the form
/// agents return.
pub fn signatureBlob(sig: [64]u8) [ssh.signature_blob_len]u8 {
    var blob: [ssh.signature_blob_len]u8 = undefined;
    var w: Writer = .fixed(&blob);
    ssh.writeString(&w, ssh.ed25519) catch unreachable;
    ssh.writeString(&w, &sig) catch unreachable;
    return blob;
}

const testing = std.testing;

test "a signature from ssh-keygen -Y sign verifies" {
    const key = try ssh.parseKeyText(ssh.ed25519, "AAAAC3NzaC1lZDI1NTE5AAAAICwLzobQsiT0GtH1xeKcMJ3KbPb38YiHHQef9Jr2O9+G");
    var sig: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sig, "d939b4aac26b13710399f6911c58b4c7459aea9b373e548d13b1fac75f5e5b025bb747754d575770bd9719695328b3f128d767f85f658bfef6af78b907f76201");
    const blob = signatureBlob(sig);

    const pk: ssh.PublicKey = .fromEd25519(key);
    try verify(&pk, &blob, &.init("tx-auth-v1@tx", "tx sshsig test"));
    try testing.expectError(error.BadSignature, verify(&pk, &blob, &.init("file", "tx sshsig test")));
    try testing.expectError(error.BadSignature, verify(&pk, &blob, &.init("tx-auth-v1@tx", "tx sshsig test!")));
}

test "an RSA signature from ssh-keygen -Y sign verifies" {
    const pk = try ssh.parsePublicKeyText(ssh.rsa, ssh.test_rsa_text);
    var sig: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sig, "6b9bb9bf225a4e2b0a2d4719ba12dbcf335b4c9b2603c896d3b9335b83e5d6ab03a9f23ec111bf5b6b7b7da16058103d36e7efdebf63a9cf836b997928b97212415bc3c2e3f222e76b0278b531ce5be00c51305806738891d3f1779ff83faf63f6e8235088726de9fbd83631d5b8006a242f23723b99b7d7ba1b3da75ed166c892142356086b13e44927b08a0ccf5bbdcd8dd1f37bb07fe69716df672bd1d25cb84f9b70c847ea5cffcb5b7fc089f5e6e85643c4c0c2f0b15ff1e506e4c955b2f8b55b25e4cbf9b8f749d9aa7b901e5224c398aee29150e554817c7e7878b7b8281ef5c0b55fea54580031c6dadfc0dcd5b7a037990b1582628fd18f1fe3a6d6");

    var blob_buf: [512]u8 = undefined;
    var w: Writer = .fixed(&blob_buf);
    try ssh.writeString(&w, "rsa-sha2-512");
    try ssh.writeString(&w, &sig);
    const blob = w.buffered();

    try verify(&pk, blob, &.init("tx-auth-v1@tx", "tx sshsig test"));
    try testing.expectError(error.BadSignature, verify(&pk, blob, &.init("tx-auth-v1@tx", "tx sshsig test!")));

    w = .fixed(&blob_buf);
    try ssh.writeString(&w, "ssh-rsa");
    try ssh.writeString(&w, &sig);
    try testing.expectError(error.UnsupportedType, verify(&pk, w.buffered(), &.init("tx-auth-v1@tx", "tx sshsig test")));
    w = .fixed(&blob_buf);
    try ssh.writeString(&w, "rsa-sha2-256");
    try ssh.writeString(&w, &sig);
    try testing.expectError(error.BadSignature, verify(&pk, w.buffered(), &.init("tx-auth-v1@tx", "tx sshsig test")));
}

test "a signature made here verifies" {
    const kp = Ed25519.KeyPair.generate(testing.io);
    const data: SignedData = .init("ns", "message");
    const blob = signatureBlob((try kp.sign(data.slice(), null)).toBytes());
    try verify(&.fromEd25519(kp.public_key.toBytes()), &blob, &data);

    const other = Ed25519.KeyPair.generate(testing.io);
    try testing.expectError(error.BadSignature, verify(&.fromEd25519(other.public_key.toBytes()), &blob, &data));
}

const fuzz = @import("fuzz");

test "fuzz: no signature verifies against a key made of fuzzed fields" {
    try fuzz.run({}, fuzzVerify, .{ .count = 300 });
}

fn fuzzVerify(_: void, in: fuzz.Input) !void {
    const shape = in.enumValue(FuzzShape);
    var key_buf: [ssh.max_key_blob_len + 64]u8 = undefined;
    var key_w: Writer = .fixed(&key_buf);
    try writeFuzzKeyBlob(in, &key_w, shape);
    var sig_buf: [1024]u8 = undefined;
    var sig_w: Writer = .fixed(&sig_buf);
    try writeFuzzSignatureBlob(in, &sig_w, if (in.chance(7, 1)) shape else in.enumValue(FuzzShape));

    const key = ssh.PublicKey.parse(key_w.buffered()) catch return;
    try testing.expectEqualSlices(u8, key_w.buffered(), key.blob());
    if (verify(&key, sig_w.buffered(), &.init("tx-auth-v1@tx", "fuzz"))) {
        return error.ForgedSignature;
    } else |_| {}
}

const FuzzShape = enum { ed25519, rsa, bytes };

fn writeFuzzKeyBlob(in: fuzz.Input, w: *Writer, shape: FuzzShape) !void {
    var buf: [ssh.max_key_blob_len]u8 = undefined;
    switch (shape) {
        .ed25519 => {
            try ssh.writeString(w, ssh.ed25519);
            if (in.chance(15, 1)) {
                in.fill(buf[0..32]);
                try ssh.writeString(w, buf[0..32]);
            } else try ssh.writeString(w, in.bytes(buf[0..64]));
        },
        .rsa => {
            try ssh.writeString(w, ssh.rsa);

            try ssh.writeString(w, if (in.chance(3, 1)) "\x01\x00\x01" else in.bytes(buf[0..5]));

            // Moduli fall on a supported length or one byte off it, and some
            // carry the zero byte an mpint with its top bit set has.
            const lens = ssh.rsa_modulus_lens;
            const len = lens[in.index(lens.len)] + (if (in.chance(3, 1)) 1 else in.int(usize, 0, 2)) - 1;
            const zero: usize = if (in.chance(1, 3)) 1 else 0;
            buf[0] = 0;
            const n = buf[zero .. zero + len];
            in.fill(n);

            // The top bit keeps the modulus at its length. std.crypto.ff
            // rejects an even modulus.
            if (in.chance(7, 1)) {
                n[0] |= 0x80;
                n[n.len - 1] |= 1;
            }
            try ssh.writeString(w, buf[0 .. zero + len]);
        },
        .bytes => try w.writeAll(in.bytes(&buf)),
    }
    if (in.chance(1, 15)) try w.writeAll(in.bytes(buf[0..8]));
}

fn writeFuzzSignatureBlob(in: fuzz.Input, w: *Writer, shape: FuzzShape) !void {
    var buf: [520]u8 = undefined;
    switch (shape) {
        .ed25519 => {
            try ssh.writeString(w, ssh.ed25519);
            in.fill(buf[0..64]);
            try ssh.writeString(w, buf[0..64]);
        },
        .rsa => {
            const types = [_][]const u8{ "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa" };
            try ssh.writeString(w, types[in.index(types.len)]);
            try ssh.writeString(w, in.bytes(&buf));
        },
        .bytes => try w.writeAll(in.bytes(&buf)),
    }
}

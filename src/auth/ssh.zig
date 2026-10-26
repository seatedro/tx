//! SSH wire encodings (RFC 4251 §5), and Ed25519 (RFC 8709) and RSA
//! (RFC 4253 §6.6) keys in SSH's formats.
//!
//! A `string` is a big-endian u32 length followed by that many bytes, and
//! an `mpint` is a string holding a big-endian integer. An Ed25519 public
//! key blob is `string "ssh-ed25519", string key`, and an RSA one is
//! `string "ssh-rsa", mpint e, mpint n`. A signature blob is the signature
//! type, then the signature as a string.
const std = @import("std");
const Writer = std.Io.Writer;
const Sha256 = std.crypto.hash.sha2.Sha256;
const base64 = std.base64.standard;
const base64_no_pad = std.base64.standard_no_pad;

pub const ed25519 = "ssh-ed25519";
pub const rsa = "ssh-rsa";

/// An Ed25519 public key.
pub const Key = [32]u8;

/// The length of an Ed25519 public key blob.
pub const key_blob_len = 4 + ed25519.len + 4 + 32;

/// The length of an Ed25519 signature blob.
pub const signature_blob_len = 4 + ed25519.len + 4 + 64;

/// The longest blob `PublicKey` holds, with room for a 4096-bit RSA key.
pub const max_key_blob_len = 1024;

/// RSA moduli tx verifies, in bytes: 1024 to 4096 bits, which std's
/// PKCS#1 v1.5 verifier covers. OpenSSH refuses keys under 1024 bits.
pub const rsa_modulus_lens = [_]usize{ 128, 256, 384, 512 };

pub const ParseError = error{
    /// The bytes end inside a field, or have bytes left after the last one.
    Malformed,
    /// A well-formed key or signature of another type, such as RSA.
    UnsupportedType,
};

pub fn writeString(w: *Writer, bytes: []const u8) Writer.Error!void {
    try w.writeInt(u32, @intCast(bytes.len), .big);
    try w.writeAll(bytes);
}

/// Reads SSH wire fields from a byte slice.
pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    pub fn byte(r: *Reader) ParseError!u8 {
        if (r.pos == r.bytes.len) return error.Malformed;
        r.pos += 1;
        return r.bytes[r.pos - 1];
    }

    pub fn uint32(r: *Reader) ParseError!u32 {
        if (r.bytes.len - r.pos < 4) return error.Malformed;
        const value = std.mem.readInt(u32, r.bytes[r.pos..][0..4], .big);
        r.pos += 4;
        return value;
    }

    /// Points into the reader's bytes.
    pub fn string(r: *Reader) ParseError![]const u8 {
        const len = try r.uint32();
        if (r.bytes.len - r.pos < len) return error.Malformed;
        const value = r.bytes[r.pos..][0..len];
        r.pos += len;
        return value;
    }

    /// Fails if bytes are left over.
    pub fn end(r: *const Reader) ParseError!void {
        if (r.pos != r.bytes.len) return error.Malformed;
    }
};

pub fn keyBlob(key: Key) [key_blob_len]u8 {
    var blob: [key_blob_len]u8 = undefined;
    var w: Writer = .fixed(&blob);
    writeString(&w, ed25519) catch unreachable;
    writeString(&w, &key) catch unreachable;
    return blob;
}

pub fn parseKeyBlob(blob: []const u8) ParseError!Key {
    // Other types have other fields after the type.
    var r: Reader = .init(blob);
    const key_type = try r.string();
    if (!std.mem.eql(u8, key_type, ed25519)) return error.UnsupportedType;

    const key = try r.string();
    try r.end();
    if (key.len != 32) return error.Malformed;
    return key[0..32].*;
}

/// The 64-byte signature in an Ed25519 signature blob.
pub fn parseSignatureBlob(blob: []const u8) ParseError![64]u8 {
    var r: Reader = .init(blob);
    const sig_type = try r.string();
    const sig = try r.string();
    try r.end();

    if (!std.mem.eql(u8, sig_type, ed25519)) return error.UnsupportedType;
    if (sig.len != 64) return error.Malformed;
    return sig[0..64].*;
}

/// A user's public key, as its blob: Ed25519, or RSA with a modulus in
/// `rsa_modulus_lens`.
pub const PublicKey = struct {
    kind: Kind,
    buf: [max_key_blob_len]u8,
    len: usize,

    pub const Kind = enum { ed25519, rsa };

    pub fn fromEd25519(key: Key) PublicKey {
        var pk: PublicKey = .{ .kind = .ed25519, .buf = undefined, .len = key_blob_len };
        @memcpy(pk.buf[0..key_blob_len], &keyBlob(key));
        return pk;
    }

    /// Checks the blob's type and fields, and copies it.
    pub fn parse(blob_bytes: []const u8) ParseError!PublicKey {
        var r: Reader = .init(blob_bytes);
        const key_type = try r.string();

        const kind: Kind = if (std.mem.eql(u8, key_type, ed25519)) kind: {
            _ = try parseKeyBlob(blob_bytes);
            break :kind .ed25519;
        } else if (std.mem.eql(u8, key_type, rsa)) kind: {
            const e = trimZeros(try r.string());
            const n = trimZeros(try r.string());
            try r.end();
            if (e.len == 0 or e.len > 4) return error.Malformed;
            if (std.mem.indexOfScalar(usize, &rsa_modulus_lens, n.len) == null) return error.UnsupportedType;
            break :kind .rsa;
        } else return error.UnsupportedType;

        if (blob_bytes.len > max_key_blob_len) return error.UnsupportedType;
        var pk: PublicKey = .{ .kind = kind, .buf = undefined, .len = blob_bytes.len };
        @memcpy(pk.buf[0..blob_bytes.len], blob_bytes);
        return pk;
    }

    pub fn blob(pk: *const PublicKey) []const u8 {
        return pk.buf[0..pk.len];
    }

    pub fn eql(a: *const PublicKey, b: *const PublicKey) bool {
        return std.mem.eql(u8, a.blob(), b.blob());
    }

    /// Asserts the key is Ed25519.
    pub fn ed25519Key(pk: *const PublicKey) Key {
        std.debug.assert(pk.kind == .ed25519);
        return parseKeyBlob(pk.blob()) catch unreachable;
    }

    pub const RsaParts = struct {
        /// Big-endian, without leading zero bytes.
        e: []const u8,
        n: []const u8,
    };

    /// Asserts the key is RSA.
    pub fn rsaParts(pk: *const PublicKey) RsaParts {
        std.debug.assert(pk.kind == .rsa);
        var r: Reader = .init(pk.blob());
        _ = r.string() catch unreachable;
        const e = r.string() catch unreachable;
        const n = r.string() catch unreachable;
        return .{ .e = trimZeros(e), .n = trimZeros(n) };
    }

    /// An mpint has a leading zero byte when its top bit is set.
    fn trimZeros(bytes: []const u8) []const u8 {
        const start = std.mem.indexOfNone(u8, bytes, &.{0}) orelse bytes.len;
        return bytes[start..];
    }
};

/// Parses the type and base64 fields of a user key line, such as
/// `ssh-rsa AAAAB3Nza...`.
pub fn parsePublicKeyText(key_type: []const u8, text: []const u8) ParseError!PublicKey {
    if (!std.mem.eql(u8, key_type, ed25519) and !std.mem.eql(u8, key_type, rsa)) return error.UnsupportedType;

    var blob_buf: [max_key_blob_len]u8 = undefined;
    const len = base64.Decoder.calcSizeForSlice(text) catch return error.Malformed;
    if (len > blob_buf.len) return error.UnsupportedType;
    base64.Decoder.decode(blob_buf[0..len], text) catch return error.Malformed;

    // The blob names its type again.
    const pk = try PublicKey.parse(blob_buf[0..len]);
    if (!std.mem.eql(u8, key_type, typeName(pk.kind))) return error.Malformed;
    return pk;
}

fn typeName(kind: PublicKey.Kind) []const u8 {
    return switch (kind) {
        .ed25519 => ed25519,
        .rsa => rsa,
    };
}

/// `SHA256:` and the unpadded base64 of the key blob's SHA-256, as
/// `ssh-keygen -l` prints it.
pub const Fingerprint = struct {
    buf: [prefix.len + base64_no_pad.Encoder.calcSize(Sha256.digest_length)]u8,

    const prefix = "SHA256:";

    pub fn init(key: Key) Fingerprint {
        return .ofBlob(&keyBlob(key));
    }

    pub fn ofBlob(blob: []const u8) Fingerprint {
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(blob, &digest, .{});

        var f: Fingerprint = undefined;
        @memcpy(f.buf[0..prefix.len], prefix);
        _ = base64_no_pad.Encoder.encode(f.buf[prefix.len..], &digest);
        return f;
    }

    pub fn slice(f: *const Fingerprint) []const u8 {
        return &f.buf;
    }
};

/// The base64 text of a key blob, as in `authorized_keys` and
/// `known_hosts`.
pub const KeyText = struct {
    buf: [base64.Encoder.calcSize(key_blob_len)]u8,

    pub fn init(key: Key) KeyText {
        var t: KeyText = undefined;
        _ = base64.Encoder.encode(&t.buf, &keyBlob(key));
        return t;
    }

    pub fn slice(t: *const KeyText) []const u8 {
        return &t.buf;
    }
};

/// Parses the type and base64 fields of a key line, such as
/// `ssh-ed25519 AAAAC3Nza...`.
pub fn parseKeyText(key_type: []const u8, text: []const u8) ParseError!Key {
    if (!std.mem.eql(u8, key_type, ed25519)) return error.UnsupportedType;

    var blob: [key_blob_len]u8 = undefined;
    const len = base64.Decoder.calcSizeForSlice(text) catch return error.Malformed;
    if (len != blob.len) return error.Malformed;
    base64.Decoder.decode(&blob, text) catch return error.Malformed;

    // The blob names its type again.
    return parseKeyBlob(&blob);
}

const testing = std.testing;

// From `ssh-keygen -t ed25519`; the fingerprint is what `ssh-keygen -l`
// printed for it.
const test_key_text = "AAAAC3NzaC1lZDI1NTE5AAAAICwLzobQsiT0GtH1xeKcMJ3KbPb38YiHHQef9Jr2O9+G";
const test_fingerprint = "SHA256:tbkLBLBNmeAZ3u08t0OonJm71SRGcbFGkGYDlm6EWG8";

test "a key round trips through its text form" {
    const key = try parseKeyText(ed25519, test_key_text);
    try testing.expectEqualStrings(test_key_text, KeyText.init(key).slice());
}

test "fingerprints match ssh-keygen" {
    const key = try parseKeyText(ed25519, test_key_text);
    try testing.expectEqualStrings(test_fingerprint, Fingerprint.init(key).slice());
}

test "other key types are reported as unsupported" {
    // An ecdsa-sha2-nistp256 key.
    const ecdsa = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNCNg5OO4oTs4qkgdGtvkLV1c5URSQDz2aWiebRKmvzW1T1Y+H+GHwgXCEN/SohRgI9jrPzh1lBl7SsE91V9fX0=";
    try testing.expectError(error.UnsupportedType, parseKeyText("ecdsa-sha2-nistp256", ecdsa));

    var blob = keyBlob(@splat(1));
    blob[4 + 4] = 'X';
    try testing.expectError(error.UnsupportedType, parseKeyBlob(&blob));
}

// From `ssh-keygen -t rsa -b 2048`.
pub const test_rsa_text = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC3DV8Ze84UBaRlEUFoKXypZ4Jrn4RAf5JhQ2qKfVKq5j80Z0drN8K2x+QceLwKJMmdXY0hWtnIVSM0go9j6eCNqsfEIepKZsEjCbKifoXE0TSJlH2rs/9t6kkGEy2UMHoxwh04O/V54+5nukINiFuH7yANaI8+3xak73R19OPg2yV9waBg5ejhfitQXzKus+6mYEoY8sj058hVKKhIeuq3nuqZX6bSdGU36l4iBbj3RPzljGVC0pkZ0HUwol1QbDfz3fX13/BjeLI0x42lRlBdz4xRGRYXphHf/2ure1h7ZMloMX24khEIN3SKDZ3BpUFBu2pyRAl6VS57aaav15gd";

test "an RSA key parses and round trips through its blob" {
    const pk = try parsePublicKeyText(rsa, test_rsa_text);
    try testing.expectEqual(.rsa, pk.kind);
    try testing.expectEqual(256, pk.rsaParts().n.len);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x01 }, pk.rsaParts().e);
    try testing.expect(pk.eql(&try PublicKey.parse(pk.blob())));

    // The line's type has to match the blob's.
    try testing.expectError(error.Malformed, parsePublicKeyText(ed25519, test_rsa_text));
}

test "user keys of other types and sizes are unsupported" {
    // An ecdsa-sha2-nistp256 key.
    try testing.expectError(error.UnsupportedType, parsePublicKeyText("ecdsa-sha2-nistp256", "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNCNg5OO4oTs4qkgdGtvkLV1c5URSQDz2aWiebRKmvzW1T1Y+H+GHwgXCEN/SohRgI9jrPzh1lBl7SsE91V9fX0="));

    // A 512-bit RSA modulus.
    var blob: [128]u8 = undefined;
    var w: Writer = .fixed(&blob);
    try writeString(&w, rsa);
    try writeString(&w, &.{ 0x01, 0x00, 0x01 });
    try writeString(&w, &(@as([64]u8, @splat(0xff))));
    try testing.expectError(error.UnsupportedType, PublicKey.parse(w.buffered()));
}

test "malformed keys are rejected" {
    try testing.expectError(error.Malformed, parseKeyText(ed25519, "not base64!"));
    try testing.expectError(error.Malformed, parseKeyText(ed25519, test_key_text[0..40]));

    const blob = keyBlob(@splat(1));
    try testing.expectError(error.Malformed, parseKeyBlob(blob[0 .. blob.len - 1]));
    try testing.expectError(error.Malformed, parseKeyBlob(&(blob ++ [_]u8{0})));
}

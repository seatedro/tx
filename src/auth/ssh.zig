//! SSH wire encodings (RFC 4251 §5) and Ed25519 keys in SSH's formats
//! (RFC 8709).
//!
//! A `string` is a big-endian u32 length followed by that many bytes. A
//! public key blob is `string "ssh-ed25519", string key`, and a signature
//! blob is `string "ssh-ed25519", string signature`.
const std = @import("std");
const Writer = std.Io.Writer;
const Sha256 = std.crypto.hash.sha2.Sha256;
const base64 = std.base64.standard;
const base64_no_pad = std.base64.standard_no_pad;

pub const ed25519 = "ssh-ed25519";

/// An Ed25519 public key.
pub const Key = [32]u8;

/// The length of an Ed25519 public key blob.
pub const key_blob_len = 4 + ed25519.len + 4 + 32;

/// The length of an Ed25519 signature blob.
pub const signature_blob_len = 4 + ed25519.len + 4 + 64;

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
    var r: Reader = .init(blob);
    const key_type = try r.string();
    const key = try r.string();
    try r.end();

    if (!std.mem.eql(u8, key_type, ed25519)) return error.UnsupportedType;
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

/// `SHA256:` and the unpadded base64 of the key blob's SHA-256, as
/// `ssh-keygen -l` prints it.
pub const Fingerprint = struct {
    buf: [prefix.len + base64_no_pad.Encoder.calcSize(Sha256.digest_length)]u8,

    const prefix = "SHA256:";

    pub fn init(key: Key) Fingerprint {
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(&keyBlob(key), &digest, .{});

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

test "malformed keys are rejected" {
    try testing.expectError(error.Malformed, parseKeyText(ed25519, "not base64!"));
    try testing.expectError(error.Malformed, parseKeyText(ed25519, test_key_text[0..40]));

    const blob = keyBlob(@splat(1));
    try testing.expectError(error.Malformed, parseKeyBlob(blob[0 .. blob.len - 1]));
    try testing.expectError(error.Malformed, parseKeyBlob(&(blob ++ [_]u8{0})));
}

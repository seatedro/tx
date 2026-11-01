//! OpenSSH private key files (openssh-key-v1, PROTOCOL.key) holding one Ed25519
//! key. A file is unencrypted, or encrypted with aes256-ctr under the bcrypt
//! KDF, the scheme ssh-keygen uses for a passphrase. tx signs logins with keys
//! from these files when the agent doesn't hold them.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const Aes256 = std.crypto.core.aes.Aes256;
const base64 = std.base64.standard;
const ssh = @import("ssh.zig");

const begin_line = "-----BEGIN OPENSSH PRIVATE KEY-----";
const end_line = "-----END OPENSSH PRIVATE KEY-----";
const magic = "openssh-key-v1\x00";

pub const ParseError = error{
    Malformed,
    UnsupportedType,
    UnsupportedCipher,
} || Allocator.Error;

pub const DecryptError = error{ Malformed, WrongPassphrase };

/// A parsed key file. It owns bytes, the decoded file, which deinit zeroes and
/// frees.
pub const PrivateKeyFile = struct {
    bytes: []u8,
    public_key: ssh.Key,
    kdf: ?Kdf,
    /// The private key list, encrypted when kdf is set. It points into bytes.
    private: []u8,

    const Kdf = struct {
        salt: []const u8,
        rounds: u32,
    };

    pub fn parse(gpa: Allocator, text: []const u8) ParseError!PrivateKeyFile {
        const bytes = try decodeArmor(gpa, text);
        errdefer gpa.free(bytes);
        if (!std.mem.startsWith(u8, bytes, magic)) return error.Malformed;

        var r: ssh.Reader = .init(bytes[magic.len..]);
        const cipher = r.string() catch return error.Malformed;
        const kdf_name = r.string() catch return error.Malformed;
        const kdf_options = r.string() catch return error.Malformed;
        const count = r.uint32() catch return error.Malformed;
        if (count != 1) return error.Malformed;
        const public_blob = r.string() catch return error.Malformed;
        const private = r.string() catch return error.Malformed;
        r.end() catch return error.Malformed;

        const public_key = ssh.parseKeyBlob(public_blob) catch |err| return switch (err) {
            error.UnsupportedType => error.UnsupportedType,
            error.Malformed => error.Malformed,
        };

        const kdf: ?Kdf = if (std.mem.eql(u8, cipher, "none") and std.mem.eql(u8, kdf_name, "none"))
            null
        else if (std.mem.eql(u8, cipher, "aes256-ctr") and std.mem.eql(u8, kdf_name, "bcrypt")) kdf: {
            var o: ssh.Reader = .init(kdf_options);
            const salt = o.string() catch return error.Malformed;
            const rounds = o.uint32() catch return error.Malformed;
            o.end() catch return error.Malformed;
            break :kdf .{ .salt = salt, .rounds = rounds };
        } else return error.UnsupportedCipher;

        // The private key list is padded to the cipher's block size.
        if (kdf != null and private.len % Aes256.block.block_length != 0) return error.Malformed;

        return .{ .bytes = bytes, .public_key = public_key, .kdf = kdf, .private = @constCast(private) };
    }

    pub fn deinit(f: *PrivateKeyFile, gpa: Allocator) void {
        std.crypto.secureZero(u8, f.bytes);
        gpa.free(f.bytes);
        f.* = undefined;
    }

    pub fn isEncrypted(f: *const PrivateKeyFile) bool {
        return f.kdf != null;
    }

    /// Decrypts the private key list with passphrase and returns its key pair.
    /// An unencrypted file ignores passphrase. The caller zeroes the key pair.
    pub fn decrypt(f: *const PrivateKeyFile, passphrase: []const u8) DecryptError!Ed25519.KeyPair {
        var plain_buf: [512]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain_buf);
        if (f.private.len > plain_buf.len) return error.Malformed;
        const plain = plain_buf[0..f.private.len];

        if (f.kdf) |kdf| {
            // opensshKdf rejects an empty passphrase as invalid input.
            if (passphrase.len == 0) return error.WrongPassphrase;

            // bcrypt_pbkdf derives the AES-256 key and the CTR IV as one output.
            var key_iv: [32 + 16]u8 = undefined;
            defer std.crypto.secureZero(u8, &key_iv);
            std.crypto.pwhash.bcrypt.opensshKdf(passphrase, kdf.salt, &key_iv, kdf.rounds) catch return error.Malformed;

            const aes = Aes256.initEnc(key_iv[0..32].*);
            std.crypto.core.modes.ctr(@TypeOf(aes), aes, plain, f.private, key_iv[32..48].*, .big);
        } else {
            @memcpy(plain, f.private);
        }

        // The list starts with the same random u32 twice (PROTOCOL.key).
        // Equal values show the passphrase was right.
        var r: ssh.Reader = .init(plain);
        const check1 = r.uint32() catch return error.Malformed;
        const check2 = r.uint32() catch return error.Malformed;
        if (check1 != check2) return error.WrongPassphrase;

        const key_type = r.string() catch return error.Malformed;
        const public = r.string() catch return error.Malformed;
        const secret = r.string() catch return error.Malformed;
        if (!std.mem.eql(u8, key_type, ssh.ed25519) or public.len != 32 or secret.len != 64) return error.Malformed;
        if (!std.mem.eql(u8, public, &f.public_key)) return error.Malformed;

        // OpenSSH's Ed25519 secret is the seed followed by the public key, the
        // layout of Ed25519.SecretKey.
        const secret_key = Ed25519.SecretKey.fromBytes(secret[0..64].*) catch return error.Malformed;
        return Ed25519.KeyPair.fromSecretKey(secret_key) catch error.Malformed;
    }
};

fn decodeArmor(gpa: Allocator, text: []const u8) ParseError![]u8 {
    const begin = std.mem.indexOf(u8, text, begin_line) orelse return error.Malformed;
    const body_start = begin + begin_line.len;
    const end = std.mem.indexOfPos(u8, text, body_start, end_line) orelse return error.Malformed;

    // In an unencrypted file the base64 text holds the private key.
    var b64: std.ArrayList(u8) = .empty;
    defer {
        std.crypto.secureZero(u8, b64.items);
        b64.deinit(gpa);
    }
    for (text[body_start..end]) |ch| switch (ch) {
        ' ', '\t', '\r', '\n' => {},
        else => try b64.append(gpa, ch),
    };

    const len = base64.Decoder.calcSizeForSlice(b64.items) catch return error.Malformed;
    const bytes = try gpa.alloc(u8, len);
    errdefer gpa.free(bytes);
    base64.Decoder.decode(bytes, b64.items) catch return error.Malformed;
    return bytes;
}

const testing = std.testing;

const plain_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    \\QyNTUxOQAAACDI/tJmA4x7Bqj2AcaIoSueX1FmHADCLttG/2lcclxpWQAAAIjXUWLl11Fi
    \\5QAAAAtzc2gtZWQyNTUxOQAAACDI/tJmA4x7Bqj2AcaIoSueX1FmHADCLttG/2lcclxpWQ
    \\AAAEAgNr/hbGFlAKl+PqHYq7+Fb0LObTU5440OQQiXF0X+G8j+0mYDjHsGqPYBxoihK55f
    \\UWYcAMIu20b/aVxyXGlZAAAABXBsYWlu
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
const plain_public = "AAAAC3NzaC1lZDI1NTE5AAAAIMj+0mYDjHsGqPYBxoihK55fUWYcAMIu20b/aVxyXGlZ";

const encrypted_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAm/7i1ie
    \\UhrMoBGLvmYoqEAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAINCQJexQXcQKPgL7
    \\X1aHoO45B6XEMcJxRSwTy8TYKT6vAAAAkMWEVaaFHfH4dTZLp0RicWHT1/vWTXf2iW8Vlf
    \\bRk9QcckE+ynTGOb28DigYKDoFQoPiLnvB0kFtPGmTq2QBbnIL+5EO+TQbxEhXkUGo9OUk
    \\z7FhHZW/Fqm4oivLFKYSdMTQmi8vpsmT79m0jYlPaa+6W5AqhjNaGWxdqpEk/GA28CCTKY
    \\JXjp9dszWtvnBnHQ==
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
const encrypted_public = "AAAAC3NzaC1lZDI1NTE5AAAAINCQJexQXcQKPgL7X1aHoO45B6XEMcJxRSwTy8TYKT6v";

test "an unencrypted key decrypts to its key pair" {
    var f: PrivateKeyFile = try .parse(testing.allocator, plain_key);
    defer f.deinit(testing.allocator);
    try testing.expect(!f.isEncrypted());

    const want = try ssh.parseKeyText(ssh.ed25519, plain_public);
    try testing.expectEqual(want, f.public_key);
    const kp = try f.decrypt("");
    try testing.expectEqual(want, kp.public_key.toBytes());
}

test "an encrypted key needs its passphrase" {
    var f: PrivateKeyFile = try .parse(testing.allocator, encrypted_key);
    defer f.deinit(testing.allocator);
    try testing.expect(f.isEncrypted());

    const want = try ssh.parseKeyText(ssh.ed25519, encrypted_public);
    try testing.expectEqual(want, f.public_key);

    try testing.expectError(error.WrongPassphrase, f.decrypt("wrong"));
    try testing.expectError(error.WrongPassphrase, f.decrypt(""));
    const kp = try f.decrypt("correct horse");
    try testing.expectEqual(want, kp.public_key.toBytes());

    const sig = try kp.sign("data", null);
    try sig.verify("data", try .fromBytes(want));
}

test "other files are rejected" {
    try testing.expectError(error.Malformed, PrivateKeyFile.parse(testing.allocator, "ssh-ed25519 " ++ plain_public));
    try testing.expectError(error.Malformed, PrivateKeyFile.parse(testing.allocator, begin_line ++ "\nnot base64\n" ++ end_line));

    var w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer w.deinit();
    try w.writer.writeAll(magic);
    try ssh.writeString(&w.writer, "none");
    try ssh.writeString(&w.writer, "none");
    try ssh.writeString(&w.writer, "");
    try w.writer.writeInt(u32, 1, .big);
    var rsa_blob: std.Io.Writer.Allocating = .init(testing.allocator);
    defer rsa_blob.deinit();
    try ssh.writeString(&rsa_blob.writer, "ssh-rsa");
    try ssh.writeString(&rsa_blob.writer, "\x01\x00\x01");
    try ssh.writeString(&rsa_blob.writer, "\x00\xc0");
    try ssh.writeString(&w.writer, rsa_blob.written());
    try ssh.writeString(&w.writer, "");

    const b64 = try testing.allocator.alloc(u8, base64.Encoder.calcSize(w.written().len));
    defer testing.allocator.free(b64);
    _ = base64.Encoder.encode(b64, w.written());
    const text = try std.mem.concat(testing.allocator, u8, &.{ begin_line, "\n", b64, "\n", end_line, "\n" });
    defer testing.allocator.free(text);
    try testing.expectError(error.UnsupportedType, PrivateKeyFile.parse(testing.allocator, text));
}

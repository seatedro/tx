//! OpenSSH private key files (OpenSSH's PROTOCOL.key), such as
//! `~/.ssh/id_ed25519`.
//!
//! The file is base64 between `-----BEGIN OPENSSH PRIVATE KEY-----` and
//! `-----END OPENSSH PRIVATE KEY-----`. Decoded, it is:
//!
//!     "openssh-key-v1\0"
//!     string  cipher       "none", or "aes256-ctr" for a passphrase
//!     string  kdf          "none", or "bcrypt"
//!     string  kdf options  for bcrypt: string salt, uint32 rounds
//!     uint32  keys         1
//!     string  public key blob
//!     string  private section, encrypted with the cipher
//!
//! The private section holds two equal uint32 check values, then the key's
//! type, public key, 64-byte secret key and comment, then padding. The check
//! values tell a wrong passphrase from a right one.
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
    /// Not an OpenSSH private key file, or a damaged one.
    Malformed,
    /// A key other than Ed25519.
    UnsupportedType,
    /// Encrypted with a cipher or key derivation other than aes256-ctr and
    /// bcrypt, the defaults of `ssh-keygen`.
    UnsupportedCipher,
} || Allocator.Error;

pub const DecryptError = error{ Malformed, WrongPassphrase };

pub const PrivateKeyFile = struct {
    /// The decoded file. The fields below point into it.
    bytes: []u8,
    public_key: ssh.Key,
    /// Null when the key has no passphrase.
    kdf: ?Kdf,
    /// The private section, still encrypted if `kdf` is set.
    private: []u8,

    const Kdf = struct {
        salt: []const u8,
        rounds: u32,
    };

    /// Parses the file's text. Reading the public key needs no passphrase.
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

        // Unencrypted, or aes256-ctr with a key and IV from bcrypt_pbkdf.
        const kdf: ?Kdf = if (std.mem.eql(u8, cipher, "none") and std.mem.eql(u8, kdf_name, "none"))
            null
        else if (std.mem.eql(u8, cipher, "aes256-ctr") and std.mem.eql(u8, kdf_name, "bcrypt")) kdf: {
            var o: ssh.Reader = .init(kdf_options);
            const salt = o.string() catch return error.Malformed;
            const rounds = o.uint32() catch return error.Malformed;
            o.end() catch return error.Malformed;
            break :kdf .{ .salt = salt, .rounds = rounds };
        } else return error.UnsupportedCipher;

        // An encrypted section is padded to whole AES blocks.
        if (kdf != null and private.len % Aes256.block.block_length != 0) return error.Malformed;

        // `private` points into `bytes`, which is mutable.
        return .{ .bytes = bytes, .public_key = public_key, .kdf = kdf, .private = @constCast(private) };
    }

    /// Wipes the file, secret key included.
    pub fn deinit(f: *PrivateKeyFile, gpa: Allocator) void {
        std.crypto.secureZero(u8, f.bytes);
        gpa.free(f.bytes);
        f.* = undefined;
    }

    pub fn isEncrypted(f: *const PrivateKeyFile) bool {
        return f.kdf != null;
    }

    /// The key pair. `passphrase` is ignored for an unencrypted key.
    pub fn decrypt(f: *const PrivateKeyFile, passphrase: []const u8) DecryptError!Ed25519.KeyPair {
        // Decrypted into a copy, so a wrong passphrase leaves the file as
        // it was for another try.
        var plain_buf: [512]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain_buf);
        if (f.private.len > plain_buf.len) return error.Malformed;
        const plain = plain_buf[0..f.private.len];

        if (f.kdf) |kdf| {
            if (passphrase.len == 0) return error.WrongPassphrase;

            // 32 bytes of AES-256 key, then the 16-byte initial counter.
            var key_iv: [32 + 16]u8 = undefined;
            defer std.crypto.secureZero(u8, &key_iv);
            std.crypto.pwhash.bcrypt.opensshKdf(passphrase, kdf.salt, &key_iv, kdf.rounds) catch return error.Malformed;

            const aes = Aes256.initEnc(key_iv[0..32].*);
            std.crypto.core.modes.ctr(@TypeOf(aes), aes, plain, f.private, key_iv[32..48].*, .big);
        } else {
            @memcpy(plain, f.private);
        }

        // Equal check values mean the passphrase was right.
        var r: ssh.Reader = .init(plain);
        const check1 = r.uint32() catch return error.Malformed;
        const check2 = r.uint32() catch return error.Malformed;
        if (check1 != check2) return error.WrongPassphrase;

        const key_type = r.string() catch return error.Malformed;
        const public = r.string() catch return error.Malformed;
        const secret = r.string() catch return error.Malformed;
        if (!std.mem.eql(u8, key_type, ssh.ed25519) or public.len != 32 or secret.len != 64) return error.Malformed;
        if (!std.mem.eql(u8, public, &f.public_key)) return error.Malformed;

        const secret_key = Ed25519.SecretKey.fromBytes(secret[0..64].*) catch return error.Malformed;
        return Ed25519.KeyPair.fromSecretKey(secret_key) catch error.Malformed;
    }
};

/// The bytes between the BEGIN and END lines, base64-decoded. Owned by the
/// caller.
fn decodeArmor(gpa: Allocator, text: []const u8) ParseError![]u8 {
    const begin = std.mem.indexOf(u8, text, begin_line) orelse return error.Malformed;
    const body_start = begin + begin_line.len;
    const end = std.mem.indexOfPos(u8, text, body_start, end_line) orelse return error.Malformed;

    // The base64 is split into lines.
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

// `ssh-keygen -t ed25519 -N ''`.
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

// `ssh-keygen -t ed25519 -N 'correct horse'`: aes256-ctr, bcrypt with 16
// rounds.
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

    // The public key is readable without the passphrase.
    const want = try ssh.parseKeyText(ssh.ed25519, encrypted_public);
    try testing.expectEqual(want, f.public_key);

    try testing.expectError(error.WrongPassphrase, f.decrypt("wrong"));
    try testing.expectError(error.WrongPassphrase, f.decrypt(""));
    const kp = try f.decrypt("correct horse");
    try testing.expectEqual(want, kp.public_key.toBytes());

    // The key signs as its public key says.
    const sig = try kp.sign("data", null);
    try sig.verify("data", try .fromBytes(want));
}

test "other files are rejected" {
    try testing.expectError(error.Malformed, PrivateKeyFile.parse(testing.allocator, "ssh-ed25519 " ++ plain_public));
    try testing.expectError(error.Malformed, PrivateKeyFile.parse(testing.allocator, begin_line ++ "\nnot base64\n" ++ end_line));

    // A file holding an RSA key, with the private section left empty.
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

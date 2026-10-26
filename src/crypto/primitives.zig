//! C-ABI wrappers around `std.crypto` for picotls_backend.c.
const std = @import("std");
const crypto = std.crypto;

/// Set by `crypto.init`.
pub var io: ?std.Io = null;

// Must match the sizes in picotls_backend.c. Software AES, used when the
// target CPU has no AES instructions, needs about 4 KiB of key schedule.
const aes_state_size = 4096;
const hash_state_size = 128;
const state_align = 16;
const mlkem_pk_len = 1184;
const mlkem_sk_len = 2400;
const mlkem_ct_len = 1088;

const MLKem768 = crypto.kem.ml_kem.MLKem768;
comptime {
    std.debug.assert(MLKem768.PublicKey.encoded_length == mlkem_pk_len);
    std.debug.assert(MLKem768.SecretKey.encoded_length == mlkem_sk_len);
    std.debug.assert(MLKem768.ciphertext_length == mlkem_ct_len);
    std.debug.assert(MLKem768.shared_length == 32);
}

fn getIo() std.Io {
    return io orelse @panic("crypto.init was not called before using TLS");
}

fn slice(ptr: ?[*]const u8, len: usize) []const u8 {
    return if (ptr) |p| p[0..len] else &.{};
}

// --- Random ---------------------------------------------------------------

pub fn random(buf: []u8) void {
    getIo().random(buf);
}

export fn tx_random_bytes(buf: ?*anyopaque, len: usize) void {
    if (len == 0) return;
    const p: [*]u8 = @ptrCast(buf.?);
    random(p[0..len]);
}

// --- AEAD -----------------------------------------------------------------

const aead_kinds = [_]type{
    crypto.aead.aes_gcm.Aes128Gcm,
    crypto.aead.aes_gcm.Aes256Gcm,
    crypto.aead.chacha_poly.ChaCha20Poly1305,
};

/// Encrypt `mlen` bytes of `m` into `c`, followed by the 16-byte tag.
/// `c` may equal `m`.
export fn tx_aead_seal(
    kind: c_int,
    key: [*]const u8,
    nonce: *const [12]u8,
    ad: ?[*]const u8,
    adlen: usize,
    m: ?[*]const u8,
    mlen: usize,
    c: [*]u8,
) void {
    switch (kind) {
        inline 0...aead_kinds.len - 1 => |k| {
            const A = aead_kinds[k];
            A.encrypt(c[0..mlen], c[mlen..][0..A.tag_length], slice(m, mlen), slice(ad, adlen), nonce.*, key[0..A.key_length].*);
        },
        else => unreachable,
    }
}

/// Decrypt `clen` bytes (ciphertext followed by the tag) into `m`.
/// Returns 0 if the tag verifies, -1 otherwise. `m` may equal `c`.
export fn tx_aead_open(
    kind: c_int,
    key: [*]const u8,
    nonce: *const [12]u8,
    ad: ?[*]const u8,
    adlen: usize,
    c: [*]const u8,
    clen: usize,
    m: [*]u8,
) c_int {
    switch (kind) {
        inline 0...aead_kinds.len - 1 => |k| {
            const A = aead_kinds[k];
            if (clen < A.tag_length) return -1;
            const n = clen - A.tag_length;
            A.decrypt(m[0..n], c[0..n], c[n..][0..A.tag_length].*, slice(ad, adlen), nonce.*, key[0..A.key_length].*) catch return -1;
            return 0;
        },
        else => unreachable,
    }
}

// --- AES-ECB (QUIC header protection) --------------------------------------

fn AesState(comptime bits: u16, comptime enc: bool) type {
    const Aes = if (bits == 128) crypto.core.aes.Aes128 else crypto.core.aes.Aes256;
    return if (enc) @TypeOf(Aes.initEnc(undefined)) else @TypeOf(Aes.initDec(undefined));
}

comptime {
    for ([_]u16{ 128, 256 }) |bits| for ([_]bool{ true, false }) |enc| {
        const S = AesState(bits, enc);
        std.debug.assert(@sizeOf(S) <= aes_state_size and @alignOf(S) <= state_align);
    };
}

export fn tx_aes_ecb_init(state: *align(state_align) [aes_state_size]u8, key: [*]const u8, key_bits: c_int, is_enc: c_int) void {
    switch (key_bits) {
        inline 128, 256 => |bits| {
            const Aes = if (bits == 128) crypto.core.aes.Aes128 else crypto.core.aes.Aes256;
            const k = key[0 .. bits / 8].*;
            if (is_enc != 0) {
                @as(*AesState(bits, true), @ptrCast(state)).* = Aes.initEnc(k);
            } else {
                @as(*AesState(bits, false), @ptrCast(state)).* = Aes.initDec(k);
            }
        },
        else => unreachable,
    }
}

/// Encrypt or decrypt `len` bytes; `len` must be a multiple of 16.
export fn tx_aes_ecb(state: *align(state_align) const [aes_state_size]u8, key_bits: c_int, is_enc: c_int, out: [*]u8, in: [*]const u8, len: usize) void {
    std.debug.assert(len % 16 == 0);
    switch (key_bits) {
        inline 128, 256 => |bits| {
            var i: usize = 0;
            if (is_enc != 0) {
                const s: *const AesState(bits, true) = @ptrCast(state);
                while (i < len) : (i += 16) s.encrypt(out[i..][0..16], in[i..][0..16]);
            } else {
                const s: *const AesState(bits, false) = @ptrCast(state);
                while (i < len) : (i += 16) s.decrypt(out[i..][0..16], in[i..][0..16]);
            }
        },
        else => unreachable,
    }
}

// --- ChaCha20 (QUIC header protection) ------------------------------------

/// XOR `len` bytes with the ChaCha20 keystream, starting `offset` bytes
/// into the stream for (`key`, `counter`, `nonce`). `out` may equal `in`.
export fn tx_chacha20_xor(out: [*]u8, in: [*]const u8, len: usize, key: *const [32]u8, counter: u32, nonce: *const [12]u8, offset: u64) void {
    const C = crypto.stream.chacha.ChaCha20IETF;
    var pos = offset;
    var i: usize = 0;
    if (pos % 64 != 0 and len > 0) {
        var ks: [64]u8 = undefined;
        C.stream(&ks, counter +% @as(u32, @truncate(pos / 64)), key.*, nonce.*);
        const skip: usize = @intCast(pos % 64);
        const n = @min(64 - skip, len);
        for (0..n) |j| out[j] = in[j] ^ ks[skip + j];
        i = n;
        pos += n;
    }
    if (i < len) C.xor(out[i..len], in[i..len], counter +% @as(u32, @truncate(pos / 64)), key.*, nonce.*);
}

// --- SHA-256 ----------------------------------------------------------------

const Sha256 = crypto.hash.sha2.Sha256;
comptime {
    std.debug.assert(@sizeOf(Sha256) <= hash_state_size and @alignOf(Sha256) <= state_align);
}

export fn tx_sha256_init(state: *align(state_align) [hash_state_size]u8) void {
    @as(*Sha256, @ptrCast(state)).* = .init(.{});
}

export fn tx_sha256_update(state: *align(state_align) [hash_state_size]u8, data: ?[*]const u8, len: usize) void {
    @as(*Sha256, @ptrCast(state)).update(slice(data, len));
}

export fn tx_sha256_final(state: *align(state_align) [hash_state_size]u8, out: *[32]u8) void {
    @as(*Sha256, @ptrCast(state)).final(out);
}

// --- X25519 and ML-KEM-768 ---------------------------------------------------

const X25519 = crypto.dh.X25519;

export fn tx_x25519_keypair(priv: *[32]u8, public: *[32]u8) void {
    const kp = X25519.KeyPair.generate(getIo());
    priv.* = kp.secret_key;
    public.* = kp.public_key;
}

/// Returns -1 if the result is the identity element (an all-zero secret).
export fn tx_x25519_dh(out: *[32]u8, priv: *const [32]u8, peer: *const [32]u8) c_int {
    out.* = X25519.scalarmult(priv.*, peer.*) catch return -1;
    return 0;
}

export fn tx_mlkem768_keypair(pk: *[mlkem_pk_len]u8, sk: *[mlkem_sk_len]u8) void {
    const kp = MLKem768.KeyPair.generate(getIo());
    pk.* = kp.public_key.toBytes();
    sk.* = kp.secret_key.toBytes();
}

export fn tx_mlkem768_encaps(pk: *const [mlkem_pk_len]u8, ct: *[mlkem_ct_len]u8, ss: *[32]u8) c_int {
    const public = MLKem768.PublicKey.fromBytes(pk) catch return -1;
    const es = public.encaps(getIo());
    ct.* = es.ciphertext;
    ss.* = es.shared_secret;
    return 0;
}

export fn tx_mlkem768_decaps(sk: *const [mlkem_sk_len]u8, ct: *const [mlkem_ct_len]u8, ss: *[32]u8) c_int {
    const secret = MLKem768.SecretKey.fromBytes(sk) catch return -1;
    ss.* = secret.decaps(ct) catch return -1;
    return 0;
}

// --- Ed25519 ------------------------------------------------------------------

const Ed25519 = crypto.sign.Ed25519;

/// Sign `msg` with an Ed25519 secret key (the 64-byte seed-and-public-key
/// form). Returns 0 on success.
export fn tx_ed25519_sign(secret_key: *const [64]u8, msg: [*]const u8, len: usize, out: *[64]u8) c_int {
    const sk = Ed25519.SecretKey.fromBytes(secret_key.*) catch return -1;
    const kp = Ed25519.KeyPair.fromSecretKey(sk) catch return -1;
    const sig = kp.sign(msg[0..len], null) catch return -1;
    out.* = sig.toBytes();
    return 0;
}

/// Returns 0 if `sig` is a valid signature of `msg` by `public_key`.
export fn tx_ed25519_verify(public_key: *const [32]u8, msg: [*]const u8, len: usize, sig: *const [64]u8) c_int {
    const pk = Ed25519.PublicKey.fromBytes(public_key.*) catch return -1;
    Ed25519.Signature.fromBytes(sig.*).verify(msg[0..len], pk) catch return -1;
    return 0;
}

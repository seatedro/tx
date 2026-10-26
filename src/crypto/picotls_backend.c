/*
 * A picotls crypto backend on Zig's std.crypto.
 *
 * picotls's algorithm structs contain C bitfields, which Zig can't express,
 * so they are defined here; every primitive is a call into primitives.zig.
 * This file only adapts picotls's calling conventions (nonce construction,
 * context lifetimes, key-share layout) and implements no cryptography.
 */
#include <tx/picotls_backend.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define TX_AES_STATE_SIZE 4096 /* fits software AES; see primitives.zig */
#define TX_HASH_STATE_SIZE 128
#define TX_MLKEM768_PK_LEN 1184
#define TX_MLKEM768_SK_LEN 2400
#define TX_MLKEM768_CT_LEN 1088

typedef struct {
  _Alignas(16) uint8_t b[TX_AES_STATE_SIZE];
} tx_aes_state;
typedef struct {
  _Alignas(16) uint8_t b[TX_HASH_STATE_SIZE];
} tx_hash_state;

/* primitives.zig */
void tx_aead_seal(int kind, const uint8_t *key, const uint8_t nonce[12], const void *ad,
                  size_t adlen, const void *m, size_t mlen, void *c);
int tx_aead_open(int kind, const uint8_t *key, const uint8_t nonce[12], const void *ad,
                 size_t adlen, const void *c, size_t clen, void *m);
void tx_aes_ecb_init(tx_aes_state *st, const void *key, int key_bits, int is_enc);
void tx_aes_ecb(const tx_aes_state *st, int key_bits, int is_enc, void *out, const void *in,
                size_t len);
void tx_chacha20_xor(void *out, const void *in, size_t len, const uint8_t key[32], uint32_t counter,
                     const uint8_t nonce[12], uint64_t offset);
void tx_sha256_init(tx_hash_state *st);
void tx_sha256_update(tx_hash_state *st, const void *data, size_t len);
void tx_sha256_final(tx_hash_state *st, void *out);
void tx_x25519_keypair(uint8_t priv[32], uint8_t pub[32]);
int tx_x25519_dh(uint8_t out[32], const uint8_t priv[32], const uint8_t peer[32]);
void tx_mlkem768_keypair(uint8_t *pk, uint8_t *sk);
int tx_mlkem768_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
int tx_mlkem768_decaps(const uint8_t *sk, const uint8_t *ct, uint8_t ss[32]);
int tx_ed25519_sign(const uint8_t secret_key[64], const uint8_t *msg, size_t len, uint8_t sig[64]);
int tx_ed25519_verify(const uint8_t public_key[32], const uint8_t *msg, size_t len,
                      const uint8_t sig[64]);

/* --- AES-ECB ---------------------------------------------------------------- */

struct tx_aes_ecb_ctx {
  ptls_cipher_context_t super;
  int key_bits, is_enc;
  tx_aes_state st;
};

static void aes_ecb_dispose(ptls_cipher_context_t *_ctx) {
  struct tx_aes_ecb_ctx *ctx = (struct tx_aes_ecb_ctx *)_ctx;
  ptls_clear_memory(&ctx->st, sizeof(ctx->st));
}

/* ECB takes no IV, but ngtcp2's picotls adapter calls ptls_cipher_init on
   ECB contexts, as picotls's OpenSSL backend allows. */
static void aes_ecb_init(ptls_cipher_context_t *ctx, const void *iv) { (void)ctx, (void)iv; }

static void aes_ecb_transform(ptls_cipher_context_t *_ctx, void *out, const void *in, size_t len) {
  struct tx_aes_ecb_ctx *ctx = (struct tx_aes_ecb_ctx *)_ctx;
  tx_aes_ecb(&ctx->st, ctx->key_bits, ctx->is_enc, out, in, len);
}

static int aes_ecb_setup(ptls_cipher_context_t *_ctx, int is_enc, const void *key, int key_bits) {
  struct tx_aes_ecb_ctx *ctx = (struct tx_aes_ecb_ctx *)_ctx;
  ctx->super.do_dispose = aes_ecb_dispose;
  ctx->super.do_init = aes_ecb_init;
  ctx->super.do_transform = aes_ecb_transform;
  ctx->key_bits = key_bits;
  ctx->is_enc = is_enc;
  tx_aes_ecb_init(&ctx->st, key, key_bits, is_enc);
  return 0;
}

static int aes128ecb_setup(ptls_cipher_context_t *ctx, int is_enc, const void *key) {
  return aes_ecb_setup(ctx, is_enc, key, 128);
}

static int aes256ecb_setup(ptls_cipher_context_t *ctx, int is_enc, const void *key) {
  return aes_ecb_setup(ctx, is_enc, key, 256);
}

ptls_cipher_algorithm_t tx_aes128ecb = {
    "AES128-ECB",    PTLS_AES128_KEY_SIZE,          PTLS_AES_BLOCK_SIZE,
    0 /* iv size */, sizeof(struct tx_aes_ecb_ctx), aes128ecb_setup};
ptls_cipher_algorithm_t tx_aes256ecb = {
    "AES256-ECB",    PTLS_AES256_KEY_SIZE,          PTLS_AES_BLOCK_SIZE,
    0 /* iv size */, sizeof(struct tx_aes_ecb_ctx), aes256ecb_setup};

/* --- ChaCha20 ----------------------------------------------------------------- */

struct tx_chacha20_ctx {
  ptls_cipher_context_t super;
  uint8_t key[32];
  uint32_t counter;
  uint8_t nonce[12];
  uint64_t offset;
};

static void chacha20_dispose(ptls_cipher_context_t *_ctx) {
  struct tx_chacha20_ctx *ctx = (struct tx_chacha20_ctx *)_ctx;
  ptls_clear_memory(ctx->key, sizeof(ctx->key));
}

/* The 16-byte IV is a little-endian 32-bit block counter, then the nonce. */
static void chacha20_init(ptls_cipher_context_t *_ctx, const void *_iv) {
  struct tx_chacha20_ctx *ctx = (struct tx_chacha20_ctx *)_ctx;
  const uint8_t *iv = _iv;
  ctx->counter =
      (uint32_t)iv[0] | (uint32_t)iv[1] << 8 | (uint32_t)iv[2] << 16 | (uint32_t)iv[3] << 24;
  memcpy(ctx->nonce, iv + 4, sizeof(ctx->nonce));
  ctx->offset = 0;
}

static void chacha20_transform(ptls_cipher_context_t *_ctx, void *out, const void *in, size_t len) {
  struct tx_chacha20_ctx *ctx = (struct tx_chacha20_ctx *)_ctx;
  tx_chacha20_xor(out, in, len, ctx->key, ctx->counter, ctx->nonce, ctx->offset);
  ctx->offset += len;
}

static int chacha20_setup(ptls_cipher_context_t *_ctx, int is_enc, const void *key) {
  (void)is_enc;
  struct tx_chacha20_ctx *ctx = (struct tx_chacha20_ctx *)_ctx;
  ctx->super.do_dispose = chacha20_dispose;
  ctx->super.do_init = chacha20_init;
  ctx->super.do_transform = chacha20_transform;
  memcpy(ctx->key, key, sizeof(ctx->key));
  ctx->counter = 0;
  memset(ctx->nonce, 0, sizeof(ctx->nonce));
  ctx->offset = 0;
  return 0;
}

ptls_cipher_algorithm_t tx_chacha20 = {"CHACHA20",
                                       PTLS_CHACHA20_KEY_SIZE,
                                       1 /* block size */,
                                       PTLS_CHACHA20_IV_SIZE,
                                       sizeof(struct tx_chacha20_ctx),
                                       chacha20_setup};

/* --- AEAD ----------------------------------------------------------------- */

enum { TX_AES128GCM = 0, TX_AES256GCM = 1, TX_CHACHA20POLY1305 = 2 };

struct tx_aead_ctx {
  ptls_aead_context_t super;
  int kind;
  uint8_t key[32];
  uint8_t static_iv[PTLS_MAX_IV_SIZE];
};

static void aead_dispose(ptls_aead_context_t *_ctx) {
  struct tx_aead_ctx *ctx = (struct tx_aead_ctx *)_ctx;
  ptls_clear_memory(ctx->key, sizeof(ctx->key));
  ptls_clear_memory(ctx->static_iv, sizeof(ctx->static_iv));
}

static void aead_get_iv(ptls_aead_context_t *_ctx, void *iv) {
  struct tx_aead_ctx *ctx = (struct tx_aead_ctx *)_ctx;
  memcpy(iv, ctx->static_iv, ctx->super.algo->iv_size);
}

static void aead_set_iv(ptls_aead_context_t *_ctx, const void *iv) {
  struct tx_aead_ctx *ctx = (struct tx_aead_ctx *)_ctx;
  memcpy(ctx->static_iv, iv, ctx->super.algo->iv_size);
}

/*
 * Gather the input vectors into `output`, then seal in place. The nonce is
 * the static IV XORed with the record sequence number (ptls_aead__build_iv),
 * exactly as picotls's other backends do.
 */
static void aead_encrypt_v(ptls_aead_context_t *_ctx, void *_output, ptls_iovec_t *input,
                           size_t incnt, uint64_t seq, const void *aad, size_t aadlen) {
  struct tx_aead_ctx *ctx = (struct tx_aead_ctx *)_ctx;
  uint8_t *output = _output, iv[PTLS_MAX_IV_SIZE];
  size_t off = 0;
  for (size_t i = 0; i < incnt; ++i) {
    if (input[i].len != 0)
      memmove(output + off, input[i].base, input[i].len);
    off += input[i].len;
  }
  ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);
  tx_aead_seal(ctx->kind, ctx->key, iv, aad, aadlen, output, off, output);
  ptls_clear_memory(iv, sizeof(iv));
}

static size_t aead_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen,
                           uint64_t seq, const void *aad, size_t aadlen) {
  struct tx_aead_ctx *ctx = (struct tx_aead_ctx *)_ctx;
  uint8_t iv[PTLS_MAX_IV_SIZE];
  size_t tag_size = ctx->super.algo->tag_size;
  if (inlen < tag_size)
    return SIZE_MAX;
  ptls_aead__build_iv(ctx->super.algo, iv, ctx->static_iv, seq);
  int ret = tx_aead_open(ctx->kind, ctx->key, iv, aad, aadlen, input, inlen, output);
  ptls_clear_memory(iv, sizeof(iv));
  return ret == 0 ? inlen - tag_size : SIZE_MAX;
}

static int aead_setup(ptls_aead_context_t *_ctx, const void *key, const void *iv, int kind) {
  struct tx_aead_ctx *ctx = (struct tx_aead_ctx *)_ctx;
  ctx->super.dispose_crypto = aead_dispose;
  ctx->super.do_get_iv = aead_get_iv;
  ctx->super.do_set_iv = aead_set_iv;
  ctx->super.do_encrypt_init = NULL; /* deprecated streaming interface */
  ctx->super.do_encrypt_update = NULL;
  ctx->super.do_encrypt_final = NULL;
  ctx->super.do_encrypt = ptls_aead__do_encrypt;
  ctx->super.do_encrypt_v = aead_encrypt_v;
  ctx->super.do_decrypt = aead_decrypt;
  ctx->kind = kind;
  memcpy(ctx->key, key, ctx->super.algo->key_size);
  if (iv != NULL) {
    memcpy(ctx->static_iv, iv, ctx->super.algo->iv_size);
  } else {
    memset(ctx->static_iv, 0, sizeof(ctx->static_iv));
  }
  return 0;
}

static int aes128gcm_setup(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv) {
  (void)is_enc;
  return aead_setup(ctx, key, iv, TX_AES128GCM);
}

static int aes256gcm_setup(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv) {
  (void)is_enc;
  return aead_setup(ctx, key, iv, TX_AES256GCM);
}

static int chacha20poly1305_setup(ptls_aead_context_t *ctx, int is_enc, const void *key,
                                  const void *iv) {
  (void)is_enc;
  return aead_setup(ctx, key, iv, TX_CHACHA20POLY1305);
}

ptls_aead_algorithm_t tx_aes128gcm = {
    .name = "AES128-GCM",
    .confidentiality_limit = PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
    .integrity_limit = PTLS_AESGCM_INTEGRITY_LIMIT,
    .ctr_cipher = NULL,
    .ecb_cipher = &tx_aes128ecb,
    .key_size = PTLS_AES128_KEY_SIZE,
    .iv_size = PTLS_AESGCM_IV_SIZE,
    .tag_size = PTLS_AESGCM_TAG_SIZE,
    .tls12 = {PTLS_TLS12_AESGCM_FIXED_IV_SIZE, PTLS_TLS12_AESGCM_RECORD_IV_SIZE},
    .context_size = sizeof(struct tx_aead_ctx),
    .setup_crypto = aes128gcm_setup,
};

ptls_aead_algorithm_t tx_aes256gcm = {
    .name = "AES256-GCM",
    .confidentiality_limit = PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
    .integrity_limit = PTLS_AESGCM_INTEGRITY_LIMIT,
    .ctr_cipher = NULL,
    .ecb_cipher = &tx_aes256ecb,
    .key_size = PTLS_AES256_KEY_SIZE,
    .iv_size = PTLS_AESGCM_IV_SIZE,
    .tag_size = PTLS_AESGCM_TAG_SIZE,
    .tls12 = {PTLS_TLS12_AESGCM_FIXED_IV_SIZE, PTLS_TLS12_AESGCM_RECORD_IV_SIZE},
    .context_size = sizeof(struct tx_aead_ctx),
    .setup_crypto = aes256gcm_setup,
};

ptls_aead_algorithm_t tx_chacha20poly1305 = {
    .name = "CHACHA20-POLY1305",
    .confidentiality_limit = PTLS_CHACHA20POLY1305_CONFIDENTIALITY_LIMIT,
    .integrity_limit = PTLS_CHACHA20POLY1305_INTEGRITY_LIMIT,
    .ctr_cipher = &tx_chacha20,
    .ecb_cipher = NULL,
    .key_size = PTLS_CHACHA20_KEY_SIZE,
    .iv_size = PTLS_CHACHA20POLY1305_IV_SIZE,
    .tag_size = PTLS_CHACHA20POLY1305_TAG_SIZE,
    .tls12 = {PTLS_TLS12_CHACHAPOLY_FIXED_IV_SIZE, PTLS_TLS12_CHACHAPOLY_RECORD_IV_SIZE},
    .context_size = sizeof(struct tx_aead_ctx),
    .setup_crypto = chacha20poly1305_setup,
};

/* --- SHA-256 -------------------------------------------------------------- */

ptls_define_hash(tx_sha256_impl, tx_hash_state, tx_sha256_init, tx_sha256_update, tx_sha256_final);

ptls_hash_algorithm_t tx_sha256 = {"sha256", PTLS_SHA256_BLOCK_SIZE, PTLS_SHA256_DIGEST_SIZE,
                                   tx_sha256_impl_create, PTLS_ZERO_DIGEST_SHA256};

ptls_cipher_suite_t tx_aes128gcmsha256 = {.id = PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
                                          .name = PTLS_CIPHER_SUITE_NAME_AES_128_GCM_SHA256,
                                          .aead = &tx_aes128gcm,
                                          .hash = &tx_sha256};
ptls_cipher_suite_t tx_chacha20poly1305sha256 = {
    .id = PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
    .name = PTLS_CIPHER_SUITE_NAME_CHACHA20_POLY1305_SHA256,
    .aead = &tx_chacha20poly1305,
    .hash = &tx_sha256};

/* --- Key exchange ------------------------------------------------------------ */

/*
 * One context type serves both groups. For X25519MLKEM768 the client's key
 * share is the ML-KEM-768 public key followed by the X25519 public key, the
 * server's is the ML-KEM ciphertext followed by its X25519 public key, and
 * the shared secret is the ML-KEM secret followed by the X25519 secret
 * (draft-ietf-tls-ecdhe-mlkem: ML-KEM comes first for X25519MLKEM768).
 */
struct tx_kx_ctx {
  ptls_key_exchange_context_t super;
  int hybrid;
  uint8_t x_priv[32];
  uint8_t mlkem_sk[TX_MLKEM768_SK_LEN];
  uint8_t pub[TX_MLKEM768_PK_LEN + 32];
};

int tx_mlkem_exchanges = 0;

static int kx_secret(ptls_iovec_t *secret, size_t len) {
  if ((secret->base = malloc(len)) == NULL)
    return PTLS_ERROR_NO_MEMORY;
  secret->len = len;
  return 0;
}

static void kx_free_secret(ptls_iovec_t *secret) {
  ptls_clear_memory(secret->base, secret->len);
  free(secret->base);
  *secret = ptls_iovec_init(NULL, 0);
}

static int kx_on_exchange(ptls_key_exchange_context_t **_ctx, int release, ptls_iovec_t *secret,
                          ptls_iovec_t peerkey) {
  struct tx_kx_ctx *ctx = (struct tx_kx_ctx *)*_ctx;
  int ret = 0;
  if (secret == NULL)
    goto Exit;

  if (ctx->hybrid) {
    if (peerkey.len != TX_MLKEM768_CT_LEN + 32) {
      ret = PTLS_ALERT_DECRYPT_ERROR;
      goto Exit;
    }
    if ((ret = kx_secret(secret, 64)) != 0)
      goto Exit;
    if (tx_mlkem768_decaps(ctx->mlkem_sk, peerkey.base, secret->base) != 0 ||
        tx_x25519_dh(secret->base + 32, ctx->x_priv, peerkey.base + TX_MLKEM768_CT_LEN) != 0) {
      kx_free_secret(secret);
      ret = PTLS_ERROR_INCOMPATIBLE_KEY;
      goto Exit;
    }
    ++tx_mlkem_exchanges;
  } else {
    if (peerkey.len != 32) {
      ret = PTLS_ALERT_DECRYPT_ERROR;
      goto Exit;
    }
    if ((ret = kx_secret(secret, 32)) != 0)
      goto Exit;
    if (tx_x25519_dh(secret->base, ctx->x_priv, peerkey.base) != 0) {
      kx_free_secret(secret);
      ret = PTLS_ERROR_INCOMPATIBLE_KEY;
    }
  }

Exit:
  if (release) {
    ptls_clear_memory(ctx, sizeof(*ctx));
    free(ctx);
    *_ctx = NULL;
  }
  return ret;
}

static int kx_create(ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **_ctx) {
  struct tx_kx_ctx *ctx = malloc(sizeof(*ctx));
  if (ctx == NULL)
    return PTLS_ERROR_NO_MEMORY;
  ctx->hybrid = algo->id == PTLS_GROUP_X25519MLKEM768;
  size_t publen;
  if (ctx->hybrid) {
    tx_mlkem768_keypair(ctx->pub, ctx->mlkem_sk);
    tx_x25519_keypair(ctx->x_priv, ctx->pub + TX_MLKEM768_PK_LEN);
    publen = TX_MLKEM768_PK_LEN + 32;
  } else {
    tx_x25519_keypair(ctx->x_priv, ctx->pub);
    publen = 32;
  }
  ctx->super =
      (ptls_key_exchange_context_t){algo, ptls_iovec_init(ctx->pub, publen), kx_on_exchange};
  *_ctx = &ctx->super;
  return 0;
}

/* Server side: answer the client's key share in one step. */
static int kx_exchange(ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey,
                       ptls_iovec_t *secret, ptls_iovec_t peerkey) {
  int hybrid = algo->id == PTLS_GROUP_X25519MLKEM768;
  size_t want = hybrid ? TX_MLKEM768_PK_LEN + 32 : 32;
  size_t publen = hybrid ? TX_MLKEM768_CT_LEN + 32 : 32;
  uint8_t x_priv[32], *pub = NULL;
  int ret;

  *secret = ptls_iovec_init(NULL, 0);
  if (peerkey.len != want)
    return PTLS_ALERT_DECRYPT_ERROR;
  if ((pub = malloc(publen)) == NULL)
    return PTLS_ERROR_NO_MEMORY;
  if ((ret = kx_secret(secret, hybrid ? 64 : 32)) != 0)
    goto Exit;

  if (hybrid) {
    tx_x25519_keypair(x_priv, pub + TX_MLKEM768_CT_LEN);
    if (tx_mlkem768_encaps(peerkey.base, pub, secret->base) != 0 ||
        tx_x25519_dh(secret->base + 32, x_priv, peerkey.base + TX_MLKEM768_PK_LEN) != 0) {
      ret = PTLS_ERROR_INCOMPATIBLE_KEY;
      goto Exit;
    }
    ++tx_mlkem_exchanges;
  } else {
    tx_x25519_keypair(x_priv, pub);
    if (tx_x25519_dh(secret->base, x_priv, peerkey.base) != 0) {
      ret = PTLS_ERROR_INCOMPATIBLE_KEY;
      goto Exit;
    }
  }
  *pubkey = ptls_iovec_init(pub, publen);
  pub = NULL;

Exit:
  ptls_clear_memory(x_priv, sizeof(x_priv));
  if (ret != 0 && secret->base != NULL)
    kx_free_secret(secret);
  free(pub);
  return ret;
}

ptls_key_exchange_algorithm_t tx_x25519 = {.id = PTLS_GROUP_X25519,
                                           .name = PTLS_GROUP_NAME_X25519,
                                           .create = kx_create,
                                           .exchange = kx_exchange};
ptls_key_exchange_algorithm_t tx_x25519mlkem768 = {.id = PTLS_GROUP_X25519MLKEM768,
                                                   .name = PTLS_GROUP_NAME_X25519MLKEM768,
                                                   .create = kx_create,
                                                   .exchange = kx_exchange};

/* --- Ed25519 raw public keys ---------------------------------------------- */

static const uint8_t spki_prefix[12] = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
                                        0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
static const uint16_t ed25519_algos[] = {PTLS_SIGNATURE_ED25519, UINT16_MAX};

void tx_ed25519_spki(uint8_t out[TX_ED25519_SPKI_LEN], const uint8_t public_key[32]) {
  memcpy(out, spki_prefix, sizeof(spki_prefix));
  memcpy(out + sizeof(spki_prefix), public_key, 32);
}

static int ed25519_sign(ptls_sign_certificate_t *_self, ptls_t *tls, ptls_async_job_t **async,
                        uint16_t *selected, ptls_buffer_t *out, ptls_iovec_t input,
                        const uint16_t *algos, size_t num_algos) {
  (void)tls, (void)async;
  tx_ed25519_signer *self = (tx_ed25519_signer *)_self;
  size_t i;
  for (i = 0; i < num_algos; ++i) {
    if (algos[i] == PTLS_SIGNATURE_ED25519)
      break;
  }
  if (i == num_algos)
    return PTLS_ALERT_HANDSHAKE_FAILURE;
  int ret = ptls_buffer_reserve(out, 64);
  if (ret != 0)
    return ret;
  if (tx_ed25519_sign(self->secret_key, input.base, input.len, out->base + out->off) != 0) {
    return PTLS_ERROR_LIBRARY;
  }
  out->off += 64;
  *selected = PTLS_SIGNATURE_ED25519;
  return 0;
}

void tx_ed25519_signer_init(tx_ed25519_signer *signer, const uint8_t secret_key[64]) {
  signer->super.cb = ed25519_sign;
  memcpy(signer->secret_key, secret_key, sizeof(signer->secret_key));
}

void tx_ed25519_signer_dispose(tx_ed25519_signer *signer) {
  ptls_clear_memory(signer->secret_key, sizeof(signer->secret_key));
}

static int ed25519_verify_sign(void *pinned, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sig) {
  if (data.base == NULL)
    return 0; /* cleanup call; nothing to free */
  if (algo != PTLS_SIGNATURE_ED25519 || sig.len != 64) {
    return PTLS_ALERT_DECRYPT_ERROR;
  }
  return tx_ed25519_verify(pinned, data.base, data.len, sig.base) == 0 ? 0
                                                                       : PTLS_ALERT_DECRYPT_ERROR;
}

static int ed25519_verify_cert(ptls_verify_certificate_t *_self, ptls_t *tls,
                               const char *server_name,
                               int (**verify_sign)(void *, uint16_t, ptls_iovec_t, ptls_iovec_t),
                               void **verify_data, ptls_iovec_t *certs, size_t num_certs) {
  (void)tls, (void)server_name;
  tx_ed25519_verifier *self = (tx_ed25519_verifier *)_self;
  uint8_t want[TX_ED25519_SPKI_LEN];
  tx_ed25519_spki(want, self->pinned);
  if (num_certs != 1 || certs[0].len != sizeof(want) ||
      !ptls_mem_equal(certs[0].base, want, sizeof(want))) {
    return PTLS_ALERT_BAD_CERTIFICATE;
  }
  *verify_sign = ed25519_verify_sign;
  *verify_data = self->pinned;
  return 0;
}

void tx_ed25519_verifier_init(tx_ed25519_verifier *verifier, const uint8_t pinned[32]) {
  verifier->super.cb = ed25519_verify_cert;
  verifier->super.algos = ed25519_algos;
  memcpy(verifier->pinned, pinned, sizeof(verifier->pinned));
}

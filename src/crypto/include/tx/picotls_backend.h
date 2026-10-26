/*
 * A picotls crypto backend backed by Zig's std.crypto (primitives.zig), and
 * Ed25519 raw public key (RFC 7250) authentication for it.
 */
#ifndef TX_PICOTLS_BACKEND_H
#define TX_PICOTLS_BACKEND_H

#include <picotls.h>

void tx_random_bytes(void *buf, size_t len);

extern ptls_cipher_algorithm_t tx_aes128ecb, tx_aes256ecb, tx_chacha20;
extern ptls_aead_algorithm_t tx_aes128gcm, tx_aes256gcm, tx_chacha20poly1305;
extern ptls_hash_algorithm_t tx_sha256;
extern ptls_cipher_suite_t tx_aes128gcmsha256, tx_chacha20poly1305sha256;
extern ptls_key_exchange_algorithm_t tx_x25519, tx_x25519mlkem768;

/* Number of X25519MLKEM768 key exchanges completed, for tests. */
extern int tx_mlkem_exchanges;

/* --- Ed25519 raw public keys ------------------------------------------- */

/* DER SubjectPublicKeyInfo of an Ed25519 key: what RFC 7250 sends. */
#define TX_ED25519_SPKI_LEN 44
void tx_ed25519_spki(uint8_t out[TX_ED25519_SPKI_LEN], const uint8_t public_key[32]);

/* Signs CertificateVerify. `secret_key` is the 64-byte Ed25519 secret key
   (seed followed by public key). */
typedef struct tx_ed25519_signer {
  ptls_sign_certificate_t super;
  uint8_t secret_key[64];
} tx_ed25519_signer;

void tx_ed25519_signer_init(tx_ed25519_signer *signer, const uint8_t secret_key[64]);
void tx_ed25519_signer_dispose(tx_ed25519_signer *signer);

/* Accepts only the pinned Ed25519 key, and verifies CertificateVerify. */
typedef struct tx_ed25519_verifier {
  ptls_verify_certificate_t super;
  uint8_t pinned[32];
} tx_ed25519_verifier;

void tx_ed25519_verifier_init(tx_ed25519_verifier *verifier, const uint8_t pinned[32]);

#endif

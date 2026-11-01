// picotls algorithms and certificate callbacks built on Zig's std.crypto, through the C
// exports in src/crypto/primitives.zig.
#ifndef TX_PICOTLS_BACKEND_H
#define TX_PICOTLS_BACKEND_H

#include <picotls.h>

// Fills buf with random bytes from the Io given to crypto.init. Panics if crypto.init has not run.
void tx_random_bytes(void *buf, size_t len);

// tx_aes256gcm and tx_aes256ecb belong to no cipher suite. ngtcp2's picotls glue refers to them
// through picotls/openssl.h.
extern ptls_cipher_algorithm_t tx_aes128ecb, tx_aes256ecb, tx_chacha20;
extern ptls_aead_algorithm_t tx_aes128gcm, tx_aes256gcm, tx_chacha20poly1305;
extern ptls_hash_algorithm_t tx_sha256;
extern ptls_cipher_suite_t tx_aes128gcmsha256, tx_chacha20poly1305sha256;
extern ptls_key_exchange_algorithm_t tx_x25519, tx_x25519mlkem768;

// Number of X25519MLKEM768 shared secrets derived in this process, as client or server. Tests
// read it to see that the hybrid group was used.
extern int tx_mlkem_exchanges;

// Writes the DER SubjectPublicKeyInfo of an Ed25519 public key, the certificate entry of a TLS
// raw public key (RFC 7250).
#define TX_ED25519_SPKI_LEN 44
void tx_ed25519_spki(uint8_t out[TX_ED25519_SPKI_LEN], const uint8_t public_key[32]);

// sign_certificate callback for an Ed25519 identity. secret_key is std.crypto's 64-byte Ed25519
// secret key, the seed followed by the public key. init copies it and dispose zeroes the copy.
typedef struct tx_ed25519_signer {
  ptls_sign_certificate_t super;
  uint8_t secret_key[64];
} tx_ed25519_signer;

void tx_ed25519_signer_init(tx_ed25519_signer *signer, const uint8_t secret_key[64]);
void tx_ed25519_signer_dispose(tx_ed25519_signer *signer);

// verify_certificate callback for a raw Ed25519 public key. It accepts a key listed in keys, or
// any key when accept_any is set. keys is borrowed and must outlive the verifier.
typedef struct tx_ed25519_verifier {
  ptls_verify_certificate_t super;
  const uint8_t (*keys)[32];
  size_t count;
  int accept_any;
  // The key the peer last presented, accepted or refused.
  uint8_t presented[32];
  int has_presented;
} tx_ed25519_verifier;

void tx_ed25519_verifier_init(tx_ed25519_verifier *verifier, const uint8_t (*keys)[32],
                              size_t count, int accept_any);

#endif

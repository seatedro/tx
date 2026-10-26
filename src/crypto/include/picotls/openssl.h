/*
 * Replaces picotls's <picotls/openssl.h> when building ngtcp2's picotls adapter
 * (crypto/picotls/picotls.c), which refers to the OpenSSL backend objects by
 * name. These macros map those names to tx's backend. Nothing else includes
 * this header.
 */
#ifndef TX_PICOTLS_OPENSSL_SHIM_H
#define TX_PICOTLS_OPENSSL_SHIM_H

#include <tx/picotls_backend.h>

#define PTLS_OPENSSL_HAVE_CHACHA20_POLY1305 1

#define ptls_openssl_random_bytes tx_random_bytes
#define ptls_openssl_aes128ecb tx_aes128ecb
#define ptls_openssl_aes256ecb tx_aes256ecb
#define ptls_openssl_chacha20 tx_chacha20
#define ptls_openssl_aes128gcm tx_aes128gcm
#define ptls_openssl_aes256gcm tx_aes256gcm
#define ptls_openssl_chacha20poly1305 tx_chacha20poly1305
#define ptls_openssl_sha256 tx_sha256

#endif

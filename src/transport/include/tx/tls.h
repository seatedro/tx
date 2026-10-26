/*
 * TLS 1.3 for QUIC connections, using picotls with Ed25519 raw public keys
 * (RFC 7250) and tx's crypto backend.
 *
 * The types are opaque because picotls's structs use bitfields, which Zig
 * can't express.
 */
#ifndef TX_TLS_H
#define TX_TLS_H

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

/* ALPN protocol ID of tx connections. */
#define TX_TLS_ALPN "tx/1"

/* Presents `public_key` and signs with `secret_key` (the 64-byte Ed25519
   secret key). `prefer_aes` orders AES-128-GCM ahead of ChaCha20-Poly1305;
   set it when the build has hardware AES. */
typedef struct tx_tls_server tx_tls_server;
tx_tls_server *tx_tls_server_new(const uint8_t secret_key[64], const uint8_t public_key[32],
                                 int prefer_aes);
void tx_tls_server_free(tx_tls_server *server);

/* Accepts a server presenting one of `count` keys, or any key if
   `accept_any` is set. The keys are copied. Use a client for one connection
   at a time: it keeps the key the server presented. */
typedef struct tx_tls_client tx_tls_client;
tx_tls_client *tx_tls_client_new(const uint8_t (*keys)[32], size_t count, int accept_any,
                                 int prefer_aes);
void tx_tls_client_free(tx_tls_client *client);

/* Copies the key the server presented in the last handshake into `out`,
   whether or not it was accepted. Returns 0 if no server has presented one. */
int tx_tls_client_presented_key(const tx_tls_client *client, uint8_t out[32]);

/* TLS state of one QUIC connection. The constructors install it as the
   connection's TLS native handle. `conn_ref` must outlive it. */
typedef struct tx_tls_session tx_tls_session;
tx_tls_session *tx_tls_session_new_server(tx_tls_server *server, ngtcp2_conn *conn,
                                          ngtcp2_crypto_conn_ref *conn_ref);
tx_tls_session *tx_tls_session_new_client(tx_tls_client *client, ngtcp2_conn *conn,
                                          ngtcp2_crypto_conn_ref *conn_ref,
                                          const char *server_name);
void tx_tls_session_free(tx_tls_session *session);

/* Derives `len` bytes from the TLS exporter (RFC 8446 §7.5) with `label` and
   an empty context. Valid once the handshake has completed. Returns 0 on
   success. */
int tx_tls_session_export(tx_tls_session *session, uint8_t *out, size_t len, const char *label);

/* Number of X25519MLKEM768 key exchanges completed, for tests. */
int tx_tls_mlkem_exchanges(void);

#endif

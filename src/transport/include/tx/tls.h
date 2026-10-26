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

/* Accepts only a server presenting `pinned`. */
typedef struct tx_tls_client tx_tls_client;
tx_tls_client *tx_tls_client_new(const uint8_t pinned[32], int prefer_aes);
void tx_tls_client_free(tx_tls_client *client);

/* TLS state of one QUIC connection. The constructors install it as the
   connection's TLS native handle. `conn_ref` must outlive it. */
typedef struct tx_tls_session tx_tls_session;
tx_tls_session *tx_tls_session_new_server(tx_tls_server *server, ngtcp2_conn *conn,
                                          ngtcp2_crypto_conn_ref *conn_ref);
tx_tls_session *tx_tls_session_new_client(tx_tls_client *client, ngtcp2_conn *conn,
                                          ngtcp2_crypto_conn_ref *conn_ref,
                                          const char *server_name);
void tx_tls_session_free(tx_tls_session *session);

/* Number of X25519MLKEM768 key exchanges completed, for tests. */
int tx_tls_mlkem_exchanges(void);

#endif

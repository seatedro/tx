/*
 * TLS 1.3 for tx's QUIC connections: picotls contexts and sessions, set up
 * for Ed25519 raw public keys (RFC 7250) on tx's crypto backend.
 *
 * picotls's structs use C bitfields, so they stay behind these opaque
 * types; quic.zig only sees this header and ngtcp2's.
 */
#ifndef TX_TLS_H
#define TX_TLS_H

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

/* The ALPN protocol id every tx connection negotiates. */
#define TX_TLS_ALPN "tx/1"

/* Server side: presents `public_key` and signs with `secret_key` (the
   64-byte Ed25519 secret key). With `prefer_aes` set, AES-128-GCM is
   preferred over ChaCha20-Poly1305; set it when the build has hardware AES. */
typedef struct tx_tls_server tx_tls_server;
tx_tls_server *tx_tls_server_new(const uint8_t secret_key[64], const uint8_t public_key[32],
                                 int prefer_aes);
void tx_tls_server_free(tx_tls_server *server);

/* Client side: accepts only a server presenting `pinned`. */
typedef struct tx_tls_client tx_tls_client;
tx_tls_client *tx_tls_client_new(const uint8_t pinned[32], int prefer_aes);
void tx_tls_client_free(tx_tls_client *client);

/* The TLS state of one QUIC connection. Creating it installs it as the
   connection's TLS native handle; `conn_ref` must outlive it. */
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

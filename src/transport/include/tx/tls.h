// picotls contexts and per-connection sessions for quic.zig. A server presents an Ed25519 raw
// public key (RFC 7250), and a client checks it against the keys it accepts.

#ifndef TX_TLS_H
#define TX_TLS_H

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#define TX_TLS_ALPN "tx/1"

// prefer_aes lists AES-128-GCM ahead of ChaCha20-Poly1305. The server picks by its own list.

typedef struct tx_tls_server tx_tls_server;
// Copies both keys. Returns NULL when out of memory.
tx_tls_server *tx_tls_server_new(const uint8_t secret_key[64], const uint8_t public_key[32],
                                 int prefer_aes);
void tx_tls_server_free(tx_tls_server *server);

typedef struct tx_tls_client tx_tls_client;
// Copies keys. With accept_any set, the server may present any key.
tx_tls_client *tx_tls_client_new(const uint8_t (*keys)[32], size_t count, int accept_any,
                                 int prefer_aes);
void tx_tls_client_free(tx_tls_client *client);

// Writes the key a server last presented to a session of this client, accepted or not, and
// returns 1. Returns 0 if no server has presented a key.
int tx_tls_client_presented_key(const tx_tls_client *client, uint8_t out[32]);

// A session is the TLS state of one ngtcp2 connection. Creating one installs it as the
// connection's TLS native handle. conn_ref must stay valid until the session is freed.
typedef struct tx_tls_session tx_tls_session;
tx_tls_session *tx_tls_session_new_server(tx_tls_server *server, ngtcp2_conn *conn,
                                          ngtcp2_crypto_conn_ref *conn_ref);
// server_name is sent as SNI when not NULL.
tx_tls_session *tx_tls_session_new_client(tx_tls_client *client, ngtcp2_conn *conn,
                                          ngtcp2_crypto_conn_ref *conn_ref,
                                          const char *server_name);
void tx_tls_session_free(tx_tls_session *session);

// TLS exporter (RFC 8446 section 7.5) with an empty context. Returns 0 on success.
int tx_tls_session_export(tx_tls_session *session, uint8_t *out, size_t len, const char *label);

// X25519MLKEM768 exchanges this process has completed, one per side of each handshake.
int tx_tls_mlkem_exchanges(void);

#endif

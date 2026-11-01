#ifndef TX_TLS_H
#define TX_TLS_H

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#define TX_TLS_ALPN "tx/1"

typedef struct tx_tls_server tx_tls_server;
tx_tls_server *tx_tls_server_new(const uint8_t secret_key[64], const uint8_t public_key[32],
                                 int prefer_aes);
void tx_tls_server_free(tx_tls_server *server);

typedef struct tx_tls_client tx_tls_client;
tx_tls_client *tx_tls_client_new(const uint8_t (*keys)[32], size_t count, int accept_any,
                                 int prefer_aes);
void tx_tls_client_free(tx_tls_client *client);

int tx_tls_client_presented_key(const tx_tls_client *client, uint8_t out[32]);

typedef struct tx_tls_session tx_tls_session;
tx_tls_session *tx_tls_session_new_server(tx_tls_server *server, ngtcp2_conn *conn,
                                          ngtcp2_crypto_conn_ref *conn_ref);
tx_tls_session *tx_tls_session_new_client(tx_tls_client *client, ngtcp2_conn *conn,
                                          ngtcp2_crypto_conn_ref *conn_ref,
                                          const char *server_name);
void tx_tls_session_free(tx_tls_session *session);

int tx_tls_session_export(tx_tls_session *session, uint8_t *out, size_t len, const char *label);

int tx_tls_mlkem_exchanges(void);

#endif

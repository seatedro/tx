#include <tx/tls.h>

#include <ngtcp2/ngtcp2_crypto_picotls.h>
#include <picotls.h>
#include <tx/picotls_backend.h>

#include <stdlib.h>
#include <string.h>

/* Hybrid post-quantum first; plain X25519 for peers that lack it. */
static ptls_key_exchange_algorithm_t *key_exchanges[] = {
  &tx_x25519mlkem768, &tx_x25519, NULL};

/* Without hardware AES, ChaCha20-Poly1305 is the faster suite. */
static ptls_cipher_suite_t *suites_aes_first[] = {
  &tx_aes128gcmsha256, &tx_chacha20poly1305sha256, NULL};
static ptls_cipher_suite_t *suites_chacha_first[] = {
  &tx_chacha20poly1305sha256, &tx_aes128gcmsha256, NULL};

static ptls_iovec_t alpn = {(uint8_t *)TX_TLS_ALPN, sizeof(TX_TLS_ALPN) - 1};

/* Agree on ALPN tx/1, or refuse the handshake. */
static int on_client_hello(ptls_on_client_hello_t *self, ptls_t *tls,
                           ptls_on_client_hello_parameters_t *params) {
  (void)self;
  for (size_t i = 0; i < params->negotiated_protocols.count; ++i) {
    ptls_iovec_t p = params->negotiated_protocols.list[i];
    if (p.len == alpn.len && memcmp(p.base, alpn.base, alpn.len) == 0) {
      return ptls_set_negotiated_protocol(tls, (const char *)alpn.base,
                                          alpn.len);
    }
  }
  return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

static ptls_on_client_hello_t client_hello_cb = {on_client_hello};

struct tx_tls_server {
  ptls_context_t ctx;
  tx_ed25519_signer signer;
  uint8_t spki[TX_ED25519_SPKI_LEN];
  ptls_iovec_t cert;
};

tx_tls_server *tx_tls_server_new(const uint8_t secret_key[64],
                                 const uint8_t public_key[32],
                                 int prefer_aes) {
  tx_tls_server *s = calloc(1, sizeof(*s));
  if (s == NULL) return NULL;
  tx_ed25519_signer_init(&s->signer, secret_key);
  tx_ed25519_spki(s->spki, public_key);
  s->cert = ptls_iovec_init(s->spki, sizeof(s->spki));
  s->ctx.random_bytes = tx_random_bytes;
  s->ctx.get_time = &ptls_get_time;
  s->ctx.key_exchanges = key_exchanges;
  s->ctx.cipher_suites = prefer_aes ? suites_aes_first : suites_chacha_first;
  s->ctx.certificates.list = &s->cert;
  s->ctx.certificates.count = 1;
  s->ctx.sign_certificate = &s->signer.super;
  s->ctx.on_client_hello = &client_hello_cb;
  s->ctx.use_raw_public_keys = 1;
  s->ctx.server_cipher_preference = 1;
  if (ngtcp2_crypto_picotls_configure_server_context(&s->ctx) != 0) {
    tx_tls_server_free(s);
    return NULL;
  }
  return s;
}

void tx_tls_server_free(tx_tls_server *s) {
  if (s == NULL) return;
  tx_ed25519_signer_dispose(&s->signer);
  free(s);
}

struct tx_tls_client {
  ptls_context_t ctx;
  tx_ed25519_verifier verifier;
};

tx_tls_client *tx_tls_client_new(const uint8_t pinned[32], int prefer_aes) {
  tx_tls_client *c = calloc(1, sizeof(*c));
  if (c == NULL) return NULL;
  tx_ed25519_verifier_init(&c->verifier, pinned);
  c->ctx.random_bytes = tx_random_bytes;
  c->ctx.get_time = &ptls_get_time;
  c->ctx.key_exchanges = key_exchanges;
  c->ctx.cipher_suites = prefer_aes ? suites_aes_first : suites_chacha_first;
  c->ctx.verify_certificate = &c->verifier.super;
  c->ctx.use_raw_public_keys = 1;
  if (ngtcp2_crypto_picotls_configure_client_context(&c->ctx) != 0) {
    tx_tls_client_free(c);
    return NULL;
  }
  return c;
}

void tx_tls_client_free(tx_tls_client *c) { free(c); }

struct tx_tls_session {
  ngtcp2_crypto_picotls_ctx cptls;
  /* ngtcp2 puts the QUIC transport parameters extension in slot 0; the
     list is terminated by an entry with type UINT16_MAX. */
  ptls_raw_extension_t extensions[2];
};

static tx_tls_session *session_new(ptls_context_t *ctx, int is_server,
                                   ngtcp2_crypto_conn_ref *conn_ref) {
  tx_tls_session *s = calloc(1, sizeof(*s));
  if (s == NULL) return NULL;
  ngtcp2_crypto_picotls_ctx_init(&s->cptls);
  s->cptls.ptls = is_server ? ptls_server_new(ctx) : ptls_client_new(ctx);
  if (s->cptls.ptls == NULL) {
    free(s);
    return NULL;
  }
  *ptls_get_data_ptr(s->cptls.ptls) = conn_ref;
  s->extensions[0].type = UINT16_MAX;
  s->extensions[1].type = UINT16_MAX;
  s->cptls.handshake_properties.additional_extensions = s->extensions;
  return s;
}

tx_tls_session *tx_tls_session_new_server(tx_tls_server *server,
                                          ngtcp2_conn *conn,
                                          ngtcp2_crypto_conn_ref *conn_ref) {
  tx_tls_session *s = session_new(&server->ctx, 1, conn_ref);
  if (s == NULL) return NULL;
  if (ngtcp2_crypto_picotls_configure_server_session(&s->cptls) != 0) {
    tx_tls_session_free(s);
    return NULL;
  }
  ngtcp2_conn_set_tls_native_handle(conn, &s->cptls);
  return s;
}

tx_tls_session *tx_tls_session_new_client(tx_tls_client *client,
                                          ngtcp2_conn *conn,
                                          ngtcp2_crypto_conn_ref *conn_ref,
                                          const char *server_name) {
  tx_tls_session *s = session_new(&client->ctx, 0, conn_ref);
  if (s == NULL) return NULL;
  s->cptls.handshake_properties.client.negotiated_protocols.list = &alpn;
  s->cptls.handshake_properties.client.negotiated_protocols.count = 1;
  if (ngtcp2_crypto_picotls_configure_client_session(&s->cptls, conn) != 0) {
    tx_tls_session_free(s);
    return NULL;
  }
  if (server_name != NULL) {
    ptls_set_server_name(s->cptls.ptls, server_name, strlen(server_name));
  }
  ngtcp2_conn_set_tls_native_handle(conn, &s->cptls);
  return s;
}

void tx_tls_session_free(tx_tls_session *s) {
  if (s == NULL) return;
  ngtcp2_crypto_picotls_deconfigure_session(&s->cptls);
  if (s->cptls.ptls != NULL) ptls_free(s->cptls.ptls);
  free(s);
}

int tx_tls_mlkem_exchanges(void) { return tx_mlkem_exchanges; }

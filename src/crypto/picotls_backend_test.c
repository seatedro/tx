/*
 * Tests for picotls_backend.c, called from root.zig. Each entry point returns
 * the number of failures and prints the failures.
 *
 * - Known-answer vectors: FIPS-197 AES, GCM spec test case 3, and RFC 9001
 *   appendix A (QUIC Initial key derivation, AES header protection, and the
 *   ChaCha20-Poly1305 short-header packet, which exercises the
 *   IV-XOR-sequence nonce). picotls's minicrypto backend computes each value
 *   too, to show which side is wrong on a mismatch.
 * - In-memory TLS 1.3 handshakes between tx and minicrypto in both directions
 *   with both cipher suites, followed by application data each way.
 * - A TLS 1.3 handshake with cloudflare.com offering only X25519MLKEM768.
 *   Runs when TX_TEST_NETWORK is set.
 */
#include <tx/picotls_backend.h>

#include <picotls/minicrypto.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static size_t unhex(uint8_t *out, const char *hex) {
  size_t n = 0;
  for (; hex[0] && hex[1]; hex += 2) {
    unsigned v;
    sscanf(hex, "%2x", &v);
    out[n++] = (uint8_t)v;
  }
  return n;
}

static void print_hex(const char *label, const uint8_t *p, size_t n) {
  fprintf(stderr, "    %s ", label);
  for (size_t i = 0; i < n; ++i)
    fprintf(stderr, "%02x", p[i]);
  fprintf(stderr, "\n");
}

static int failures = 0;

/* Compare tx's output and minicrypto's output against the expected hex. */
static void check(const char *name, const uint8_t *tx, const uint8_t *mini, const char *want_hex) {
  uint8_t want[256];
  size_t n = unhex(want, want_hex);
  int tx_ok = memcmp(tx, want, n) == 0, mini_ok = memcmp(mini, want, n) == 0;
  if (!tx_ok) {
    fprintf(stderr, "  FAIL %s\n", name);
    ++failures;
    print_hex("want", want, n);
    print_hex("tx  ", tx, n);
    print_hex("mini", mini, n);
    if (mini_ok)
      fprintf(stderr, "    (minicrypto matches the vector)\n");
  }
}

/* --- Known-answer tests ------------------------------------------------------- */

static void ecb(ptls_cipher_algorithm_t *algo, const uint8_t *key, const uint8_t *in, size_t len,
                uint8_t *out) {
  ptls_cipher_context_t *c = ptls_cipher_new(algo, 1, key);
  ptls_cipher_encrypt(c, out, in, len);
  ptls_cipher_free(c);
}

static void kat_aes_ecb(void) {
  uint8_t key[16], pt[16], a[16], b[16];
  unhex(key, "000102030405060708090a0b0c0d0e0f");
  unhex(pt, "00112233445566778899aabbccddeeff");
  ecb(&tx_aes128ecb, key, pt, 16, a);
  ecb(&ptls_minicrypto_aes128ecb, key, pt, 16, b);
  check("FIPS-197 C.1 AES-128", a, b, "69c4e0d86a7b0430d8cdb78070b4c55a");
}

static void seal(ptls_aead_algorithm_t *algo, const uint8_t *key, const uint8_t *iv, uint64_t seq,
                 const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t len, uint8_t *out) {
  ptls_aead_context_t *c = ptls_aead_new_direct(algo, 1, key, iv);
  ptls_aead_encrypt(c, out, pt, len, seq, aad, aadlen);
  ptls_aead_free(c);
}

static int open_ok(ptls_aead_algorithm_t *algo, const uint8_t *key, const uint8_t *iv, uint64_t seq,
                   const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t len, uint8_t *out) {
  ptls_aead_context_t *c = ptls_aead_new_direct(algo, 0, key, iv);
  size_t n = ptls_aead_decrypt(c, out, ct, len, seq, aad, aadlen);
  ptls_aead_free(c);
  return n == len - algo->tag_size;
}

static void kat_gcm(void) {
  uint8_t key[16], iv[12], pt[64], a[80], b[80], back[64];
  unhex(key, "feffe9928665731c6d6a8f9467308308");
  unhex(iv, "cafebabefacedbaddecaf888");
  unhex(pt, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
  seal(&tx_aes128gcm, key, iv, 0, NULL, 0, pt, 64, a);
  seal(&ptls_minicrypto_aes128gcm, key, iv, 0, NULL, 0, pt, 64, b);
  check("GCM test case 3 (ciphertext and tag)", a, b,
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
        "4d5c2af327cd64a62cf35abd2ba6fab4");

  int ok = open_ok(&tx_aes128gcm, key, iv, 0, NULL, 0, a, 80, back) && memcmp(back, pt, 64) == 0;
  a[10] ^= 1;
  int rejects = !open_ok(&tx_aes128gcm, key, iv, 0, NULL, 0, a, 80, back);
  if (!(ok && rejects)) {
    fprintf(stderr, "  FAIL GCM open, and reject a flipped bit\n");
    ++failures;
  }
}

static void expand(ptls_hash_algorithm_t *h, uint8_t *out, size_t len, const uint8_t *secret,
                   const char *label) {
  ptls_hkdf_expand_label(h, out, len, ptls_iovec_init(secret, 32), label, ptls_iovec_init(NULL, 0),
                         "tls13 ");
}

static void kat_rfc9001_initial(void) {
  uint8_t salt[20], dcid[8], is_a[32], is_b[32], cs_a[32], cs_b[32];
  uint8_t key_a[16], key_b[16], iv_a[12], iv_b[12], hp_a[16], hp_b[16];
  uint8_t sample[16], mask_a[16], mask_b[16];
  unhex(salt, "38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
  unhex(dcid, "8394c8f03e515708");
  ptls_hkdf_extract(&tx_sha256, is_a, ptls_iovec_init(salt, 20), ptls_iovec_init(dcid, 8));
  ptls_hkdf_extract(&ptls_minicrypto_sha256, is_b, ptls_iovec_init(salt, 20),
                    ptls_iovec_init(dcid, 8));
  check("RFC 9001 A.1 initial_secret", is_a, is_b,
        "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
  expand(&tx_sha256, cs_a, 32, is_a, "client in");
  expand(&ptls_minicrypto_sha256, cs_b, 32, is_b, "client in");
  check("RFC 9001 A.1 client_initial_secret", cs_a, cs_b,
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
  expand(&tx_sha256, key_a, 16, cs_a, "quic key");
  expand(&ptls_minicrypto_sha256, key_b, 16, cs_b, "quic key");
  check("RFC 9001 A.1 client key", key_a, key_b, "1f369613dd76d5467730efcbe3b1a22d");
  expand(&tx_sha256, iv_a, 12, cs_a, "quic iv");
  expand(&ptls_minicrypto_sha256, iv_b, 12, cs_b, "quic iv");
  check("RFC 9001 A.1 client iv", iv_a, iv_b, "fa044b2f42a3fd3b46fb255c");
  expand(&tx_sha256, hp_a, 16, cs_a, "quic hp");
  expand(&ptls_minicrypto_sha256, hp_b, 16, cs_b, "quic hp");
  check("RFC 9001 A.1 client hp", hp_a, hp_b, "9f50449e04a0e810283a1e9933adedd2");

  unhex(sample, "d1b1c98dd7689fb8ec11d242b123dc9b");
  ecb(&tx_aes128ecb, hp_a, sample, 16, mask_a);
  ecb(&ptls_minicrypto_aes128ecb, hp_b, sample, 16, mask_b);
  check("RFC 9001 A.2 header protection mask", mask_a, mask_b, "437b9aec36");
}

static void kat_rfc9001_chacha(void) {
  uint8_t secret[32], key_a[32], key_b[32], iv_a[12], iv_b[12], hp_a[32], hp_b[32];
  uint8_t header[4], pt[1] = {0x01}, ct_a[17], ct_b[17], sample[16];
  uint8_t zeros[5] = {0}, mask_a[5], mask_b[5];
  unhex(secret, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
  expand(&tx_sha256, key_a, 32, secret, "quic key");
  expand(&ptls_minicrypto_sha256, key_b, 32, secret, "quic key");
  check("RFC 9001 A.5 key", key_a, key_b,
        "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
  expand(&tx_sha256, iv_a, 12, secret, "quic iv");
  expand(&ptls_minicrypto_sha256, iv_b, 12, secret, "quic iv");
  check("RFC 9001 A.5 iv", iv_a, iv_b, "e0459b3474bdd0e44a41c144");
  expand(&tx_sha256, hp_a, 32, secret, "quic hp");
  expand(&ptls_minicrypto_sha256, hp_b, 32, secret, "quic hp");
  check("RFC 9001 A.5 hp", hp_a, hp_b,
        "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");

  /* The nonce is iv XOR packet number, built by ptls_aead__build_iv. */
  unhex(header, "4200bff4");
  seal(&tx_chacha20poly1305, key_a, iv_a, 654360564, header, 4, pt, 1, ct_a);
  seal(&ptls_minicrypto_chacha20poly1305, key_b, iv_b, 654360564, header, 4, pt, 1, ct_b);
  check("RFC 9001 A.5 payload ciphertext", ct_a, ct_b, "655e5cd55c41f69080575d7999c25a5bfb");

  unhex(sample, "5e5cd55c41f69080575d7999c25a5bfb");
  ptls_cipher_context_t *c = ptls_cipher_new(&tx_chacha20, 1, hp_a);
  ptls_cipher_init(c, sample);
  ptls_cipher_encrypt(c, mask_a, zeros, 5);
  ptls_cipher_free(c);
  c = ptls_cipher_new(&ptls_minicrypto_chacha20, 1, hp_b);
  ptls_cipher_init(c, sample);
  ptls_cipher_encrypt(c, mask_b, zeros, 5);
  ptls_cipher_free(c);
  check("RFC 9001 A.5 header protection mask", mask_a, mask_b, "aefefe7d03");
}

/* --- TLS handshakes between backends, in memory ------------------------------ */

static ptls_key_exchange_algorithm_t *tx_kx[] = {&tx_x25519, NULL};
static ptls_key_exchange_algorithm_t *mini_kx[] = {&ptls_minicrypto_x25519, NULL};

/* Feeds `in` to `tls` as handshake input and drops the consumed bytes. Returns
   the handshake status. */
static int feed(ptls_t *tls, ptls_buffer_t *out, ptls_buffer_t *in) {
  size_t consumed = in->off;
  int ret = ptls_handshake(tls, out, in->base, &consumed, NULL);
  memmove(in->base, in->base + consumed, in->off - consumed);
  in->off -= consumed;
  return ret;
}

static int roundtrip(ptls_t *from, ptls_t *to, const char *msg) {
  ptls_buffer_t rec, plain;
  ptls_buffer_init(&rec, "", 0);
  ptls_buffer_init(&plain, "", 0);
  int sret = ptls_send(from, &rec, msg, strlen(msg));
  size_t n = rec.off;
  int rret = sret == 0 ? ptls_receive(to, &plain, rec.base, &n) : -1;
  int ok =
      sret == 0 && rret == 0 && plain.off == strlen(msg) && memcmp(plain.base, msg, plain.off) == 0;
  if (!ok) {
    fprintf(stderr, "    send=%d receive=%d plain=%zu\n", sret, rret, plain.off);
  }
  ptls_buffer_dispose(&rec);
  ptls_buffer_dispose(&plain);
  return ok;
}

static void tls_pair(const char *name, int client_tx, int server_tx, int chacha,
                     const uint8_t secret_key[64], const uint8_t pub[32]) {
  uint8_t spki[TX_ED25519_SPKI_LEN];
  tx_ed25519_spki(spki, pub);
  ptls_iovec_t cert = {spki, sizeof(spki)};
  tx_ed25519_signer signer;
  tx_ed25519_signer_init(&signer, secret_key);
  tx_ed25519_verifier verifier;
  tx_ed25519_verifier_init(&verifier, (const uint8_t (*)[32])pub, 1, 0);

  ptls_cipher_suite_t *tx_suites[] = {chacha ? &tx_chacha20poly1305sha256 : &tx_aes128gcmsha256,
                                      NULL};
  ptls_cipher_suite_t *mini_suites[] = {
      chacha ? &ptls_minicrypto_chacha20poly1305sha256 : &ptls_minicrypto_aes128gcmsha256, NULL};

  ptls_context_t cctx = {
      .random_bytes = client_tx ? tx_random_bytes : ptls_minicrypto_random_bytes,
      .get_time = &ptls_get_time,
      .key_exchanges = client_tx ? tx_kx : mini_kx,
      .cipher_suites = client_tx ? tx_suites : mini_suites,
      .verify_certificate = &verifier.super,
  };
  cctx.use_raw_public_keys = 1;
  ptls_context_t sctx = {
      .random_bytes = server_tx ? tx_random_bytes : ptls_minicrypto_random_bytes,
      .get_time = &ptls_get_time,
      .key_exchanges = server_tx ? tx_kx : mini_kx,
      .cipher_suites = server_tx ? tx_suites : mini_suites,
      .certificates = {&cert, 1},
      .sign_certificate = &signer.super,
  };
  sctx.use_raw_public_keys = 1;

  ptls_t *client = ptls_client_new(&cctx), *server = ptls_server_new(&sctx);
  ptls_buffer_t c2s, s2c;
  ptls_buffer_init(&c2s, "", 0);
  ptls_buffer_init(&s2c, "", 0);
  int cret = ptls_handshake(client, &c2s, NULL, NULL, NULL), sret = -1;
  /* A picotls server returns 0 after sending its Finished, before it reads the
     client's. Loop until both sides report the handshake complete. */
  for (int i = 0;
       i < 8 && !(ptls_handshake_is_complete(client) && ptls_handshake_is_complete(server)); ++i) {
    if (c2s.off)
      sret = feed(server, &s2c, &c2s);
    if (s2c.off)
      cret = feed(client, &c2s, &s2c);
  }
  int ok = cret == 0 && sret == 0 && roundtrip(client, server, "hello from the client") &&
           roundtrip(server, client, "hello from the server");
  if (!ok) {
    ++failures;
    fprintf(stderr, "  FAIL %s (client=%d server=%d)\n", name, cret, sret);
  }
  ptls_buffer_dispose(&c2s);
  ptls_buffer_dispose(&s2c);
  ptls_free(client);
  ptls_free(server);
  tx_ed25519_signer_dispose(&signer);
}

/* --- Hybrid key exchange against cloudflare.com -------------------------------- */

static int accept_sign(void *ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sig) {
  (void)ctx, (void)algo, (void)data, (void)sig;
  return 0; /* The certificate is not checked; this test covers key exchange. */
}

static int accept_cert(ptls_verify_certificate_t *self, ptls_t *tls, const char *name,
                       int (**vs)(void *, uint16_t, ptls_iovec_t, ptls_iovec_t), void **vd,
                       ptls_iovec_t *certs, size_t n) {
  (void)self, (void)tls, (void)name, (void)certs, (void)n;
  *vs = accept_sign;
  *vd = NULL;
  return 0;
}

static const uint16_t web_algos[] = {
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    PTLS_SIGNATURE_RSA_PKCS1_SHA256, PTLS_SIGNATURE_ED25519, UINT16_MAX};

static void hybrid_cloudflare(void) {
  const char *host = "cloudflare.com";
  struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *ai;
  if (getaddrinfo(host, "443", &hints, &ai) != 0) {
    fprintf(stderr, "  FAIL cloudflare.com: name lookup failed\n");
    ++failures;
    return;
  }
  int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  struct timeval tv = {5, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
    freeaddrinfo(ai);
    close(fd);
    fprintf(stderr, "  FAIL cloudflare.com: connect failed\n");
    ++failures;
    return;
  }
  freeaddrinfo(ai);

  ptls_verify_certificate_t verifier = {accept_cert, web_algos};
  ptls_key_exchange_algorithm_t *kx[] = {&tx_x25519mlkem768, NULL};
  ptls_cipher_suite_t *suites[] = {&tx_aes128gcmsha256, &tx_chacha20poly1305sha256, NULL};
  ptls_context_t ctx = {.random_bytes = tx_random_bytes,
                        .get_time = &ptls_get_time,
                        .key_exchanges = kx,
                        .cipher_suites = suites,
                        .verify_certificate = &verifier};
  ptls_t *tls = ptls_client_new(&ctx);
  ptls_set_server_name(tls, host, strlen(host));

  int before = tx_mlkem_exchanges;
  ptls_buffer_t out;
  ptls_buffer_init(&out, "", 0);
  int ret = ptls_handshake(tls, &out, NULL, NULL, NULL);
  uint8_t buf[16384];
  while (ret == PTLS_ERROR_IN_PROGRESS) {
    if (out.off && send(fd, out.base, out.off, 0) != (ssize_t)out.off)
      break;
    out.off = 0;
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0)
      break;
    size_t off = 0;
    while (off < (size_t)n && ret == PTLS_ERROR_IN_PROGRESS) {
      size_t consumed = (size_t)n - off;
      ret = ptls_handshake(tls, &out, buf + off, &consumed, NULL);
      off += consumed;
    }
  }
  if (out.off)
    send(fd, out.base, out.off, 0);
  out.off = 0;

  /* Check that application data decrypts by reading an HTTP status line. */
  int got_http = 0;
  if (ret == 0) {
    char req[128];
    snprintf(req, sizeof(req), "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    ptls_send(tls, &out, req, strlen(req));
    send(fd, out.base, out.off, 0);
    ptls_buffer_t plain;
    ptls_buffer_init(&plain, "", 0);
    for (int i = 0; i < 20 && plain.off < 12; ++i) {
      ssize_t n = recv(fd, buf, sizeof(buf), 0);
      if (n <= 0)
        break;
      size_t off = 0;
      while (off < (size_t)n) {
        size_t consumed = (size_t)n - off;
        if (ptls_receive(tls, &plain, buf + off, &consumed) != 0)
          break;
        off += consumed;
      }
    }
    got_http = plain.off >= 8 && memcmp(plain.base, "HTTP/1.1", 8) == 0;
    ptls_buffer_dispose(&plain);
  }
  int ok = ret == 0 && tx_mlkem_exchanges > before && got_http;
  if (!ok) {
    ++failures;
    fprintf(stderr, "  FAIL cloudflare.com: handshake=%d hybrid=%d http=%d\n", ret,
            tx_mlkem_exchanges > before, got_http);
  }
  ptls_buffer_dispose(&out);
  ptls_free(tls);
  close(fd);
}

int tx_crypto_test_known_answers(void) {
  failures = 0;
  kat_aes_ecb();
  kat_gcm();
  kat_rfc9001_initial();
  kat_rfc9001_chacha();
  return failures;
}

int tx_crypto_test_backend_interop(const uint8_t secret_key[64], const uint8_t public_key[32]) {
  failures = 0;
  tls_pair("minicrypto both sides (baseline)", 0, 0, 0, secret_key, public_key);
  tls_pair("tx both sides", 1, 1, 0, secret_key, public_key);
  tls_pair("tx client, minicrypto server, AES-GCM", 1, 0, 0, secret_key, public_key);
  tls_pair("tx client, minicrypto server, ChaCha20", 1, 0, 1, secret_key, public_key);
  tls_pair("minicrypto client, tx server, AES-GCM", 0, 1, 0, secret_key, public_key);
  tls_pair("minicrypto client, tx server, ChaCha20", 0, 1, 1, secret_key, public_key);
  return failures;
}

/* Returns -1 when skipped (TX_TEST_NETWORK unset). */
int tx_crypto_test_cloudflare(void) {
  if (getenv("TX_TEST_NETWORK") == NULL)
    return -1;
  failures = 0;
  hybrid_cloudflare();
  return failures;
}

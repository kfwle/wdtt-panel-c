// TLS support (optional): wrap listening socket with OpenSSL
#ifndef WDTT_TLS_H
#define WDTT_TLS_H

#include <openssl/ssl.h>

// returns ctx or NULL (err msg in buf). min TLS1.2, server certs only.
SSL_CTX *tls_ctx_new(const char *cert_path, const char *key_path, char *err, size_t errcap);
void tls_ctx_free(SSL_CTX *ctx);
void tls_set_alpn_h2_off(SSL_CTX *ctx); // keep http/1.1 only

#endif

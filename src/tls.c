#include "tls.h"

#include <stdio.h>

SSL_CTX *tls_ctx_new(const char *cert_path, const char *key_path, char *err, size_t errcap) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        snprintf(err, errcap, "SSL_CTX_new failed");
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) {
        snprintf(err, errcap, "cannot load certificate %s", cert_path);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        snprintf(err, errcap, "cannot load private key %s", key_path);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        snprintf(err, errcap, "private key does not match certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

void tls_ctx_free(SSL_CTX *ctx) {
    if (ctx) SSL_CTX_free(ctx);
}

// HTTP request/response + connection abstraction (plain or TLS)
#ifndef WDTT_HTTP_H
#define WDTT_HTTP_H

#include "util.h"
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>

// ---- header list ----
typedef struct {
    char **keys;
    char **vals;
    size_t n, cap;
} HList;

void hlist_add(HList *h, const char *k, size_t kn, const char *v, size_t vn);
const char *hlist_get(const HList *h, const char *key); // case-insensitive
void hlist_free(HList *h);

// ---- query params ----
typedef struct {
    char **keys;
    char **vals;
    size_t n, cap;
} QList;

void qlist_parse(const char *query, QList *q);      // takes raw "a=1&b=2", decodes
const char *qlist_get(const QList *q, const char *key);
void qlist_free(QList *q);

// ---- connection (fd or SSL) ----
typedef struct {
    int fd;
    SSL *ssl;           // NULL for plain
    uint8_t rbuf[16384];
    size_t rlen, rpos;
    int eof;
} Conn;

int conn_read(Conn *c, uint8_t *dst, size_t n);     // >0 bytes, 0 eof, <0 err
int conn_readline(Conn *c, Buf *line);              // reads up to \n, strips \r\n; 0 ok, -1 err/over
int conn_write(Conn *c, const void *data, size_t n);
int conn_readn(Conn *c, uint8_t *dst, size_t n);    // exact n; 0 ok, -1 err/eof

// ---- request ----
typedef struct {
    char method[16];
    char path[512];        // decoded path (no query)
    char query[1024];      // raw query
    HList headers;
    QList params;          // parsed query params
    Buf body;
    char client_ip[64];
    SSL *tls;              // set when TLS session used
} HttpReq;

// returns 0 on success, -1 malformed, -2 body too large, -3 timeout
int http_req_parse(Conn *c, HttpReq *req, size_t max_body);
void http_req_free(HttpReq *req);

// ---- response helpers ----
typedef struct {
    int status;
    const char *content_type;
    HList headers;         // extra headers
    Buf body;
} HttpRes;

void http_res_init(HttpRes *r);
void http_res_free(HttpRes *r);
void http_res_set_header(HttpRes *r, const char *k, const char *v);
void http_res_json(HttpRes *r, int status, const char *json);  // json copied
void http_res_text(HttpRes *r, int status, const char *text);
void http_res_redirect(HttpRes *r, const char *location);
int  http_res_send(Conn *c, HttpRes *r, int keep_alive);       // 0 ok

#endif

#include "http.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

// ---------- HList ----------
void hlist_add(HList *h, const char *k, size_t kn, const char *v, size_t vn) {
    if (h->n == h->cap) {
        h->cap = h->cap ? h->cap * 2 : 16;
        h->keys = xrealloc(h->keys, h->cap * sizeof(char *));
        h->vals = xrealloc(h->vals, h->cap * sizeof(char *));
    }
    h->keys[h->n] = xstrndup(k, kn);
    h->vals[h->n] = xstrndup(v, vn);
    h->n++;
}

const char *hlist_get(const HList *h, const char *key) {
    for (size_t i = 0; i < h->n; i++)
        if (str_ieq(h->keys[i], key)) return h->vals[i];
    return NULL;
}

void hlist_free(HList *h) {
    for (size_t i = 0; i < h->n; i++) {
        free(h->keys[i]);
        free(h->vals[i]);
    }
    free(h->keys);
    free(h->vals);
    memset(h, 0, sizeof(*h));
}

// ---------- QList ----------
static void qlist_add(QList *q, char *k, char *v) {
    if (q->n == q->cap) {
        q->cap = q->cap ? q->cap * 2 : 8;
        q->keys = xrealloc(q->keys, q->cap * sizeof(char *));
        q->vals = xrealloc(q->vals, q->cap * sizeof(char *));
    }
    q->keys[q->n] = k;
    q->vals[q->n] = v;
    q->n++;
}

void qlist_parse(const char *query, QList *q) {
    memset(q, 0, sizeof(*q));
    if (!query) return;
    const char *p = query;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        if (seg) {
            const char *eq = memchr(p, '=', seg);
            Buf k, v;
            buf_init(&k);
            buf_init(&v);
            if (eq) {
                url_decode(p, (size_t)(eq - p), &k);
                url_decode(eq + 1, (size_t)(p + seg - eq - 1), &v);
            } else {
                url_decode(p, seg, &k);
            }
            qlist_add(q, buf_detach(&k), buf_detach(&v));
        }
        if (!amp) break;
        p = amp + 1;
    }
}

const char *qlist_get(const QList *q, const char *key) {
    for (size_t i = 0; i < q->n; i++)
        if (strcmp(q->keys[i], key) == 0) return q->vals[i];
    return NULL;
}

void qlist_free(QList *q) {
    for (size_t i = 0; i < q->n; i++) {
        free(q->keys[i]);
        free(q->vals[i]);
    }
    free(q->keys);
    free(q->vals);
    memset(q, 0, sizeof(*q));
}

// ---------- Conn ----------
int conn_read(Conn *c, uint8_t *dst, size_t n) {
    if (c->rpos < c->rlen) {
        size_t take = c->rlen - c->rpos;
        if (take > n) take = n;
        memcpy(dst, c->rbuf + c->rpos, take);
        c->rpos += take;
        return (int)take;
    }
    for (;;) {
        ssize_t r;
        if (c->ssl) {
            r = SSL_read(c->ssl, dst, (int)n);
            if (r <= 0) {
                int err = SSL_get_error(c->ssl, (int)r);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                return (r == 0) ? 0 : -1;
            }
        } else {
            do {
                r = recv(c->fd, dst, n, 0);
            } while (r < 0 && errno == EINTR);
            if (r == 0) return 0;
            if (r < 0) return -1;
        }
        return (int)r;
    }
}

int conn_readn(Conn *c, uint8_t *dst, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = conn_read(c, dst + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

int conn_readline(Conn *c, Buf *line) {
    for (;;) {
        // scan buffered data for newline
        while (c->rpos < c->rlen) {
            uint8_t *nl = memchr(c->rbuf + c->rpos, '\n', c->rlen - c->rpos);
            if (nl) {
                size_t end = (size_t)(nl - (c->rbuf + c->rpos));
                buf_append(line, c->rbuf + c->rpos, end ? end : 0);
                c->rpos += end + 1;
                if (line->len && line->s[line->len - 1] == '\r') line->len--;
                if (line->s) line->s[line->len] = 0;
                return 0;
            }
            buf_append(line, c->rbuf + c->rpos, c->rlen - c->rpos);
            c->rpos = c->rlen = 0;
            if (line->len > 16384) return -1; // header line cap
        }
        if (c->eof) return -1;
        int r = conn_read(c, c->rbuf, sizeof(c->rbuf));
        if (r <= 0) {
            c->eof = 1;
            return -1;
        }
        c->rlen = (size_t)r;
        c->rpos = 0;
    }
}

int conn_write(Conn *c, const void *data, size_t n) {
    const uint8_t *p = data;
    while (n > 0) {
        ssize_t w;
        if (c->ssl) {
            w = SSL_write(c->ssl, p, (int)n);
            if (w <= 0) {
                int err = SSL_get_error(c->ssl, (int)w);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                return -1;
            }
        } else {
            do {
                w = send(c->fd, p, n, MSG_NOSIGNAL);
            } while (w < 0 && errno == EINTR);
            if (w <= 0) return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

// ---------- request parse ----------
int http_req_parse(Conn *c, HttpReq *req, size_t max_body) {
    memset(req, 0, sizeof(*req));
    req->tls = c->ssl;

    Buf line;
    buf_init(&line);
    // request line; skip stray blank lines between pipelined requests
    for (;;) {
        if (conn_readline(c, &line) != 0) {
            buf_free(&line);
            return -1;
        }
        if (line.len > 0) break;
        buf_free(&line);
        buf_init(&line);
    }

    // "METHOD SP TARGET SP VERSION"
    char *sp1 = memchr(line.s, ' ', line.len);
    char *sp2 = sp1 ? memchr(sp1 + 1, ' ', (size_t)(line.s + line.len - sp1 - 1)) : NULL;
    if (!sp1 || !sp2) {
        buf_free(&line);
        return -1;
    }
    size_t mlen = (size_t)(sp1 - line.s);
    if (mlen >= sizeof(req->method)) mlen = sizeof(req->method) - 1;
    memcpy(req->method, line.s, mlen);
    req->method[mlen] = 0;

    char *target = sp1 + 1;
    size_t tlen = (size_t)(sp2 - target);
    char *qmark = memchr(target, '?', tlen);
    size_t plen = qmark ? (size_t)(qmark - target) : tlen;
    if (plen >= sizeof(req->path)) plen = sizeof(req->path) - 1;
    Buf pd;
    buf_init(&pd);
    url_decode(target, plen, &pd);
    snprintf(req->path, sizeof(req->path), "%s", pd.s ? pd.s : "");
    buf_free(&pd);
    if (qmark) {
        size_t qlen = tlen - (size_t)(qmark - target) - 1;
        if (qlen >= sizeof(req->query)) qlen = sizeof(req->query) - 1;
        memcpy(req->query, qmark + 1, qlen);
        req->query[qlen] = 0;
    }

    // headers
    size_t headers_total = 0;
    for (;;) {
        buf_free(&line);
        buf_init(&line);
        if (conn_readline(c, &line) != 0) {
            buf_free(&line);
            return -1;
        }
        if (line.len == 0) break;
        if (req->headers.n >= 100 || headers_total > 32768) {
            buf_free(&line);
            return -1; // header count/size caps
        }
        headers_total += line.len;
        char *colon = memchr(line.s, ':', line.len);
        if (!colon) continue;
        size_t kn = (size_t)(colon - line.s);
        if (kn > 512) {
            buf_free(&line);
            return -1;
        }
        const char *v = colon + 1;
        while (v < line.s + line.len && (*v == ' ' || *v == '\t')) v++;
        size_t vn = (size_t)(line.s + line.len - v);
        // truncate long single headers defensively
        if (vn > 8192) vn = 8192;
        hlist_add(&req->headers, line.s, kn, v, vn);
    }

    // body
    const char *te = hlist_get(&req->headers, "Transfer-Encoding");
    const char *cl = hlist_get(&req->headers, "Content-Length");
    if (te && str_ieq(te, "chunked")) {
        // chunked: read chunks (RFC 7230: size is HEX, optional ;extensions)
        for (;;) {
            buf_free(&line);
            buf_init(&line);
            if (conn_readline(c, &line) != 0) goto bad;
            // strict hex parse before optional ';'
            char *semi = line.s ? memchr(line.s, ';', line.len) : NULL;
            size_t numlen = semi ? (size_t)(semi - line.s) : line.len;
            if (numlen == 0 || numlen > 16) goto bad;
            char hexnum[17];
            memcpy(hexnum, line.s, numlen);
            hexnum[numlen] = 0;
            char *end = NULL;
            errno = 0;
            unsigned long long sz = strtoull(hexnum, &end, 16);
            if (errno || end == hexnum || *end != 0) goto bad;
            if (sz == 0) {
                // trailers until blank line
                for (;;) {
                    buf_free(&line);
                    buf_init(&line);
                    if (conn_readline(c, &line) != 0) goto bad;
                    if (line.len == 0) break;
                }
                break;
            }
            if ((size_t)sz > max_body - req->body.len) {
                buf_free(&line);
                return -2;
            }
            uint8_t tmp[65536];
            unsigned long long left = sz;
            while (left > 0) {
                size_t take = left > (unsigned long long)sizeof(tmp) ? sizeof(tmp) : (size_t)left;
                if (conn_readn(c, tmp, take) != 0) goto bad;
                buf_append(&req->body, tmp, take);
                left -= take;
            }
            // trailing CRLF after chunk data
            if (conn_readn(c, tmp, 2) != 0) goto bad;
        }
    } else if (cl) {
        long long sz = 0;
        if (parse_ll(cl, &sz) != 0 || sz < 0 || (size_t)sz > max_body) {
            buf_free(&line);
            return -2;
        }
        uint8_t tmp[65536];
        long long left = sz;
        while (left > 0) {
            size_t take = left > (long long)sizeof(tmp) ? sizeof(tmp) : (size_t)left;
            if (conn_readn(c, tmp, take) != 0) goto bad;
            buf_append(&req->body, tmp, take);
            left -= (long long)take;
        }
    }

    qlist_parse(req->query[0] ? req->query : NULL, &req->params);
    buf_free(&line);
    return 0;

bad:
    buf_free(&line);
    return -1;
}

void http_req_free(HttpReq *req) {
    hlist_free(&req->headers);
    qlist_free(&req->params);
    buf_free(&req->body);
}

// ---------- response ----------
static const char *status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 413: return "Payload Too Large";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default: return "OK";
    }
}

void http_res_init(HttpRes *r) {
    r->status = 200;
    r->content_type = "text/plain; charset=utf-8";
    memset(&r->headers, 0, sizeof(r->headers));
    buf_init(&r->body);
}

void http_res_free(HttpRes *r) {
    hlist_free(&r->headers);
    buf_free(&r->body);
}

void http_res_set_header(HttpRes *r, const char *k, const char *v) {
    hlist_add(&r->headers, k, strlen(k), v, strlen(v));
}

void http_res_json(HttpRes *r, int status, const char *json) {
    r->status = status;
    r->content_type = "application/json; charset=utf-8";
    buf_clear(&r->body);
    buf_puts(&r->body, json);
}

void http_res_text(HttpRes *r, int status, const char *text) {
    r->status = status;
    r->content_type = "text/plain; charset=utf-8";
    buf_clear(&r->body);
    buf_puts(&r->body, text);
}

void http_res_redirect(HttpRes *r, const char *location) {
    r->status = 302;
    http_res_set_header(r, "Location", location);
    buf_clear(&r->body);
}

int http_res_send(Conn *c, HttpRes *r, int keep_alive) {
    Buf h;
    buf_init(&h);
    buf_printf(&h, "HTTP/1.1 %d %s\r\n", r->status, status_text(r->status));
    buf_printf(&h, "Content-Length: %zu\r\n", r->body.len);
    if (r->content_type) buf_printf(&h, "Content-Type: %s\r\n", r->content_type);
    buf_printf(&h, "Connection: %s\r\n", keep_alive ? "keep-alive" : "close");
    for (size_t i = 0; i < r->headers.n; i++)
        buf_printf(&h, "%s: %s\r\n", r->headers.keys[i], r->headers.vals[i]);
    buf_puts(&h, "\r\n");
    int rc = conn_write(c, h.s, h.len);
    if (rc == 0 && r->body.len) rc = conn_write(c, r->body.s, r->body.len);
    buf_free(&h);
    return rc;
}

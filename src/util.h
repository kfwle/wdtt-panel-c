// wdttpanel-c: lightweight VPN panel core utilities
#ifndef WDTT_UTIL_H
#define WDTT_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

// ---- dynamic string buffer ----
typedef struct {
    char  *s;
    size_t len, cap;
} Buf;

void buf_init(Buf *b);
static inline void buf_clear(Buf *b) { b->len = 0; if (b->s) b->s[0] = 0; }
void buf_free(Buf *b);
void buf_reserve(Buf *b, size_t need);
void buf_append(Buf *b, const void *data, size_t n);
void buf_puts(Buf *b, const char *s);
void buf_putc(Buf *b, char c);
void buf_printf(Buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
char *buf_detach(Buf *b); // returns malloc'd NUL-terminated string

// ---- alloc helpers ----
void *xmalloc(size_t n);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

// ---- encoding ----
size_t b64_encode(const uint8_t *in, size_t n, char *out);          // out >= b64len(n)+1
size_t b64_decode(const char *in, size_t n, uint8_t *out);          // returns decoded len
size_t b64url_encode(const uint8_t *in, size_t n, char *out);       // URL-safe, no padding
size_t b64url_decode(const char *in, size_t n, uint8_t *out);
void  hex_encode(const uint8_t *in, size_t n, char *out);           // out >= 2n+1
int   hex_decode(const char *in, size_t n, uint8_t *out);
int   hexval(char c);
void  url_encode(const char *in, Buf *out);
void  url_decode(const char *in, size_t n, Buf *out);

// ---- crypto shortcuts (OpenSSL) ----
void sha256_hex(const uint8_t *in, size_t n, char *out);            // out >= 65
void rand_bytes(uint8_t *out, size_t n);
void rand_hex(char *out, size_t nbytes);                            // nbytes*2+1 chars

// ---- misc ----
long long now_ms(void);
void   rfc1123(time_t t, char *out, size_t cap);                    // HTTP date
void   iso8601_local(long long ms, char *out, size_t cap);
int    str_ieq(const char *a, const char *b);
int    str_ieqn(const char *a, const char *b, size_t n);
int    parse_ll(const char *s, long long *out);
char  *json_escape(const char *s, size_t n);                        // malloc'd escaped (no quotes)

#endif

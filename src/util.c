#include "util.h"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>

// ---------- buffer ----------
void buf_init(Buf *b) { b->s = NULL; b->len = 0; b->cap = 0; }
void buf_free(Buf *b) { free(b->s); buf_init(b); }

void buf_reserve(Buf *b, size_t need) {
    if (b->len + need + 1 <= b->cap) return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + need + 1) cap *= 2;
    b->s = xrealloc(b->s, cap);
    b->cap = cap;
}

void buf_append(Buf *b, const void *data, size_t n) {
    if (!n) return;
    buf_reserve(b, n);
    memcpy(b->s + b->len, data, n);
    b->len += n;
    b->s[b->len] = 0;
}

void buf_puts(Buf *b, const char *s) { buf_append(b, s, strlen(s)); }
void buf_putc(Buf *b, char c) { buf_append(b, &c, 1); }

void buf_printf(Buf *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n > 0) {
        buf_reserve(b, (size_t)n);
        vsnprintf(b->s + b->len, (size_t)n + 1, fmt, ap2);
        b->len += (size_t)n;
    }
    va_end(ap2);
}

char *buf_detach(Buf *b) {
    if (!b->s) return xstrdup("");
    char *s = b->s;
    buf_init(b);
    return s;
}

// ---------- alloc ----------
void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { fprintf(stderr, "wdttpanel: out of memory\n"); abort(); }
    return p;
}
void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { fprintf(stderr, "wdttpanel: out of memory\n"); abort(); }
    return q;
}
char *xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = xmalloc(n);
    memcpy(p, s, n);
    return p;
}
char *xstrndup(const char *s, size_t n) {
    char *p = xmalloc(n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

// ---------- base64 ----------
static const char B64_STD[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char B64_URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t b64_gen(const uint8_t *in, size_t n, char *out, const char *tbl, int pad) {
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        size_t rem = n - i;
        if (rem > 1) v |= (uint32_t)in[i + 1] << 8;
        if (rem > 2) v |= in[i + 2];
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = rem > 1 ? tbl[(v >> 6) & 63] : (pad ? '=' : 0);
        if (!pad && rem == 1) o--; // no padding char at all
        out[o++] = rem > 2 ? tbl[v & 63] : (pad ? '=' : 0);
        if (!pad && rem < 3) o--;
    }
    out[o] = 0;
    return o;
}

size_t b64_encode(const uint8_t *in, size_t n, char *out) { return b64_gen(in, n, out, B64_STD, 1); }
size_t b64url_encode(const uint8_t *in, size_t n, char *out) { return b64_gen(in, n, out, B64_URL, 0); }

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

static size_t b64_gen_decode(const char *in, size_t n, uint8_t *out) {
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        int v = b64_val(c);
        if (v < 0) break;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return o;
}

size_t b64_decode(const char *in, size_t n, uint8_t *out) { return b64_gen_decode(in, n, out); }
size_t b64url_decode(const char *in, size_t n, uint8_t *out) { return b64_gen_decode(in, n, out); }

// ---------- hex ----------
void hex_encode(const uint8_t *in, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = H[in[i] >> 4];
        out[2 * i + 1] = H[in[i] & 15];
    }
    out[2 * n] = 0;
}

int hex_decode(const char *in, size_t n, uint8_t *out) {
    if (n % 2) return -1;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hexval(in[i]), lo = hexval(in[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// ---------- url ----------
void url_encode(const char *in, Buf *out) {
    for (; *in; in++) {
        unsigned char c = (unsigned char)*in;
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') buf_putc(out, (char)c);
        else buf_printf(out, "%%%02X", c);
    }
}

void url_decode(const char *in, size_t n, Buf *out) {
    for (size_t i = 0; i < n; i++) {
        if (in[i] == '%' && i + 2 < n) {
            int hi = hexval(in[i + 1]), lo = hexval(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                buf_putc(out, (char)((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        if (in[i] == '+') buf_putc(out, ' ');
        else buf_putc(out, in[i]);
    }
}

// ---------- crypto ----------
void sha256_hex(const uint8_t *in, size_t n, char *out) {
    uint8_t d[SHA256_DIGEST_LENGTH];
    SHA256(in, n, d);
    hex_encode(d, sizeof(d), out);
}

void rand_bytes(uint8_t *out, size_t n) {
    if (RAND_bytes(out, (int)n) != 1) {
        // extremely unlikely; fall back to /dev/urandom
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f || fread(out, 1, n, f) != n) abort();
        if (f) fclose(f);
    }
}

void rand_hex(char *out, size_t nbytes) {
    uint8_t tmp[64];
    if (nbytes > sizeof(tmp)) nbytes = sizeof(tmp);
    rand_bytes(tmp, nbytes);
    hex_encode(tmp, nbytes, out);
}

// ---------- misc ----------
long long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void rfc1123(time_t t, char *out, size_t cap) {
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, cap, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

void iso8601_local(long long ms, char *out, size_t cap) {
    time_t t = (time_t)(ms / 1000);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%d %H:%M:%S", &tm);
}

int str_ieq(const char *a, const char *b) { return a && b && strcasecmp(a, b) == 0; }
int str_ieqn(const char *a, const char *b, size_t n) { return a && b && strncasecmp(a, b, n) == 0; }

int parse_ll(const char *s, long long *out) {
    if (!s || !*s) return -1;
    char *end = NULL;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno || end == s) return -1;
    *out = v;
    return 0;
}

char *json_escape(const char *s, size_t n) {
    Buf b;
    buf_init(&b);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"': buf_puts(&b, "\\\""); break;
            case '\\': buf_puts(&b, "\\\\"); break;
            case '\n': buf_puts(&b, "\\n"); break;
            case '\r': buf_puts(&b, "\\r"); break;
            case '\t': buf_puts(&b, "\\t"); break;
            default:
                if (c < 0x20) buf_printf(&b, "\\u%04x", c);
                else buf_putc(&b, (char)c);
        }
    }
    return buf_detach(&b);
}

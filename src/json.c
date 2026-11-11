#include "json.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// ---------- parse ----------
typedef struct {
    const char *s;
    size_t n, pos;
    int depth;
} JP;

static JVal *jparse_value(JP *p);

static JVal *jnew(JType t) {
    JVal *v = xmalloc(sizeof(JVal));
    memset(v, 0, sizeof(*v));
    v->type = t;
    return v;
}

void json_free(JVal *v) {
    if (!v) return;
    free(v->str);
    for (size_t i = 0; i < v->n; i++) {
        json_free(v->items[i]);
        if (v->keys) free(v->keys[i]);
    }
    free(v->items);
    free(v->keys);
    free(v);
}

static void jpush(JVal *v, char *key, JVal *item) {
    if (v->n == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 8;
        v->items = xrealloc(v->items, v->cap * sizeof(JVal *));
        if (v->type == J_OBJ) v->keys = xrealloc(v->keys, v->cap * sizeof(char *));
    }
    if (v->type == J_OBJ) v->keys[v->n] = key;
    v->items[v->n] = item;
    v->n++;
}

static void jskip(JP *p) {
    while (p->pos < p->n && (isspace((unsigned char)p->s[p->pos]))) p->pos++;
}

static int jhex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int jparse_utf8(Buf *out, unsigned cp) {
    if (cp < 0x80) {
        buf_putc(out, (char)cp);
    } else if (cp < 0x800) {
        buf_putc(out, (char)(0xC0 | (cp >> 6)));
        buf_putc(out, (char)(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        buf_putc(out, (char)(0xE0 | (cp >> 12)));
        buf_putc(out, (char)(0x80 | ((cp >> 6) & 0x3F)));
        buf_putc(out, (char)(0x80 | (cp & 0x3F)));
    } else {
        buf_putc(out, (char)(0xF0 | (cp >> 18)));
        buf_putc(out, (char)(0x80 | ((cp >> 12) & 0x3F)));
        buf_putc(out, (char)(0x80 | ((cp >> 6) & 0x3F)));
        buf_putc(out, (char)(0x80 | (cp & 0x3F)));
    }
    return 0;
}

static char *jparse_string_raw(JP *p, size_t *outlen) {
    if (p->pos >= p->n || p->s[p->pos] != '"') return NULL;
    p->pos++;
    Buf b;
    buf_init(&b);
    while (p->pos < p->n) {
        char c = p->s[p->pos];
        if (c == '"') {
            p->pos++;
            *outlen = b.len;
            return buf_detach(&b);
        }
        if ((unsigned char)c < 0x20) {
            buf_free(&b);
            return NULL;
        }
        if (c == '\\') {
            p->pos++;
            if (p->pos >= p->n) break;
            char e = p->s[p->pos++];
            switch (e) {
                case '"': buf_putc(&b, '"'); break;
                case '\\': buf_putc(&b, '\\'); break;
                case '/': buf_putc(&b, '/'); break;
                case 'b': buf_putc(&b, '\b'); break;
                case 'f': buf_putc(&b, '\f'); break;
                case 'n': buf_putc(&b, '\n'); break;
                case 'r': buf_putc(&b, '\r'); break;
                case 't': buf_putc(&b, '\t'); break;
                case 'u': {
                    if (p->pos + 4 > p->n) goto fail;
                    unsigned cp = 0;
                    for (int i = 0; i < 4; i++) {
                        int h = jhex(p->s[p->pos + i]);
                        if (h < 0) goto fail;
                        cp = (cp << 4) | (unsigned)h;
                    }
                    p->pos += 4;
                    if (cp >= 0xD800 && cp <= 0xDBFF && p->pos + 6 <= p->n &&
                        p->s[p->pos] == '\\' && p->s[p->pos + 1] == 'u') {
                        unsigned lo = 0;
                        int ok = 1;
                        for (int i = 0; i < 4; i++) {
                            int h = jhex(p->s[p->pos + 2 + i]);
                            if (h < 0) { ok = 0; break; }
                            lo = (lo << 4) | (unsigned)h;
                        }
                        if (ok && lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            p->pos += 6;
                        }
                    }
                    jparse_utf8(&b, cp);
                    break;
                }
                default: goto fail;
            }
        } else {
            buf_putc(&b, c);
            p->pos++;
        }
    }
fail:
    buf_free(&b);
    return NULL;
}

static JVal *jparse_string(JP *p) {
    size_t len = 0;
    char *s = jparse_string_raw(p, &len);
    if (!s) return NULL;
    JVal *v = jnew(J_STR);
    v->str = s;
    v->strlen = len;
    return v;
}

static JVal *jparse_num(JP *p) {
    const char *start = p->s + p->pos;
    char *end = NULL;
    double d = strtod(start, &end);
    if (end == start) return NULL;
    p->pos += (size_t)(end - start);
    JVal *v = jnew(J_NUM);
    v->num = d;
    return v;
}

static JVal *jparse_arr(JP *p) {
    p->pos++; // [
    JVal *arr = jnew(J_ARR);
    jskip(p);
    if (p->pos < p->n && p->s[p->pos] == ']') {
        p->pos++;
        return arr;
    }
    for (;;) {
        JVal *item = jparse_value(p);
        if (!item) {
            json_free(arr);
            return NULL;
        }
        jpush(arr, NULL, item);
        jskip(p);
        if (p->pos >= p->n) {
            json_free(arr);
            return NULL;
        }
        if (p->s[p->pos] == ',') {
            p->pos++;
            jskip(p);
            continue;
        }
        if (p->s[p->pos] == ']') {
            p->pos++;
            return arr;
        }
        json_free(arr);
        return NULL;
    }
}

static JVal *jparse_obj(JP *p) {
    p->pos++; // {
    JVal *obj = jnew(J_OBJ);
    jskip(p);
    if (p->pos < p->n && p->s[p->pos] == '}') {
        p->pos++;
        return obj;
    }
    for (;;) {
        jskip(p);
        size_t klen = 0;
        char *key = jparse_string_raw(p, &klen);
        if (!key) {
            json_free(obj);
            return NULL;
        }
        jskip(p);
        if (p->pos >= p->n || p->s[p->pos] != ':') {
            free(key);
            json_free(obj);
            return NULL;
        }
        p->pos++;
        jskip(p);
        JVal *item = jparse_value(p);
        if (!item) {
            free(key);
            json_free(obj);
            return NULL;
        }
        jpush(obj, key, item);
        jskip(p);
        if (p->pos >= p->n) {
            json_free(obj);
            return NULL;
        }
        if (p->s[p->pos] == ',') {
            p->pos++;
            continue;
        }
        if (p->s[p->pos] == '}') {
            p->pos++;
            return obj;
        }
        json_free(obj);
        return NULL;
    }
}

static JVal *jparse_value(JP *p) {
    if (p->depth++ > 32) {
        p->depth--;
        return NULL;
    }
    jskip(p);
    if (p->pos >= p->n) {
        p->depth--;
        return NULL;
    }
    char c = p->s[p->pos];
    JVal *v = NULL;
    if (c == '"') v = jparse_string(p);
    else if (c == '{') v = jparse_obj(p);
    else if (c == '[') v = jparse_arr(p);
    else if (!strncmp(p->s + p->pos, "true", 4) && p->pos + 4 <= p->n) {
        v = jnew(J_BOOL);
        v->boolean = 1;
        p->pos += 4;
    } else if (!strncmp(p->s + p->pos, "false", 5) && p->pos + 5 <= p->n) {
        v = jnew(J_BOOL);
        v->boolean = 0;
        p->pos += 5;
    } else if (!strncmp(p->s + p->pos, "null", 4) && p->pos + 4 <= p->n) {
        v = jnew(J_NULL);
        p->pos += 4;
    } else {
        v = jparse_num(p);
    }
    p->depth--;
    return v;
}

JVal *json_parse(const char *s, size_t n) {
    JP p = {s, n, 0, 0};
    JVal *v = jparse_value(&p);
    if (!v) return NULL;
    jskip(&p);
    // trailing garbage => reject
    if (p.pos != n) {
        json_free(v);
        return NULL;
    }
    return v;
}

// ---------- accessors ----------
JVal *json_get(const JVal *obj, const char *key) {
    if (!obj || obj->type != J_OBJ) return NULL;
    for (size_t i = 0; i < obj->n; i++)
        if (strcmp(obj->keys[i], key) == 0) return obj->items[i];
    return NULL;
}

JVal *json_idx(const JVal *arr, size_t i) {
    if (!arr || arr->type != J_ARR || i >= arr->n) return NULL;
    return arr->items[i];
}

const char *json_get_str(const JVal *obj, const char *key) {
    JVal *v = json_get(obj, key);
    return (v && v->type == J_STR) ? v->str : NULL;
}

long long json_get_int(const JVal *obj, const char *key, long long def) {
    JVal *v = json_get(obj, key);
    if (!v) return def;
    if (v->type == J_NUM) return (long long)v->num;
    if (v->type == J_BOOL) return v->boolean;
    return def;
}

int json_get_bool(const JVal *obj, const char *key, int def) {
    JVal *v = json_get(obj, key);
    if (!v) return def;
    if (v->type == J_BOOL) return v->boolean;
    if (v->type == J_NUM) return v->num != 0;
    return def;
}

// ---------- writer ----------
void jsonw_str(Buf *b, const char *s) {
    buf_putc(b, '"');
    if (s) {
        char *e = json_escape(s, strlen(s));
        buf_puts(b, e);
        free(e);
    }
    buf_putc(b, '"');
}

void jsonw_kv_str(Buf *b, const char *k, const char *v) {
    jsonw_str(b, k);
    buf_putc(b, ':');
    jsonw_str(b, v);
}

void jsonw_kv_int(Buf *b, const char *k, long long v) {
    jsonw_str(b, k);
    buf_printf(b, ":%lld", v);
}

void jsonw_kv_bool(Buf *b, const char *k, int v) {
    jsonw_str(b, k);
    buf_puts(b, v ? ":true" : ":false");
}

void jsonw_kv_raw(Buf *b, const char *k, const char *raw_json) {
    jsonw_str(b, k);
    buf_putc(b, ':');
    buf_puts(b, raw_json ? raw_json : "null");
}

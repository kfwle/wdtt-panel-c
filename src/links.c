#include "links.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void resolve_user_ports(const WdttUser *u, const WdttInbound *in, int *dtls, int *wg, int *client) {
    *dtls = in->dtls_port > 0 ? in->dtls_port : 56000;
    *wg = in->wg_port > 0 ? in->wg_port : 56001;
    *client = in->client_port > 0 ? in->client_port : 9000;
    if (!u || !u->ports[0]) return;
    int vals[3] = {0, 0, 0};
    const char *p = u->ports;
    for (int i = 0; i < 3 && *p; i++) {
        char *end = NULL;
        long v = strtol(p, &end, 10);
        if (end == p) break;
        if (v > 0 && v <= 65535) vals[i] = (int)v;
        p = strchr(end, ',');
        if (!p) break;
        p++;
    }
    if (vals[0] > 0) *dtls = vals[0];
    if (vals[1] > 0) *wg = vals[1];
    if (vals[2] > 0) *client = vals[2];
}

char *gen_password(void) {
    const char *tbl = WDTT_PASS_CHARS;
    size_t n = strlen(tbl);
    char *out = xmalloc(17);
    for (int i = 0; i < 16; i++) {
        // rejection sampling (fixes Go panel modulo bias)
        uint8_t b;
        do {
            rand_bytes(&b, 1);
        } while (b >= (uint8_t)(256 - 256 % n));
        out[i] = tbl[b % n];
    }
    out[16] = 0;
    return out;
}

char *gen_subid(void) {
    char *out = xmalloc(17);
    for (int i = 0; i < 16; i++) {
        uint8_t b;
        do {
            rand_bytes(&b, 1);
        } while (b >= (uint8_t)(256 - 256 % 36));
        out[i] = (char)("abcdefghijklmnopqrstuvwxyz0123456789"[b % 36]);
    }
    out[16] = 0;
    return out;
}

static void payload_json(Buf *b, const char *vpn, const char *name, const char *ip,
                         int dtls, int raw, const char *pass, const char *did,
                         const char *hash, const char *sub, const char *wb_room) {
    // Go field order: vpn,name,ps,ip,dtls,raw,pass,did,hash,sub,wb_room; omitempty except ip/dtls/pass
    buf_putc(b, '{');
    int first = 1;
#define COMMA() do { if (!first) buf_putc(b, ','); first = 0; } while (0)
    if (vpn && vpn[0]) { COMMA(); jsonw_kv_str(b, "vpn", vpn); }
    if (name && name[0]) { COMMA(); jsonw_kv_str(b, "name", name); }
    COMMA(); jsonw_kv_str(b, "ip", ip);
    COMMA(); jsonw_kv_int(b, "dtls", dtls);
    if (raw != 0) { COMMA(); jsonw_kv_int(b, "raw", raw); }
    COMMA(); jsonw_kv_str(b, "pass", pass);
    if (did && did[0]) { COMMA(); jsonw_kv_str(b, "did", did); }
    if (hash && hash[0]) { COMMA(); jsonw_kv_str(b, "hash", hash); }
    if (sub && sub[0]) { COMMA(); jsonw_kv_str(b, "sub", sub); }
    if (wb_room && wb_room[0]) { COMMA(); jsonw_kv_str(b, "wb_room", wb_room); }
#undef COMMA
    buf_putc(b, '}');
}

char *build_panel_link(const char *host, const char *password, const char *user_name,
                       const char *vpn_name, const char *device_id, const char *vk_hash,
                       const char *sub_url, int dtls_port, int raw_port) {
    if (!host || !host[0] || !password || !password[0]) return NULL;
    if (dtls_port <= 0) dtls_port = 56000;
    Buf j;
    buf_init(&j);
    payload_json(&j, vpn_name, user_name, host, dtls_port, raw_port, password,
                 device_id, vk_hash && vk_hash[0] ? vk_hash : NULL, sub_url, NULL);
    size_t b64len = (j.len + 2) / 3 * 4 + 4;
    char *out = xmalloc(b64len + 8);
    strcpy(out, "wdtt://");
    b64_encode((const uint8_t *)j.s, j.len, out + 7);
    buf_free(&j);
    return out;
}

char *build_colon_link(const char *host, const char *password, const char *name,
                       const char *vk_hash, int dtls, int wg, int local, int with_name, int hash_limit) {
    if (!host || !host[0] || !password || !password[0]) return NULL;
    if (dtls <= 0) dtls = 56000;
    if (wg <= 0) wg = 56001;
    Buf b;
    buf_init(&b);
    buf_printf(&b, "wdtt://%s:%d:%d:%d:%s:", host, dtls, wg, local, password);
    // hashes: comma-separated bare tokens, limited by hash_limit (0 = all)
    if (vk_hash && vk_hash[0]) {
        int emitted = 0;
        const char *p = vk_hash;
        while (*p) {
            const char *comma = strchr(p, ',');
            size_t tok = comma ? (size_t)(comma - p) : strlen(p);
            if (tok) {
                if (emitted) buf_putc(&b, ',');
                buf_append(&b, p, tok);
                emitted++;
            }
            if (!comma) break;
            p = comma + 1;
            if (hash_limit > 0 && emitted >= hash_limit) break;
        }
    }
    if (with_name) {
        const char *nm = (name && name[0]) ? name : "WDTT";
        buf_printf(&b, "#%s", nm);
    }
    return buf_detach(&b);
}

char *build_qwdtt_link(const char *host, const char *password, const char *name,
                       const char *vk_hash, int port) {
    if (!host || !host[0] || !password || !password[0]) return NULL;
    if (port <= 0) port = 9000;
    const char *nm = (name && name[0]) ? name : "WDTT";
    Buf b;
    buf_init(&b);
    buf_printf(&b, "qwdtt://config?name=%s&peer=%s&hashes=", nm, host);
    if (vk_hash && vk_hash[0]) {
        // hashes are comma-joined (bare format)
        const char *p = vk_hash;
        int first = 1;
        while (*p) {
            const char *comma = strchr(p, ',');
            size_t tok = comma ? (size_t)(comma - p) : strlen(p);
            if (tok) {
                if (!first) buf_putc(&b, ',');
                buf_append(&b, p, tok);
                first = 0;
            }
            if (!comma) break;
            p = comma + 1;
        }
    }
    buf_printf(&b, "&workers=18&port=%d&pass=%s", port, password);
    return buf_detach(&b);
}

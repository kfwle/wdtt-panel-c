#include "sub.h"
#include "db.h"
#include "links.h"
#include "users.h"
#include "util.h"
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *cfg_str(const char *field) {
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT %s FROM panel_config WHERE id=1", field);
    return db_str(sql, NULL, 0);
}

static long long cfg_int(const char *field, long long def) {
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT %s FROM panel_config WHERE id=1", field);
    return db_int(sql, def);
}

// load inbound row for link building
static int load_inbound(WdttInbound *in) {
    memset(in, 0, sizeof(*in));
    char *v;
    in->dtls_port = (int)db_int("SELECT dtls_port FROM wdtt_inbound WHERE id=1", 56000);
    in->wg_port = (int)db_int("SELECT wg_port FROM wdtt_inbound WHERE id=1", 56001);
    in->client_port = (int)db_int("SELECT client_port FROM wdtt_inbound WHERE id=1", 9000);
    in->enable = (int)db_int("SELECT enable FROM wdtt_inbound WHERE id=1", 1);
    in->raw_enable = (int)db_int("SELECT raw_enable FROM wdtt_inbound WHERE id=1", 1);
    in->raw_direct_port = (int)db_int("SELECT raw_direct_port FROM wdtt_inbound WHERE id=1", 0);
    if ((v = db_str("SELECT server_host FROM wdtt_inbound WHERE id=1", NULL, 0))) {
        snprintf(in->server_host, sizeof(in->server_host), "%s", v);
        free(v);
    }
    if ((v = db_str("SELECT tag FROM wdtt_inbound WHERE id=1", NULL, 0))) {
        snprintf(in->tag, sizeof(in->tag), "%s", v);
        free(v);
    }
    if ((v = db_str("SELECT remark FROM wdtt_inbound WHERE id=1", NULL, 0))) {
        snprintf(in->remark, sizeof(in->remark), "%s", v);
        free(v);
    }
    return 0;
}

// protocol-subscriptions.json: {"<subid>": {"up_bytes":N,"down_bytes":N,
//   "connections":[{"protocol":..,"title":..,"link":..,"wg_config":..}]}}
typedef struct {
    const char *subid;
    long long up, down;
    char **links;
    size_t n, cap;
    int found;
} BundleCtx;

static int bundle_conn(const JVal *conn, char ***links, size_t *n, size_t *cap) {
    const char *link = json_get_str(conn, "link");
    if (!link || !link[0]) return 0;
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 8;
        *links = xrealloc(*links, *cap * sizeof(char *));
    }
    (*links)[(*n)++] = xstrdup(link);
    return 0;
}

static void load_bundle(BundleCtx *ctx) {
    FILE *f = fopen("/etc/wdtt/protocol-subscriptions.json", "rb");
    if (!f) return;
    Buf data;
    buf_init(&data);
    char tmp[8192];
    size_t r;
    while ((r = fread(tmp, 1, sizeof(tmp), f)) > 0) buf_append(&data, tmp, r);
    fclose(f);
    if (!data.s) {
        buf_free(&data);
        return;
    }
    JVal *root = json_parse(data.s, data.len);
    buf_free(&data);
    if (!root || root->type != J_OBJ) {
        json_free(root);
        return;
    }
    JVal *entry = json_get(root, ctx->subid);
    if (entry && entry->type == J_OBJ) {
        ctx->found = 1;
        ctx->up = json_get_int(entry, "up_bytes", 0);
        ctx->down = json_get_int(entry, "down_bytes", 0);
        JVal *conns = json_get(entry, "connections");
        if (conns && conns->type == J_ARR)
            for (size_t i = 0; i < conns->n; i++) bundle_conn(conns->items[i], &ctx->links, &ctx->n, &ctx->cap);
    }
    json_free(root);
}

static int user_protocol_has(const char *subid, const char *protocol) {
    Buf p;
    buf_init(&p);
    users_get_protocols(subid, &p);
    int has = 0;
    JVal *arr = json_parse(p.s, p.len);
    if (arr && arr->type == J_ARR)
        for (size_t i = 0; i < arr->n; i++)
            if (arr->items[i]->type == J_STR && strcmp(arr->items[i]->str, protocol) == 0) has = 1;
    json_free(arr);
    buf_free(&p);
    return has;
}

static void sub_error(HttpRes *res, int status, const char *text) {
    http_res_text(res, status, text);
}

int sub_handle(const HttpReq *req, HttpRes *res, const char *path) {
    if (strncmp(path, "/sub/", 5) != 0) return -1;
    const char *subid = path + 5;
    if (!subid[0] || strchr(subid, '/')) {
        sub_error(res, 404, "subscription not found");
        return 0;
    }
    if (strcmp(req->method, "GET") != 0 && strcmp(req->method, "HEAD") != 0) {
        sub_error(res, 405, "method not allowed");
        return 0;
    }

    WdttUser u;
    char password[129];
    if (users_load_by_subid(subid, password, sizeof(password), &u) != 1) {
        sub_error(res, 404, "subscription not found");
        return 0;
    }
    long long now = now_ms() / 1000;
    if (u.is_deactivated ||
        (u.expires_at > 0 && u.expires_at <= now) ||
        (u.total_bytes > 0 && (u.up_bytes + u.down_bytes) >= u.total_bytes)) {
        sub_error(res, 404, "subscription not found");
        return 0;
    }

    WdttInbound in;
    load_inbound(&in);

    BundleCtx bundle = {0};
    bundle.subid = subid;
    load_bundle(&bundle);

    // build wdtt:// link
    char *sub_uri = cfg_str("sub_uri");
    Buf sub_url_b;
    buf_init(&sub_url_b);
    if (sub_uri && sub_uri[0]) {
        buf_puts(&sub_url_b, sub_uri);
        // TrimRight "/" then append
        while (sub_url_b.len > 0 && sub_url_b.s[sub_url_b.len - 1] == '/') sub_url_b.len--;
        if (sub_url_b.s) sub_url_b.s[sub_url_b.len] = 0;
        buf_printf(&sub_url_b, "/%s", subid);
    }
    free(sub_uri);

    char *link = NULL;
    int proto_wdtt = user_protocol_has(subid, "wdtt");
    fprintf(stderr, "[sub] subid=%s enable=%d has_wdtt=%d host=%s pw=%s\n",
            subid, in.enable, proto_wdtt, in.server_host, password);
    if (in.enable && proto_wdtt) {
        const char *user_name = u.comment[0] ? u.comment : (in.remark[0] ? in.remark : in.tag);
        char *title = cfg_str("sub_title");
        int raw_port = in.raw_enable && in.raw_direct_port > 0 ? in.raw_direct_port : 0;
        link = build_panel_link(in.server_host, password, user_name, title && title[0] ? title : in.tag,
                                "", u.vk_hash, sub_url_b.s ? sub_url_b.s : "", in.dtls_port, raw_port);
        free(title);
    }
    buf_free(&sub_url_b);

    // assemble links
    char **links = bundle.links;
    size_t nlinks = bundle.n;
    size_t lcap = bundle.cap;
    if (link) {
        // wdtt link goes FIRST
        if (nlinks == lcap) {
            lcap = lcap ? lcap * 2 : 8;
            links = xrealloc(links, lcap * sizeof(char *));
        }
        memmove(links + 1, links, nlinks * sizeof(char *));
        links[0] = link;
        nlinks++;
    }
    fprintf(stderr, "[sub] link=%s nlinks=%zu\n", link ? link : "(null)", nlinks);
    if (nlinks == 0) {
        sub_error(res, 500, "failed to build link");
        return 0;
    }

    Buf body;
    buf_init(&body);
    for (size_t i = 0; i < nlinks; i++) {
        if (i) buf_putc(&body, '\n');
        buf_puts(&body, links[i]);
        free(links[i]);
    }
    free(links);

    // headers
    long long show_info = cfg_int("sub_show_info", 1);
    if (show_info) {
        Buf h;
        buf_init(&h);
        buf_printf(&h, "upload=%lld; download=%lld; total=%lld; expire=%lld",
                   u.up_bytes + bundle.up, u.down_bytes + bundle.down, u.total_bytes,
                   u.expires_at > 0 ? u.expires_at : 0);
        http_res_set_header(res, "Subscription-Userinfo", h.s);
        buf_free(&h);
    }
    char *title = cfg_str("sub_title");
    if (title && title[0]) {
        size_t b64len = strlen(title) * 2;
        char *b64 = xmalloc(b64len + 16);
        b64_encode((const uint8_t *)title, strlen(title), b64);
        Buf h;
        buf_init(&h);
        buf_printf(&h, "base64:%s", b64);
        http_res_set_header(res, "Profile-Title", h.s);
        buf_free(&h);
        free(b64);
    }
    free(title);
    char *support = cfg_str("sub_support_url");
    if (support && support[0]) http_res_set_header(res, "Profile-Web-Page-Url", support);
    free(support);
    char *profile = cfg_str("sub_profile_url");
    if (profile && profile[0]) http_res_set_header(res, "Profile-Home-Page-Url", profile);
    free(profile);
    char *announce = cfg_str("sub_announce");
    if (announce && announce[0]) {
        size_t blen = strlen(announce) * 2;
        char *b64 = xmalloc(blen + 16);
        b64_encode((const uint8_t *)announce, strlen(announce), b64);
        Buf h;
        buf_init(&h);
        buf_printf(&h, "base64:%s", b64);
        http_res_set_header(res, "Announce", h.s);
        buf_free(&h);
        free(b64);
    }
    free(announce);
    http_res_set_header(res, "Content-Disposition", "attachment; filename=wdtt");

    // encrypt?
    const char *fmt = qlist_get(&req->params, "format");
    int force_raw = fmt && (!strcmp(fmt, "raw") || !strcmp(fmt, "sub") || !strcmp(fmt, "base64"));
    long long encrypt = cfg_int("sub_encrypt", 1);
    if (encrypt && !force_raw) {
        char *b64 = xmalloc(body.len * 2 + 8);
        b64_encode((const uint8_t *)body.s, body.len, b64);
        buf_clear(&body);
        buf_puts(&body, b64);
        free(b64);
    }

    res->content_type = "text/plain; charset=utf-8";
    buf_append(&res->body, body.s, body.len);
    buf_free(&body);
    return 0;
}

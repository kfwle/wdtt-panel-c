#include "app.h"
#include "db.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

static AppCfg g_app;

// ---------- sessions ----------
typedef struct {
    char token[65];      // 32 bytes hex
    long long expires_ms;
    char ip[64];
} Session;

#define MAX_SESSIONS 64
static Session g_sessions[MAX_SESSIONS];
static pthread_mutex_t g_sess_mu = PTHREAD_MUTEX_INITIALIZER;

#define COOKIE_NAME "WDTT_SESS"

static Session *sess_create(const char *ip) {
    pthread_mutex_lock(&g_sess_mu);
    long long now = now_ms();
    Session *slot = NULL;
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (!g_sessions[i].token[0] || g_sessions[i].expires_ms < now) {
            slot = &g_sessions[i];
            break;
        }
    if (!slot) slot = &g_sessions[0]; // single-admin panel: overwrite is fine
    memset(slot, 0, sizeof(*slot));
    rand_hex(slot->token, 32);
    slot->expires_ms = now + 12LL * 3600 * 1000;
    snprintf(slot->ip, sizeof(slot->ip), "%s", ip ? ip : "");
    pthread_mutex_unlock(&g_sess_mu);
    return slot;
}

static Session *sess_find(const char *token) {
    if (!token || strlen(token) != 64) return NULL;
    pthread_mutex_lock(&g_sess_mu);
    long long now = now_ms();
    Session *found = NULL;
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_sessions[i].token[0] && strcmp(g_sessions[i].token, token) == 0) {
            if (g_sessions[i].expires_ms >= now) found = &g_sessions[i];
            break;
        }
    pthread_mutex_unlock(&g_sess_mu);
    return found;
}

static void sess_destroy(const char *token) {
    pthread_mutex_lock(&g_sess_mu);
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_sessions[i].token[0] && strcmp(g_sessions[i].token, token) == 0)
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
    pthread_mutex_unlock(&g_sess_mu);
}

// token access for api.c
const char *app_session_token(const HttpReq *req) {
    const char *cookie = hlist_get(&req->headers, "Cookie");
    if (!cookie) return NULL;
    const char *p = strstr(cookie, COOKIE_NAME "=");
    if (!p) return NULL;
    p += strlen(COOKIE_NAME) + 1;
    static _Thread_local char tok[65];
    size_t i = 0;
    while (p[i] && p[i] != ';' && p[i] != ' ' && i < 64) {
        tok[i] = p[i];
        i++;
    }
    tok[i] = 0;
    return sess_find(tok) ? tok : NULL;
}

// server mode for api.c (Secure cookie flag)
int app_is_https(void) {
    return g_app.https;
}

// api.c entry points: create session, returns 0 ok; token copied to token_out
int sess_create_pub(const char *ip, char *token_out, size_t tcap) {
    Session *s = sess_create(ip);
    if (!s) return -1;
    if (token_out && tcap) snprintf(token_out, tcap, "%s", s->token);
    return 0;
}

void sess_destroy_pub(const char *token) {
    sess_destroy(token);
}

void sess_destroy_all(void) {
    pthread_mutex_lock(&g_sess_mu);
    memset(g_sessions, 0, sizeof(g_sessions));
    pthread_mutex_unlock(&g_sess_mu);
}

// ---------- api helpers ----------
void api_error(HttpRes *res, int status, const char *msg) {
    Buf b;
    buf_init(&b);
    buf_puts(&b, "{\"error\":");
    jsonw_str(&b, msg ? msg : "error");
    buf_puts(&b, "}");
    http_res_json(res, status, b.s);
    buf_free(&b);
}

// ---------- handlers ----------
// login/logout/subscription are served by api.c (api_public)
int api_public(const HttpReq *req, HttpRes *res, const char *path);
void api_dispatch(const HttpReq *req, HttpRes *res, const char *path);

// router: path is already normalized (no /wdtt prefix)
static void app_route(const HttpReq *req, HttpRes *res, const char *path) {
    if (!strcmp(path, "/") || !strcmp(path, "/panel") || !strcmp(path, "/panel/") ||
        !strcmp(path, "/login")) {
        // embedded SPA (handles login itself)
        extern const char UI_HTML[];
        res->content_type = "text/html; charset=utf-8";
        buf_append(&res->body, UI_HTML, strlen(UI_HTML));
        return;
    }
    if (api_public(req, res, path)) return;
    if (!strncmp(path, "/api/", 5)) return api_dispatch(req, res, path);
    api_error(res, 404, "not found");
}

// entry: strip optional /wdtt prefix (nginx proxies /wdtt/* to us), add headers
void app_handle(const HttpReq *req, HttpRes *res) {
    http_res_set_header(res, "X-Content-Type-Options", "nosniff");
    http_res_set_header(res, "X-Frame-Options", "DENY");
    http_res_set_header(res, "Referrer-Policy", "no-referrer");
    http_res_set_header(res, "Cache-Control", "no-store");

    char pathbuf[512];
    snprintf(pathbuf, sizeof(pathbuf), "%s", req->path);
    if (!strncmp(pathbuf, "/wdtt/", 6)) {
        memmove(pathbuf, pathbuf + 5, strlen(pathbuf + 5) + 1); // "/wdtt/api/x" -> "/api/x"
    } else if (!strcmp(pathbuf, "/wdtt")) {
        snprintf(pathbuf, sizeof(pathbuf), "/");
    }
    app_route(req, res, pathbuf);
}

int app_init(const AppCfg *cfg, char *err, size_t errcap) {
    g_app = *cfg;
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/panel.db", cfg->config_dir);
    if (access(cfg->config_dir, F_OK) != 0) {
        if (mkdir(cfg->config_dir, 0700) != 0 && errno != EEXIST) {
            snprintf(err, errcap, "mkdir %s: %s", cfg->config_dir, strerror(errno));
            return -1;
        }
    }
    if (db_open(dbpath, err, errcap) != 0) return -1;
    return 0;
}

#include "api.h"
#include "app.h"
#include "auth.h"
#include "db.h"
#include "links.h"
#include "proto.h"
#include "sub.h"
#include "users.h"
#include "util.h"
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---------- helpers ----------
static void ok_obj(HttpRes *res, const char *obj_json) {
    Buf b;
    buf_init(&b);
    buf_printf(&b, "{\"success\":true,\"obj\":%s}", obj_json ? obj_json : "null");
    http_res_json(res, 200, b.s);
    buf_free(&b);
}

static void ok_null(HttpRes *res) {
    http_res_json(res, 200, "{\"success\":true,\"obj\":null}");
}

static void fail(HttpRes *res, const char *msg, int status) {
    Buf b;
    buf_init(&b);
    buf_puts(&b, "{\"success\":false,\"msg\":");
    jsonw_str(&b, msg);
    buf_puts(&b, "}");
    http_res_json(res, status, b.s);
    buf_free(&b);
}

static JVal *body_json(const HttpReq *req) {
    if (!req->body.len || !req->body.s) return NULL;
    return json_parse(req->body.s, req->body.len);
}

// ---------- sessions & CSRF ----------
static void sess_set_cookie_hdr(HttpRes *res, const char *token) {
    Buf b;
    buf_init(&b);
    buf_printf(&b, "WDTT_SESS=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200%s", token,
               app_is_https() ? "; Secure" : "");
    http_res_set_header(res, "Set-Cookie", b.s);
    buf_free(&b);
}

static void sess_clear_cookie_hdr(HttpRes *res) {
    http_res_set_header(res, "Set-Cookie", "WDTT_SESS=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
}

// ---------- login ----------
static void h_login(const HttpReq *req, HttpRes *res) {
    if (!auth_rate_allow(req->client_ip)) {
        fail(res, "слишком много попыток входа; подождите 15 минут", 429);
        return;
    }
    JVal *v = body_json(req);
    const char *username = v ? json_get_str(v, "username") : NULL;
    const char *password = v ? json_get_str(v, "password") : NULL;
    if (!username || !password) {
        json_free(v);
        fail(res, "укажите логин и пароль", 400);
        return;
    }
    char *db_user = auth_get_username();
    char *hash = auth_get_password_hash();
    int user_ok = username[0] && db_user && strcmp(username, db_user) == 0;
    // constant work regardless of username correctness (anti-enumeration)
    static const char *DUMMY = "$wdttpanel$1$210000$00000000000000000000000000000000$"
                               "0000000000000000000000000000000000000000000000000000000000000000";
    int pw_ok = auth_verify_password(password, hash && hash[0] ? hash : DUMMY);
    if (!user_ok) auth_verify_password(password, DUMMY);
    json_free(v);
    free(db_user);
    free(hash);
    if (!user_ok || !pw_ok) {
        auth_rate_fail(req->client_ip);
        fail(res, "неверный логин или пароль", 200); // original returns 200 with success:false
        return;
    }
    auth_rate_reset(req->client_ip);
    char token[65];
    if (sess_create_pub(req->client_ip, token, sizeof(token)) != 0) {
        fail(res, "internal error", 500);
        return;
    }
    sess_set_cookie_hdr(res, token);
    Buf b;
    buf_init(&b);
    buf_printf(&b, "{\"success\":true,\"obj\":{\"username\":\"admin\",\"csrf\":\"%s\"}}", token);
    http_res_json(res, 200, b.s);
    buf_free(&b);
}

static void h_logout(const HttpReq *req, HttpRes *res) {
    const char *tok = app_session_token(req);
    if (tok) sess_destroy_pub(tok);
    sess_clear_cookie_hdr(res);
    ok_null(res);
}

static void h_me(const HttpReq *req, HttpRes *res) {
    char *user = auth_get_username();
    // csrf = session token (per-session random, rotation-safe)
    const char *tok = app_session_token(req);
    Buf b;
    buf_init(&b);
    buf_printf(&b, "{\"success\":true,\"obj\":{\"username\":");
    jsonw_str(&b, user ? user : "admin");
    buf_printf(&b, ",\"csrf\":\"%s\"}}", tok ? tok : "");
    http_res_json(res, 200, b.s);
    buf_free(&b);
    free(user);
}

// ---------- users ----------
typedef struct {
    Buf *b;
    int first;
} DevList;

static int dev_row_cb(sqlite3_stmt *st, void *ud) {
    DevList *dl = ud;
    const unsigned char *v = sqlite3_column_text(st, 0);
    if (!v) return 0;
    if (!dl->first) buf_putc(dl->b, ',');
    jsonw_str(dl->b, (const char *)v);
    dl->first = 0;
    return 0;
}

static void user_json_row(Buf *b, const WdttUser *u, const char *main_password) {
    int is_main = main_password && strcmp(u->password, main_password) == 0;
    char *sub_uri = db_str("SELECT sub_uri FROM panel_config WHERE id=1", NULL, 0);
    buf_putc(b, '{');
    jsonw_kv_str(b, "password", u->password);
    buf_putc(b, ',');
    jsonw_kv_str(b, "comment", u->comment);
    buf_putc(b, ',');
    jsonw_kv_int(b, "max_devices", u->max_devices);
    buf_putc(b, ',');
    jsonw_kv_int(b, "expires_at", u->expires_at);
    buf_putc(b, ',');
    jsonw_kv_int(b, "down_bytes", u->down_bytes);
    buf_putc(b, ',');
    jsonw_kv_int(b, "up_bytes", u->up_bytes);
    buf_putc(b, ',');
    jsonw_kv_int(b, "total_bytes", u->total_bytes);
    buf_printf(b, ",\"max_down_mbps\":%.3f", u->max_down_mbps);
    buf_printf(b, ",\"max_up_mbps\":%.3f", u->max_up_mbps);
    buf_printf(b, ",\"active\":%s", u->is_deactivated ? "false" : "true");
    buf_putc(b, ',');
    jsonw_kv_str(b, "ports", u->ports);
    buf_putc(b, ',');
    jsonw_kv_str(b, "vk_hash", u->vk_hash);
    buf_putc(b, ',');
    jsonw_kv_str(b, "sub_id", u->sub_id);
    buf_printf(b, ",\"is_main\":%s", is_main ? "true" : "false");
    buf_putc(b, ',');
    jsonw_kv_int(b, "last_seen_at", u->last_seen_at);
    // sub_url
    buf_putc(b, ',');
    if (sub_uri && sub_uri[0]) {
        Buf su;
        buf_init(&su);
        buf_puts(&su, sub_uri);
        while (su.len && su.s[su.len - 1] == '/') su.len--;
        if (su.s) su.s[su.len] = 0;
        buf_puts(&su, "/");
        buf_puts(&su, u->sub_id);
        jsonw_kv_str(b, "sub_url", su.s ? su.s : "");
        buf_free(&su);
    } else {
        jsonw_kv_str(b, "sub_url", "");
    }
    // device_ids from wdtt_user_devices
    char *sql = sqlite3_mprintf(
        "SELECT device_id FROM wdtt_user_devices WHERE password=%Q ORDER BY sort_order, device_id",
        u->password);
    char derr[128];
    char *errp = derr;
    (void)errp;
    buf_puts(b, ",\"device_ids\":[");
    // inline scan via db_str-like helper: use db_query closure
    DevList dl = {b, 0};
    db_query(sql, dev_row_cb, &dl, derr, sizeof(derr));
    sqlite3_free(sql);
    buf_puts(b, "]");
    // inbounds from vpn_user_inbounds
    Buf prot;
    buf_init(&prot);
    if (u->sub_id[0]) users_get_protocols(u->sub_id, &prot);
    buf_putc(b, ',');
    jsonw_kv_raw(b, "inbounds", prot.s ? prot.s : "[]");
    buf_free(&prot);
    buf_putc(b, '}');
    free(sub_uri);
}

typedef struct {
    Buf *arr;
    const char *main_password;
    int n;
} ListCtx;

static int list_cb(const WdttUser *u, void *ud) {
    ListCtx *ctx = ud;
    if (ctx->n) buf_putc(ctx->arr, ',');
    user_json_row(ctx->arr, u, ctx->main_password);
    ctx->n++;
    return 0;
}

static void h_users_list(const HttpReq *req, HttpRes *res) {
    (void)req;
    char *main_password = users_main_password();
    Buf arr;
    buf_init(&arr);
    ListCtx ctx = {&arr, main_password, 0};
    users_each(list_cb, &ctx);
    Buf b;
    buf_init(&b);
    buf_printf(&b, "{\"users\":[%s],\"max_users\":%d,\"active_users\":%d}",
               arr.s ? arr.s : "", users_max_users(), users_count_active());
    buf_free(&arr);
    free(main_password);
    ok_obj(res, b.s);
    buf_free(&b);
}

static int json_str_arr(JVal *v, const char *key, char ***out, size_t *n) {
    JVal *arr = json_get(v, key);
    if (!arr || arr->type != J_ARR) return 0;
    *n = arr->n;
    *out = xmalloc((arr->n + 1) * sizeof(char *));
    for (size_t i = 0; i < arr->n; i++)
        (*out)[i] = (arr->items[i]->type == J_STR) ? xstrdup(arr->items[i]->str) : xstrdup("");
    (*out)[arr->n] = NULL;
    return 1;
}

static void fill_user_from_json(WdttUser *u, JVal *v, int *active_set) {
    const char *s;
    if ((s = json_get_str(v, "password"))) snprintf(u->password, sizeof(u->password), "%.128s", s);
    if ((s = json_get_str(v, "comment"))) snprintf(u->comment, sizeof(u->comment), "%.255s", s);
    if ((s = json_get_str(v, "device_id"))) snprintf(u->device_id, sizeof(u->device_id), "%.129s", s);
    if ((s = json_get_str(v, "ports"))) snprintf(u->ports, sizeof(u->ports), "%.63s", s);
    if ((s = json_get_str(v, "vk_hash"))) snprintf(u->vk_hash, sizeof(u->vk_hash), "%.511s", s);
    if (json_get(v, "max_devices")) u->max_devices = (int)json_get_int(v, "max_devices", u->max_devices);
    if (json_get(v, "expires_at")) u->expires_at = json_get_int(v, "expires_at", u->expires_at);
    if (json_get(v, "total_gb")) {
        double gb = json_get(v, "total_gb")->num;
        u->total_bytes = gb > 0 ? (long long)(gb * 1024.0 * 1024.0 * 1024.0) : 0;
    }
    if (json_get(v, "max_down_mbps")) u->max_down_mbps = json_get(v, "max_down_mbps")->num;
    if (json_get(v, "max_up_mbps")) u->max_up_mbps = json_get(v, "max_up_mbps")->num;
    JVal *act = json_get(v, "active");
    if (act) {
        int a = (act->type == J_BOOL) ? act->boolean : (int)act->num;
        u->is_deactivated = a ? 0 : 1;
        *active_set = 1;
    }
}

static void h_users_add(const HttpReq *req, HttpRes *res) {
    JVal *v = body_json(req);
    if (!v) {
        fail(res, "некорректный JSON", 400);
        return;
    }
    WdttUser u = {0};
    int active_set = 0;
    fill_user_from_json(&u, v, &active_set);
    int inbounds_set = 0;
    char **inbounds = NULL;
    size_t ninb = 0;
    inbounds_set = json_str_arr(v, "inbounds", &inbounds, &ninb);
    long long bulk_count = json_get_int(v, "count", 1);
    json_free(v); // pointers into v must not be used below

    // validate protocols
    if (inbounds_set) {
        for (size_t i = 0; i < ninb; i++) {
            const char *valid[] = {"wdtt", "qwdtt", "wdtt-plus", "csqtt-2.1.9", "csqtt-2.5.0", "freeturn"};
            int ok = 0;
            for (size_t k = 0; k < 6; k++)
                if (strcmp(inbounds[i], valid[k]) == 0) ok = 1;
            if (!ok) {
                for (size_t k = 0; k < ninb; k++) free(inbounds[k]);
                free(inbounds);
                fail(res, "некорректный инбаунд", 400);
                return;
            }
        }
    }

    // bulk mode
    if (!u.password[0] && !u.comment[0] && !u.expires_at && !u.total_bytes && !active_set) {
        long long count = bulk_count;
        if (count < 1) count = 1;
        if (count > 100) count = 100;
        int max = users_max_users();
        int have = users_count_active();
        if (have + (int)count > max) count = (long long)(max - have);
        if (count < 1) {
            for (size_t k = 0; k < ninb; k++) free(inbounds[k]);
            free(inbounds);
            fail(res, "достигнут максимум активных паролей (wdtt_inbound.max_users)", 400);
            return;
        }
        Buf arr;
        buf_init(&arr);
        int created = 0;
        for (int i = 0; i < (int)count; i++) {
            WdttUser nu = {0};
            char *pw = gen_password();
            snprintf(nu.password, sizeof(nu.password), "%s", pw);
            free(pw);
            if (users_upsert(&nu) == 0) {
                if (created) buf_putc(&arr, ',');
                jsonw_str(&arr, nu.password);
                created++;
            }
        }
        for (size_t k = 0; k < ninb; k++) free(inbounds[k]);
        free(inbounds);
        Buf b;
        buf_init(&b);
        buf_printf(&b, "{\"passwords\":[%s]}", arr.s ? arr.s : "");
        buf_free(&arr);
        ok_obj(res, b.s);
        buf_free(&b);
        return;
    }

    if (!u.password[0]) {
        char *pw = gen_password();
        snprintf(u.password, sizeof(u.password), "%s", pw);
        free(pw);
    }
    if (strlen(u.password) > 128) {
        for (size_t k = 0; k < ninb; k++) free(inbounds[k]);
        free(inbounds);
        fail(res, "пароль должен быть от 1 до 128 символов", 400);
        return;
    }
    if (users_count_active() >= users_max_users()) {
        for (size_t k = 0; k < ninb; k++) free(inbounds[k]);
        free(inbounds);
        fail(res, "достигнут максимум активных паролей (wdtt_inbound.max_users)", 400);
        return;
    }
    WdttUser existing;
    if (users_load(u.password, &existing) == 1) {
        for (size_t k = 0; k < ninb; k++) free(inbounds[k]);
        free(inbounds);
        fail(res, "пароль уже существует", 400);
        return;
    }
    if (users_upsert(&u) != 0) {
        for (size_t k = 0; k < ninb; k++) free(inbounds[k]);
        free(inbounds);
        fail(res, "ошибка базы данных", 500);
        return;
    }
    if (inbounds_set && u.sub_id[0]) {
        // build JSON array string
        Buf pa;
        buf_init(&pa);
        buf_putc(&pa, '[');
        for (size_t i = 0; i < ninb; i++) {
            if (i) buf_putc(&pa, ',');
            jsonw_str(&pa, inbounds[i]);
        }
        buf_putc(&pa, ']');
        users_set_protocols(u.sub_id, pa.s);
        buf_free(&pa);
    }
    if (u.device_id[0]) {
        const char *devs[2] = {u.device_id, NULL};
        users_set_devices(u.password, devs);
    }
    // push to data plane
    char err[256] = "";
    const char *devs[2] = {u.device_id[0] ? u.device_id : NULL, NULL};
    admin_push_user_update(NULL, u.password, &u, u.device_id[0] ? devs : NULL,
                           u.device_id[0] ? 1 : 0, err, sizeof(err));
    for (size_t i = 0; i < ninb; i++) free(inbounds[i]);
    free(inbounds);
    Buf b;
    buf_init(&b);
    buf_puts(&b, "{\"password\":");
    jsonw_str(&b, u.password);
    buf_puts(&b, "}");
    ok_obj(res, b.s);
    buf_free(&b);
}

static void h_users_update(const HttpReq *req, HttpRes *res) {
    JVal *v = body_json(req);
    if (!v) {
        fail(res, "некорректный JSON", 400);
        return;
    }
    const char *old_password_p = json_get_str(v, "old_password");
    char old_password[130] = "";
    if (!old_password_p || !old_password_p[0]) {
        json_free(v);
        fail(res, "укажите old_password", 400);
        return;
    }
    snprintf(old_password, sizeof(old_password), "%.129s", old_password_p);
    WdttUser u;
    if (users_load(old_password, &u) != 1) {
        json_free(v);
        fail(res, "пользователь не найден", 400);
        return;
    }
    char *main_password = users_main_password();
    int is_main = main_password && strcmp(old_password, main_password) == 0;
    free(main_password);
    int active_set = 0;
    fill_user_from_json(&u, v, &active_set);
    // fill_user_from_json also overwrites u.password from "password" (the rename
    // target) — restore it: u must stay keyed to old_password until the rename
    snprintf(u.password, sizeof(u.password), "%s", old_password);
    const char *new_password = json_get_str(v, "new_password");
    new_password = new_password ? new_password : json_get_str(v, "password");
    char newpw[129] = "";
    if (new_password && new_password[0]) snprintf(newpw, sizeof(newpw), "%.128s", new_password);

    // device_ids management
    int manage_devices = 0;
    char **device_ids = NULL;
    size_t ndev = 0;
    if (json_str_arr(v, "device_ids", &device_ids, &ndev) || json_get(v, "device_id")) manage_devices = 1;
    if (!device_ids && manage_devices) {
        const char *d = json_get_str(v, "device_id");
        device_ids = xmalloc(2 * sizeof(char *));
        device_ids[0] = d && d[0] ? xstrdup(d) : NULL;
        device_ids[1] = NULL;
        if (!device_ids[0]) {
            free(device_ids);
            device_ids = NULL;
        }
    }
    int inbounds_set = 0;
    char **inbounds = NULL;
    size_t ninb = 0;
    inbounds_set = json_str_arr(v, "inbounds", &inbounds, &ninb);
    json_free(v); // pointers into v must not be used below

    if (is_main && !newpw[0]) {
        // main user edits (comment/vk/inbounds) allowed
        if (inbounds_set && u.sub_id[0]) {
            Buf pa;
            buf_init(&pa);
            buf_putc(&pa, '[');
            for (size_t i = 0; i < ninb; i++) {
                if (i) buf_putc(&pa, ',');
                jsonw_str(&pa, inbounds[i]);
            }
            buf_putc(&pa, ']');
            users_set_protocols(u.sub_id, pa.s);
            buf_free(&pa);
        }
        users_upsert(&u);
        char err[256];
        admin_push_user_update(old_password, old_password, &u, NULL, 0, err, sizeof(err));
        ok_null(res);
        return;
    }

    if (newpw[0] && strcmp(newpw, u.password) != 0) {
        // atomic rename: keeps sub_id, devices FK and vpn_user_inbounds intact
        if (users_load(newpw, &((WdttUser){0})) == 1) {
            fail(res, "пароль уже существует", 400);
            return;
        }
        if (users_rename(old_password, newpw) != 0) {
            fail(res, "ошибка переименования", 500);
            return;
        }
        snprintf(u.password, sizeof(u.password), "%s", newpw);
    } else {
        users_upsert(&u);
    }
    if (manage_devices)
        users_set_devices(u.password, (const char *const *)device_ids);
    if (inbounds_set && u.sub_id[0]) {
        Buf pa;
        buf_init(&pa);
        buf_putc(&pa, '[');
        for (size_t i = 0; i < ninb; i++) {
            if (i) buf_putc(&pa, ',');
            jsonw_str(&pa, inbounds[i]);
        }
        buf_putc(&pa, ']');
        users_set_protocols(u.sub_id, pa.s);
        buf_free(&pa);
    }
    char err[256];
    admin_push_user_update(old_password, u.password, &u,
                           (const char *const *)device_ids, manage_devices, err, sizeof(err));
    if (device_ids) {
        for (size_t k = 0; device_ids[k]; k++) free(device_ids[k]);
        free(device_ids);
    }
    if (inbounds) {
        for (size_t k = 0; k < ninb; k++) free(inbounds[k]);
        free(inbounds);
    }
    ok_null(res);
}

static void h_users_delete(const HttpReq *req, HttpRes *res) {
    JVal *v = body_json(req);
    const char *password_p = v ? json_get_str(v, "password") : NULL;
    char password[130] = "";
    if (!password_p || !password_p[0]) {
        json_free(v);
        fail(res, "укажите password", 400);
        return;
    }
    snprintf(password, sizeof(password), "%.129s", password_p);
    json_free(v); // pointers into v must not be used below
    char *main_password = users_main_password();
    if (main_password && strcmp(password, main_password) == 0) {
        free(main_password);
        fail(res, "Основную подписку удалить нельзя", 400);
        return;
    }
    free(main_password);
    users_delete(password);
    char err[256];
    admin_push_user_delete(password, err, sizeof(err));
    ok_null(res);
}

static void h_users_reset_traffic(const HttpReq *req, HttpRes *res) {
    JVal *v = body_json(req);
    const char *password_p = v ? json_get_str(v, "password") : NULL;
    char password[130] = "";
    if (!password_p || !password_p[0]) {
        json_free(v);
        fail(res, "укажите password", 400);
        return;
    }
    snprintf(password, sizeof(password), "%.129s", password_p);
    json_free(v); // pointers into v must not be used below
    WdttUser u;
    if (users_load(password, &u) != 1) {
        fail(res, "пользователь не найден", 400);
        return;
    }
    users_reset_traffic(password);
    // protocols.py reset-user-traffic
    if (u.sub_id[0]) {
        char op[300];
        snprintf(op, sizeof(op), "{\"op\":\"reset-user-traffic\",\"sub_id\":\"%s\"}", u.sub_id);
        char err[256];
        proto_op(op, err, sizeof(err));
    }
    ok_null(res);
}

// ---------- passwords ----------
static void h_password_main(const HttpReq *req, HttpRes *res) {
    JVal *v = body_json(req);
    const char *password_p = v ? json_get_str(v, "password") : NULL;
    char password[130] = "";
    if (!password_p || !password_p[0] || strlen(password_p) > 128) {
        json_free(v);
        fail(res, "пароль должен быть от 1 до 128 символов", 400);
        return;
    }
    snprintf(password, sizeof(password), "%s", password_p);
    json_free(v); // pointers into v must not be used below
    char *old = users_main_password();
    if (users_set_main_password(password) != 0) {
        free(old);
        fail(res, "ошибка базы данных", 500);
        return;
    }
    WdttUser u;
    if (users_load(password, &u) == 1) {
        char err[256];
        admin_push_user_update(old, password, &u, NULL, 0, err, sizeof(err));
    }
    free(old);
    ok_null(res);
}

static void h_password_panel(const HttpReq *req, HttpRes *res) {
    JVal *v = body_json(req);
    const char *old_password = v ? json_get_str(v, "old_password") : NULL;
    const char *new_password = v ? json_get_str(v, "new_password") : NULL;
    const char *new_username = v ? json_get_str(v, "new_username") : NULL;
    if (!old_password || !new_password || !new_password[0] || strlen(new_password) < 6) {
        json_free(v);
        fail(res, "новый пароль должен быть не менее 6 символов", 400);
        return;
    }
    char old_pw[130], new_pw[130], new_user[130] = "";
    snprintf(old_pw, sizeof(old_pw), "%.129s", old_password);
    snprintf(new_pw, sizeof(new_pw), "%.129s", new_password);
    if (new_username && new_username[0]) snprintf(new_user, sizeof(new_user), "%.129s", new_username);
    char *hash = auth_get_password_hash();
    if (!auth_verify_password(old_pw, hash)) {
        free(hash);
        json_free(v);
        fail(res, "неверный текущий пароль", 400);
        return;
    }
    free(hash);
    json_free(v); // pointers into v must not be used below
    char *newhash = auth_hash_password(new_pw);
    if (!newhash) {
        fail(res, "internal error", 500);
        return;
    }
    auth_set_credentials(new_user[0] ? new_user : NULL, newhash);
    free(newhash);
    // invalidate all sessions (logout everywhere)
    extern void sess_destroy_all(void);
    sess_destroy_all();
    ok_null(res);
}

// ---------- protocols ----------
static void h_protocols_get(const HttpReq *req, HttpRes *res) {
    (void)req;
    char err[256];
    char *out = proto_op("{\"op\":\"list\"}", err, sizeof(err));
    if (!out) {
        fail(res, err, 502);
        return;
    }
    // relay raw {"success":..} JSON
    http_res_json(res, 200, out);
    free(out);
}

static void h_protocols_post(const HttpReq *req, HttpRes *res) {
    JVal *v = body_json(req);
    if (!v) {
        fail(res, "некорректный JSON", 400);
        return;
    }
    const char *op_p = json_get_str(v, "op");
    const char *protocol_p = json_get_str(v, "protocol");
    char op[32] = "", protocol[64] = "";
    if (!op_p || !protocol_p || !protocol_p[0] ||
        !(strcmp(op_p, "create") == 0 || strcmp(op_p, "delete") == 0 ||
          strcmp(op_p, "enable") == 0 || strcmp(op_p, "disable") == 0 || strcmp(op_p, "update") == 0)) {
        json_free(v);
        fail(res, "некорректный op", 400);
        return;
    }
    snprintf(op, sizeof(op), "%.31s", op_p);
    snprintf(protocol, sizeof(protocol), "%.63s", protocol_p);
    json_free(v); // pointers into v must not be used below
    if (strcmp(op, "create") == 0 || strcmp(op, "delete") == 0 ||
        strcmp(op, "enable") == 0 || strcmp(op, "disable") == 0) {
        // body size cap 64KB enforced by http layer
        char opjson[512];
        if (strcmp(op, "create") == 0) {
            char host[256];
            char *sh = db_str("SELECT server_host FROM wdtt_inbound WHERE id=1", NULL, 0);
            snprintf(host, sizeof(host), "%s", (sh && sh[0]) ? sh : "127.0.0.1");
            free(sh);
            snprintf(opjson, sizeof(opjson),
                     "{\"op\":\"create\",\"protocol\":\"%s\",\"host\":\"%s\"}", protocol, host);
        } else {
            snprintf(opjson, sizeof(opjson),
                     "{\"op\":\"%s\",\"protocol\":\"%s\"}", op, protocol);
        }
        char err[256];
        char *out = proto_op(opjson, err, sizeof(err));
        if (!out) {
            fail(res, err, 502);
            return;
        }
        // wdtt enable/disable flips inbound enable
        if (strcmp(protocol, "wdtt") == 0 &&
            (strcmp(op, "enable") == 0 || strcmp(op, "disable") == 0)) {
            char sql[128];
            snprintf(sql, sizeof(sql), "UPDATE wdtt_inbound SET enable=%d WHERE id=1",
                     strcmp(op, "enable") == 0 ? 1 : 0);
            char derr[128];
            db_exec(sql, derr, sizeof(derr));
            proto_reload_dataplane(derr, sizeof(derr));
        }
        http_res_json(res, 200, out);
        free(out);
        return;
    }
    fail(res, "update через UI не поддерживается в C-версии; правьте через protocols.py", 400);
}

// ---------- status ----------
// systemctl forks are expensive; cache the whole /api/status for 2s
static pthread_mutex_t g_status_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_status_cache[16384];
static long long g_status_cache_ms = 0;

static void h_status(const HttpReq *req, HttpRes *res) {
    (void)req;
    pthread_mutex_lock(&g_status_mu);
    long long now = now_ms();
    if (g_status_cache[0] && now - g_status_cache_ms < 2000) {
        http_res_json(res, 200, g_status_cache);
        pthread_mutex_unlock(&g_status_mu);
        return;
    }
    pthread_mutex_unlock(&g_status_mu);

    Buf b;
    buf_init(&b);
    buf_puts(&b, "{\"success\":true,\"obj\":{\"services\":{");
    const char *units[] = {"wdtt", "wdtt-xray", "wdttpanel", "wdtt-protocol-watch"};
    for (size_t i = 0; i < 4; i++) {
        if (i) buf_putc(&b, ',');
        buf_printf(&b, "\"%s\":%s", units[i], svc_active(units[i]) ? "true" : "false");
    }
    buf_puts(&b, "},\"protocols\":{");
    const char *protos[] = {"wdtt", "qwdtt", "wdtt-plus", "csqtt-2.1.9", "csqtt-2.5.0", "freeturn"};
    for (size_t i = 0; i < 6; i++) {
        char unit[64];
        if (i) buf_putc(&b, ',');
        if (strcmp(protos[i], "wdtt") == 0) {
            buf_printf(&b, "\"wdtt\":%s", svc_active("wdtt") ? "true" : "false");
            continue;
        }
        snprintf(unit, sizeof(unit), "wdtt-protocol@%s", protos[i]);
        buf_printf(&b, "\"%s\":%s", protos[i], svc_active(unit) ? "true" : "false");
    }
    buf_puts(&b, "}");
    // server.log stats (last JSON line)
    Buf stats;
    buf_init(&stats);
    FILE *f = fopen("/etc/wdtt/server.log", "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        if (size > 65536) fseek(f, -65536, SEEK_END);
        else fseek(f, 0, SEEK_SET);
        Buf data;
        buf_init(&data);
        char tmp[4096];
        size_t r;
        while ((r = fread(tmp, 1, sizeof(tmp), f)) > 0) buf_append(&data, tmp, r);
        fclose(f);
        if (data.s) {
            // find start of last line that begins with '{'
            const char *last = NULL;
            for (long i = (long)data.len - 2; i >= 0; i--) {
                if (data.s[i] == '\n' && data.s[i + 1] == '{') {
                    last = data.s + i + 1;
                    break;
                }
            }
            if (!last && data.s[0] == '{') last = data.s;
            if (last) {
                const char *nl = strchr(last, '\n');
                size_t len = nl ? (size_t)(nl - last) : strlen(last);
                JVal *v = json_parse(last, len);
                if (v && v->type == J_OBJ) {
                    // project select fields
                    Buf st;
                    buf_init(&st);
                    buf_putc(&st, '{');
                    jsonw_kv_int(&st, "active_users", json_get_int(v, "active_users", 0));
                    buf_putc(&st, ',');
                    jsonw_kv_int(&st, "sessions", json_get_int(v, "sessions", 0));
                    buf_putc(&st, ',');
                    jsonw_kv_int(&st, "total", json_get_int(v, "total", 0));
                    buf_putc(&st, ',');
                    jsonw_kv_int(&st, "uptime", json_get_int(v, "uptime_sec", 0));
                    buf_putc(&st, ',');
                    jsonw_kv_int(&st, "timestamp", json_get_int(v, "timestamp", 0));
                    buf_putc(&st, '}');
                    buf_puts(&stats, st.s);
                    buf_free(&st);
                }
                json_free(v);
            }
        }
        buf_free(&data);
    }
    buf_putc(&b, ',');
    jsonw_kv_raw(&b, "stats", stats.s ? stats.s : "null");
    buf_free(&stats);
    buf_printf(&b, ",\"users\":{\"max\":%d,\"active\":%d}", users_max_users(), users_count_active());
    buf_puts(&b, "}}");
    pthread_mutex_lock(&g_status_mu);
    snprintf(g_status_cache, sizeof(g_status_cache), "%s", b.s ? b.s : "");
    g_status_cache_ms = now_ms();
    pthread_mutex_unlock(&g_status_mu);
    http_res_json(res, 200, b.s);
    buf_free(&b);
}

// ---------- inbound ----------
static void inb_s(Buf *b, const char *field) {
    char sql[160];
    snprintf(sql, sizeof(sql), "SELECT %s FROM wdtt_inbound WHERE id=1", field);
    char *v = db_str(sql, NULL, 0);
    buf_printf(b, "\"%s\":", field);
    jsonw_str(b, v ? v : "");
    free(v);
    buf_putc(b, ',');
}

static void inb_i(Buf *b, const char *field, long long def) {
    char sql[160];
    snprintf(sql, sizeof(sql), "SELECT %s FROM wdtt_inbound WHERE id=1", field);
    buf_printf(b, "\"%s\":%lld,", field, db_int(sql, def));
}

static void h_inbound_get(const HttpReq *req, HttpRes *res) {
    (void)req;
    Buf b;
    buf_init(&b);
    inb_s(&b, "tag");
    inb_s(&b, "remark");
    inb_i(&b, "enable", 1);
    inb_s(&b, "listen_host");
    inb_s(&b, "server_host");
    inb_i(&b, "dtls_port", 56000);
    inb_i(&b, "wg_port", 56001);
    inb_i(&b, "client_port", 9000);
    inb_s(&b, "dns");
    inb_i(&b, "mtu", 1280);
    inb_i(&b, "max_users", 10);
    inb_i(&b, "handshake_timeout_sec", 30);
    inb_i(&b, "max_dtls_per_device", 0);
    inb_i(&b, "online_timeout_sec", 15);
    inb_i(&b, "wg_keepalive_sec", 25);
    inb_i(&b, "stats_interval_sec", 2);
    inb_s(&b, "admin_addr");
    inb_i(&b, "raw_enable", 1);
    inb_i(&b, "raw_direct_port", 0);
    if (b.len && b.s[b.len - 1] == ',') b.len--;
    if (b.s) b.s[b.len] = 0;
    Buf wrap;
    buf_init(&wrap);
    buf_printf(&wrap, "{%s}", b.s ? b.s : "");
    buf_free(&b);
    ok_obj(res, wrap.s);
    buf_free(&wrap);
}

static void h_inbound_save(const HttpReq *req, HttpRes *res) {
    JVal *v = body_json(req);
    if (!v) {
        fail(res, "некорректный JSON", 400);
        return;
    }
    char err[256] = "";
    int rc = 0;
#define SET_S(field)                                              \
    do {                                                          \
        const char *s_ = json_get_str(v, field);                  \
        if (s_) {                                                 \
            char *sql = sqlite3_mprintf("UPDATE wdtt_inbound SET " field "=%Q WHERE id=1", s_); \
            rc |= db_exec(sql, err, sizeof(err));                 \
            sqlite3_free(sql);                                    \
        }                                                         \
    } while (0)
#define SET_I(field)                                              \
    do {                                                          \
        JVal *j_ = json_get(v, field);                            \
        if (j_) {                                                 \
            char *sql = sqlite3_mprintf("UPDATE wdtt_inbound SET " field "=%lld WHERE id=1", \
                                        (long long)(j_->type == J_STR ? strtoll(j_->str, NULL, 10) : (long long)j_->num)); \
            rc |= db_exec(sql, err, sizeof(err));                 \
            sqlite3_free(sql);                                    \
        }                                                         \
    } while (0)
    SET_S("tag");
    SET_S("remark");
    SET_I("enable");
    SET_S("listen_host");
    SET_S("server_host");
    SET_I("dtls_port");
    SET_I("wg_port");
    SET_I("client_port");
    SET_S("dns");
    SET_I("mtu");
    SET_I("max_users");
    SET_I("handshake_timeout_sec");
    SET_I("max_dtls_per_device");
    SET_I("online_timeout_sec");
    SET_I("wg_keepalive_sec");
    SET_I("stats_interval_sec");
    SET_S("admin_addr");
    SET_I("raw_enable");
    SET_I("raw_direct_port");
#undef SET_S
#undef SET_I
    json_free(v);
    if (rc != 0) {
        fail(res, err, 500);
        return;
    }
    // hot reload data plane (fallback: systemctl restart wdtt)
    char rerr[256];
    proto_reload_dataplane(rerr, sizeof(rerr));
    ok_null(res);
}

// ---------- public dispatch ----------
int api_public(const HttpReq *req, HttpRes *res, const char *path) {
    if (strcmp(path, "/health") == 0) {
        http_res_text(res, 200, "wdttpanel ok\n");
        return 1;
    }
    if (strncmp(path, "/sub/", 5) == 0) {
        sub_handle(req, res, path);
        return 1;
    }
    if (strcmp(path, "/api/login") == 0 && strcmp(req->method, "POST") == 0) {
        h_login(req, res);
        return 1;
    }
    if (strcmp(path, "/api/logout") == 0) {
        if (strcmp(req->method, "POST") != 0) {
            fail(res, "POST required", 405);
            return 1;
        }
        h_logout(req, res);
        return 1;
    }
    return 0;
}

void api_dispatch(const HttpReq *req, HttpRes *res, const char *path) {
    // session required
    const char *tok = app_session_token(req);
    if (!tok) {
        fail(res, "unauthorized", 401);
        return;
    }
    // CSRF for mutating methods
    if (strcmp(req->method, "GET") != 0 && strcmp(req->method, "HEAD") != 0) {
        const char *csrf = hlist_get(&req->headers, "X-CSRF-Token");
        if (!csrf || strcmp(csrf, tok) != 0) {
            fail(res, "CSRF token invalid", 403);
            return;
        }
    }
    if (strcmp(path, "/api/me") == 0) return h_me(req, res);
    if (strcmp(path, "/api/users") == 0) return h_users_list(req, res);
    if (strcmp(path, "/api/users/add") == 0) return h_users_add(req, res);
    if (strcmp(path, "/api/users/update") == 0) return h_users_update(req, res);
    if (strcmp(path, "/api/users/delete") == 0) return h_users_delete(req, res);
    if (strcmp(path, "/api/users/reset-traffic") == 0) return h_users_reset_traffic(req, res);
    if (strcmp(path, "/api/password/main") == 0) return h_password_main(req, res);
    if (strcmp(path, "/api/password/panel") == 0) return h_password_panel(req, res);
    if (strcmp(path, "/api/protocols") == 0 && strcmp(req->method, "GET") == 0) return h_protocols_get(req, res);
    if (strcmp(path, "/api/protocols") == 0 && strcmp(req->method, "POST") == 0) return h_protocols_post(req, res);
    if (strcmp(path, "/api/status") == 0) return h_status(req, res);
    if (strcmp(path, "/api/inbound") == 0) return h_inbound_get(req, res);
    if (strcmp(path, "/api/inbound/save") == 0) return h_inbound_save(req, res);
    fail(res, "not found", 404);
}

// ---------- CLI ----------
int api_init_panel(const char *admin_password, const char *public_url) {
    char err[512];
    if (auth_init_schema(err, sizeof(err)) != 0) {
        fprintf(stderr, "wdttpanel: schema: %s\n", err);
        return 1;
    }
    auth_ensure_session_key();
    if (admin_password && admin_password[0]) {
        char *hash = auth_hash_password(admin_password);
        if (!hash) return 1;
        auth_set_credentials(NULL, hash);
        free(hash);
    }
    // seed main password if missing
    char *main = users_main_password();
    if (!main || !main[0]) {
        char *pw = gen_password();
        users_set_main_password(pw);
        fprintf(stderr, "[init] main VPN password: %s\n", pw);
        free(pw);
    } else {
        // ensure ADMIN row exists
        WdttUser u;
        if (users_load(main, &u) != 1) {
            memset(&u, 0, sizeof(u));
            snprintf(u.password, sizeof(u.password), "%s", main);
            snprintf(u.comment, sizeof(u.comment), "ADMIN");
            users_upsert(&u);
        }
    }
    free(main);
    if (public_url && public_url[0]) {
        Buf su;
        buf_init(&su);
        buf_printf(&su, "%s/wdtt/sub", public_url);
        char sql[600];
        // escape single quotes minimally (public_url is admin-controlled)
        char esc[512];
        size_t j = 0;
        for (const char *c = su.s; *c && j < sizeof(esc) - 2; c++) {
            if (*c == '\'') esc[j++] = '\'';
            esc[j++] = *c;
        }
        esc[j] = 0;
        snprintf(sql, sizeof(sql), "UPDATE panel_config SET sub_uri='%s' WHERE id=1", esc);
        db_exec(sql, err, sizeof(err));
        buf_free(&su);
    }
    puts("panel initialized");
    return 0;
}

int api_set_admin_password(const char *pw) {
    char *hash = auth_hash_password(pw);
    if (!hash) return 1;
    auth_set_credentials(NULL, hash);
    free(hash);
    puts("admin password updated");
    return 0;
}

#include "users.h"
#include "db.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define USER_COLS "password, device_id, max_devices, expires_at, down_bytes, up_bytes, total_bytes, " \
                  "max_down_mbps, max_up_mbps, is_deactivated, comment, ports, vk_hash, sub_id, last_seen_at"

static const unsigned char *col(sqlite3_stmt *st, int i) {
    return sqlite3_column_text(st, i);
}

static void user_from_stmt(sqlite3_stmt *st, WdttUser *u) {
    memset(u, 0, sizeof(*u));
    const unsigned char *v;
    int i = 0;
    if ((v = col(st, i++))) snprintf(u->password, sizeof(u->password), "%s", (const char *)v);
    if ((v = col(st, i++))) snprintf(u->device_id, sizeof(u->device_id), "%s", (const char *)v);
    u->max_devices = sqlite3_column_int(st, i++);
    u->expires_at = sqlite3_column_int64(st, i++);
    u->down_bytes = sqlite3_column_int64(st, i++);
    u->up_bytes = sqlite3_column_int64(st, i++);
    u->total_bytes = sqlite3_column_int64(st, i++);
    u->max_down_mbps = sqlite3_column_double(st, i++);
    u->max_up_mbps = sqlite3_column_double(st, i++);
    u->is_deactivated = sqlite3_column_int(st, i++);
    if ((v = col(st, i++))) snprintf(u->comment, sizeof(u->comment), "%s", (const char *)v);
    if ((v = col(st, i++))) snprintf(u->ports, sizeof(u->ports), "%s", (const char *)v);
    if ((v = col(st, i++))) snprintf(u->vk_hash, sizeof(u->vk_hash), "%s", (const char *)v);
    if ((v = col(st, i++))) snprintf(u->sub_id, sizeof(u->sub_id), "%s", (const char *)v);
    u->last_seen_at = sqlite3_column_int64(st, i);
}

// ---- single-row loads ----
typedef struct {
    WdttUser *out;
    int found;
} LoadCtx;

static int load_row_cb(sqlite3_stmt *st, void *ud) {
    LoadCtx *ctx = ud;
    user_from_stmt(st, ctx->out);
    ctx->found = 1;
    return 1; // stop after first row
}

int users_load(const char *password, WdttUser *out) {
    char *sql = sqlite3_mprintf("SELECT " USER_COLS " FROM wdtt_users WHERE password = %Q", password);
    char err[256] = "";
    LoadCtx ctx = {out, 0};
    db_query(sql, load_row_cb, &ctx, err, sizeof(err));
    sqlite3_free(sql);
    return ctx.found;
}

int users_load_by_subid(const char *subid, char *password_out, size_t pcap, WdttUser *out) {
    char *sql = sqlite3_mprintf("SELECT " USER_COLS " FROM wdtt_users WHERE sub_id = %Q", subid);
    char err[256] = "";
    LoadCtx ctx = {out, 0};
    db_query(sql, load_row_cb, &ctx, err, sizeof(err));
    sqlite3_free(sql);
    if (ctx.found && password_out && pcap)
        snprintf(password_out, pcap, "%s", out->password);
    return ctx.found;
}

// ---- iteration ----
// ---- iteration: snapshot rows under db lock, run callbacks outside it
// (callbacks may issue their own db queries; calling them under g_mu deadlocks)
typedef struct {
    WdttUser *items;
    size_t n, cap;
} UserArr;

static void user_arr_push(UserArr *arr, const WdttUser *u) {
    if (arr->n == arr->cap) {
        arr->cap = arr->cap ? arr->cap * 2 : 16;
        arr->items = xrealloc(arr->items, arr->cap * sizeof(WdttUser));
    }
    arr->items[arr->n++] = *u;
}

static int snapshot_row_cb(sqlite3_stmt *st, void *ud) {
    UserArr *arr = ud;
    WdttUser u;
    user_from_stmt(st, &u);
    user_arr_push(arr, &u);
    return 0;
}

int users_each(int (*cb)(const WdttUser *u, void *ud), void *ud) {
    char err[256] = "";
    UserArr arr = {0};
    db_query("SELECT " USER_COLS " FROM wdtt_users", snapshot_row_cb, &arr, err, sizeof(err));
    int rc = 0;
    for (size_t i = 0; i < arr.n; i++)
        if (cb(&arr.items[i], ud) != 0) {
            rc = 1;
            break;
        }
    free(arr.items);
    return rc;
}

// ---- mutations ----
void users_bump_rev(void) {
    char err[128];
    db_exec("UPDATE wdtt_global SET users_rev = users_rev + 1 WHERE id=1", err, sizeof(err));
}

int users_upsert(WdttUser *u) {
    if (!u->sub_id[0]) {
        char *sid = gen_subid();
        snprintf(u->sub_id, sizeof(u->sub_id), "%s", sid);
        free(sid);
    }
    char *sql = sqlite3_mprintf(
        "INSERT INTO wdtt_users (password, device_id, max_devices, expires_at, down_bytes, up_bytes,"
        " total_bytes, max_down_mbps, max_up_mbps, is_deactivated, comment, ports, vk_hash, sub_id, last_seen_at)"
        " VALUES (%Q, %Q, %d, %lld, %lld, %lld, %lld, %.3f, %.3f, %d, %Q, %Q, %Q, %Q, %lld)"
        " ON CONFLICT(password) DO UPDATE SET"
        " device_id=excluded.device_id, max_devices=excluded.max_devices, expires_at=excluded.expires_at,"
        " down_bytes=excluded.down_bytes, up_bytes=excluded.up_bytes, total_bytes=excluded.total_bytes,"
        " max_down_mbps=excluded.max_down_mbps, max_up_mbps=excluded.max_up_mbps,"
        " is_deactivated=excluded.is_deactivated, comment=excluded.comment, ports=excluded.ports,"
        " vk_hash=excluded.vk_hash, sub_id=excluded.sub_id",
        u->password, u->device_id, u->max_devices, u->expires_at, u->down_bytes, u->up_bytes,
        u->total_bytes, u->max_down_mbps, u->max_up_mbps, u->is_deactivated, u->comment, u->ports,
        u->vk_hash, u->sub_id, u->last_seen_at);
    char err[256] = "";
    int rc = db_exec(sql, err, sizeof(err));
    sqlite3_free(sql);
    if (rc == 0) users_bump_rev();
    return rc;
}

int users_set_devices(const char *password, const char *const *device_ids) {
    char err[256] = "";
    char *sql = sqlite3_mprintf("DELETE FROM wdtt_user_devices WHERE password = %Q", password);
    int rc = db_exec(sql, err, sizeof(err));
    sqlite3_free(sql);
    if (rc != 0) return rc;
    int first = 1;
    for (const char *const *d = device_ids; d && *d; d++) {
        if (!(*d)[0]) continue;
        sql = sqlite3_mprintf(
            "INSERT OR IGNORE INTO wdtt_user_devices (password, device_id, sort_order) VALUES (%Q, %Q, %d)",
            password, *d, 0);
        rc = db_exec(sql, err, sizeof(err));
        sqlite3_free(sql);
        if (rc != 0) return rc;
        if (first) {
            sql = sqlite3_mprintf("UPDATE wdtt_users SET device_id = %Q WHERE password = %Q", *d, password);
            db_exec(sql, err, sizeof(err));
            sqlite3_free(sql);
        }
        first = 0;
    }
    if (first) { // no devices
        sql = sqlite3_mprintf("UPDATE wdtt_users SET device_id = '' WHERE password = %Q", password);
        db_exec(sql, err, sizeof(err));
        sqlite3_free(sql);
    }
    users_bump_rev();
    return 0;
}

int users_get_protocols(const char *subid, Buf *out) {
    char *v = db_str("SELECT protocols FROM vpn_user_inbounds WHERE sub_id=?", subid, 0);
    buf_clear(out);
    buf_puts(out, (v && v[0]) ? v : "[]");
    free(v);
    return 0;
}

int users_set_protocols(const char *subid, const char *protocols_json) {
    char err[256] = "";
    char *sql = sqlite3_mprintf(
        "INSERT INTO vpn_user_inbounds (sub_id, protocols) VALUES (%Q, %Q)"
        " ON CONFLICT(sub_id) DO UPDATE SET protocols=excluded.protocols",
        subid, protocols_json);
    int rc = db_exec(sql, err, sizeof(err));
    sqlite3_free(sql);
    if (rc == 0) users_bump_rev();
    return rc;
}

int users_delete(const char *password) {
    WdttUser u;
    if (users_load(password, &u) != 1) return -1;
    if (u.sub_id[0]) {
        char *sql = sqlite3_mprintf("DELETE FROM vpn_user_inbounds WHERE sub_id = %Q", u.sub_id);
        char err[128];
        db_exec(sql, err, sizeof(err));
        sqlite3_free(sql);
    }
    char *sql = sqlite3_mprintf("DELETE FROM wdtt_user_devices WHERE password = %Q", password);
    char err[128];
    db_exec(sql, err, sizeof(err));
    sqlite3_free(sql);
    sql = sqlite3_mprintf("DELETE FROM wdtt_users WHERE password = %Q", password);
    int rc = db_exec(sql, err, sizeof(err));
    sqlite3_free(sql);
    if (rc == 0) users_bump_rev();
    return rc;
}

int users_reset_traffic(const char *password) {
    char *sql = sqlite3_mprintf(
        "UPDATE wdtt_users SET down_bytes=0, up_bytes=0 WHERE password = %Q", password);
    char err[256] = "";
    int rc = db_exec(sql, err, sizeof(err));
    sqlite3_free(sql);
    if (rc == 0) users_bump_rev();
    return rc;
}

// ---- main password ----
char *users_main_password(void) {
    return db_str("SELECT main_password FROM wdtt_global WHERE id=1", NULL, 0);
}

int users_set_main_password(const char *new_main) {
    char *old = users_main_password();
    char err[256] = "";
    if (old && old[0] && strcmp(old, new_main) == 0) {
        free(old);
        return 0;
    }
    // carry entry: old main row moves to new password (or new row becomes ADMIN)
    WdttUser carry;
    int have_old = (old && old[0]) ? (users_load(old, &carry) == 1) : 0;
    WdttUser existing;
    int have_new = (users_load(new_main, &existing) == 1);

    if (have_old && !have_new) {
        // insert copy under new password, copy device bindings, delete old
        snprintf(carry.password, sizeof(carry.password), "%s", new_main);
        snprintf(carry.comment, sizeof(carry.comment), "ADMIN");
        carry.max_devices = 0;
        carry.is_deactivated = 0;
        if (users_upsert(&carry) == 0) {
            // copy bindings
            char *q = sqlite3_mprintf(
                "INSERT OR IGNORE INTO wdtt_user_devices (password, device_id, sort_order) "
                "SELECT %Q, device_id, sort_order FROM wdtt_user_devices WHERE password=%Q",
                new_main, old);
            db_exec(q, err, sizeof(err));
            sqlite3_free(q);
            char *d = sqlite3_mprintf("DELETE FROM wdtt_user_devices WHERE password=%Q", old);
            db_exec(d, err, sizeof(err));
            sqlite3_free(d);
            char *del = sqlite3_mprintf("DELETE FROM wdtt_users WHERE password=%Q", old);
            db_exec(del, err, sizeof(err));
            sqlite3_free(del);
        }
    } else if (have_new) {
        // entry already exists under new password: make it ADMIN
        char *upd = sqlite3_mprintf(
            "UPDATE wdtt_users SET comment='ADMIN', max_devices=0, is_deactivated=0 WHERE password=%Q",
            new_main);
        db_exec(upd, err, sizeof(err));
        sqlite3_free(upd);
        if (have_old) {
            char *d = sqlite3_mprintf(
                "DELETE FROM wdtt_user_devices WHERE password=%Q;"
                "DELETE FROM wdtt_users WHERE password=%Q",
                old, old);
            db_exec(d, err, sizeof(err));
            sqlite3_free(d);
        }
    } else {
        // no old, no new: create fresh ADMIN row
        memset(&carry, 0, sizeof(carry));
        snprintf(carry.password, sizeof(carry.password), "%s", new_main);
        snprintf(carry.comment, sizeof(carry.comment), "ADMIN");
        users_upsert(&carry);
    }

    int rc = db_exec1("UPDATE wdtt_global SET main_password=? WHERE id=1", new_main, err, sizeof(err));
    users_bump_rev();
    free(old);
    return rc;
}

int users_count_active(void) {
    return (int)db_int(
        "SELECT COUNT(*) FROM wdtt_users WHERE is_deactivated=0 AND (expires_at=0 OR expires_at > strftime('%s','now'))",
        0);
}

int users_max_users(void) {
    return (int)db_int("SELECT max_users FROM wdtt_inbound WHERE id=1", 10);
}

// ---- admin API push ----
void admin_inbound_addr(char *out, size_t cap) {
    char *addr = db_str("SELECT admin_addr FROM wdtt_inbound WHERE id=1", NULL, 0);
    if (addr && addr[0]) snprintf(out, cap, "%s", addr);
    else snprintf(out, cap, "127.0.0.1:2861");
    free(addr);
}

char *admin_session_key(void) {
    return db_str("SELECT session_key FROM panel_config WHERE id=1", NULL, 0);
}

static int admin_post(const char *addr, const char *path, const char *body,
                      char *err, size_t errcap) {
    char host[256] = "127.0.0.1";
    int port = 2861;
    const char *colon = strrchr(addr, ':');
    if (colon) {
        size_t hl = (size_t)(colon - addr);
        if (hl > 0 && hl < sizeof(host)) {
            memcpy(host, addr, hl);
            host[hl] = 0;
        }
        port = atoi(colon + 1);
    }
    if (port <= 0) port = 2861;

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) {
        snprintf(err, errcap, "admin api: cannot resolve %s", host);
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET)
            ((struct sockaddr_in *)ai->ai_addr)->sin_port = htons((uint16_t)port);
        else if (ai->ai_family == AF_INET6)
            ((struct sockaddr_in6 *)ai->ai_addr)->sin6_port = htons((uint16_t)port);
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = {30, 0};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        snprintf(err, errcap, "admin api: connect %s:%d failed: %s", host, port, strerror(errno));
        return -1;
    }

    char *key = admin_session_key();
    Buf req;
    buf_init(&req);
    buf_printf(&req,
               "POST %s HTTP/1.1\r\n"
               "Host: %s:%d\r\n"
               "Content-Type: application/json\r\n"
               "Content-Length: %zu\r\n"
               "Connection: close\r\n",
               path, host, port, strlen(body));
    if (key && key[0]) buf_printf(&req, "X-WDTT-Admin-Token: %s\r\n", key);
    free(key);
    buf_puts(&req, "\r\n");
    buf_puts(&req, body);

    int rc = 0;
    if (write(fd, req.s, req.len) != (ssize_t)req.len) {
        snprintf(err, errcap, "admin api: write failed");
        rc = -1;
        goto out;
    }

    // read full response, parse {"ok":..,"msg":..}
    Buf resp;
    buf_init(&resp);
    char tmp[4096];
    ssize_t r;
    while ((r = read(fd, tmp, sizeof(tmp))) > 0) {
        buf_append(&resp, tmp, (size_t)r);
        if (resp.len > 65536) break;
    }
    // split headers/body
    char *hdr_end = resp.s ? strstr(resp.s, "\r\n\r\n") : NULL;
    const char *json_body = hdr_end ? hdr_end + 4 : (resp.s ? resp.s : "");
    int status = 0;
    if (resp.s && strncmp(resp.s, "HTTP/1.", 7) == 0) {
        const char *sp = strchr(resp.s, ' ');
        if (sp) status = atoi(sp + 1);
    }
    if (status == 401) {
        snprintf(err, errcap, "admin api: unauthorized (session_key mismatch)");
        rc = -1;
    } else {
        JVal *v = json_parse(json_body, strlen(json_body));
        if (v) {
            if (!json_get_bool(v, "ok", 0)) {
                const char *msg = json_get_str(v, "msg");
                snprintf(err, errcap, "admin api: %s", msg ? msg : "error");
                rc = -1;
            }
            json_free(v);
        } else if (status != 200) {
            snprintf(err, errcap, "admin api: HTTP %d", status);
            rc = -1;
        }
    }
    buf_free(&resp);
out:
    close(fd);
    buf_free(&req);
    return rc;
}

static void build_update_body(Buf *b, const char *old_password, const char *new_password,
                              const WdttUser *u, const char *const *device_ids, int manage_devices) {
    buf_putc(b, '{');
    jsonw_kv_str(b, "old_password", old_password ? old_password : "");
    jsonw_kv_str(b, "password", new_password ? new_password : "");
    jsonw_kv_str(b, "device_id", u->device_id);
    if (manage_devices && device_ids) {
        jsonw_str(b, "device_ids");
        buf_puts(b, ":[");
        int first = 1;
        for (const char *const *d = device_ids; *d; d++) {
            if (!first) buf_putc(b, ',');
            jsonw_str(b, *d);
            first = 0;
        }
        buf_puts(b, "]");
    }
    buf_putc(b, ',');
    jsonw_kv_int(b, "max_devices", u->max_devices);
    buf_putc(b, ',');
    jsonw_kv_str(b, "comment", u->comment);
    buf_putc(b, ',');
    jsonw_kv_int(b, "expires_at", u->expires_at);
    buf_putc(b, ',');
    // total_gb as double (Go float64; server converts gbToBytes)
    buf_printf(b, "\"total_gb\":%.6f", (double)u->total_bytes / (1024.0 * 1024.0 * 1024.0));
    buf_putc(b, ',');
    buf_printf(b, "\"max_down_mbps\":%.3f", u->max_down_mbps);
    buf_putc(b, ',');
    buf_printf(b, "\"max_up_mbps\":%.3f", u->max_up_mbps);
    buf_puts(b, ",\"active\":");
    buf_puts(b, u->is_deactivated ? "false" : "true");
    buf_putc(b, ',');
    jsonw_kv_str(b, "ports", u->ports);
    buf_putc(b, ',');
    jsonw_kv_int(b, "dtls_port", 0);
    buf_putc(b, ',');
    jsonw_kv_int(b, "wg_port", 0);
    buf_putc(b, ',');
    jsonw_kv_int(b, "client_port", 0);
    buf_puts(b, ",\"use_custom_ports\":false");
    buf_putc(b, ',');
    jsonw_kv_str(b, "vk_hash", u->vk_hash);
    buf_putc(b, '}');
}

int admin_push_user_update(const char *old_password, const char *new_password,
                           const WdttUser *u, const char *const *device_ids, int manage_devices,
                           char *err, size_t errcap) {
    char addr[128];
    admin_inbound_addr(addr, sizeof(addr));
    Buf body;
    buf_init(&body);
    build_update_body(&body, old_password, new_password, u, device_ids, manage_devices);
    int rc = admin_post(addr, "/admin/users/update", body.s, err, errcap);
    buf_free(&body);
    return rc;
}

int admin_push_user_delete(const char *password, char *err, size_t errcap) {
    char addr[128];
    admin_inbound_addr(addr, sizeof(addr));
    Buf body;
    buf_init(&body);
    buf_puts(&body, "{\"password\":");
    jsonw_str(&body, password);
    buf_puts(&body, "}");
    int rc = admin_post(addr, "/admin/users/delete", body.s, err, errcap);
    buf_free(&body);
    return rc;
}

int admin_post_reload(const char *addr, char *err, size_t errcap) {
    return admin_post(addr, "/admin/reload", "{}", err, errcap);
}

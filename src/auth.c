#include "auth.h"
#include "db.h"
#include "util.h"

#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---------- PBKDF2 ----------
#define PBKDF2_ITER 210000
#define PBKDF2_SALT 16
#define PBKDF2_DK   32

char *auth_hash_password(const char *pw) {
    uint8_t salt[PBKDF2_SALT], dk[PBKDF2_DK];
    rand_bytes(salt, sizeof(salt));
    if (PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw), salt, sizeof(salt), PBKDF2_ITER,
                          EVP_sha256(), sizeof(dk), dk) != 1)
        return NULL;
    char shex[2 * PBKDF2_SALT + 1], dhex[2 * PBKDF2_DK + 1];
    hex_encode(salt, sizeof(salt), shex);
    hex_encode(dk, sizeof(dk), dhex);
    Buf b;
    buf_init(&b);
    buf_printf(&b, "$wdttpanel$1$%d$%s$%s", PBKDF2_ITER, shex, dhex);
    return buf_detach(&b);
}

int auth_verify_password(const char *pw, const char *hash) {
    if (!pw || !hash || strncmp(hash, "$wdttpanel$1$", 13) != 0) return 0;
    // parse iter, salt, dk
    const char *p = hash + 13;
    char *end = NULL;
    long long iter = strtoll(p, &end, 10);
    if (iter <= 0 || iter > 2000000 || *end != '$') return 0;
    p = end + 1;
    const char *dollar = strchr(p, '$');
    if (!dollar) return 0;
    size_t slen = (size_t)(dollar - p);
    uint8_t salt[64];
    if (slen == 0 || slen > 2 * sizeof(salt) || slen % 2) return 0;
    if (hex_decode(p, slen, salt) < 0) return 0;
    p = dollar + 1;
    uint8_t dk[64], calc[64];
    size_t dklen = strlen(p);
    if (dklen == 0 || dklen > 2 * sizeof(dk) || dklen % 2) return 0;
    if (hex_decode(p, dklen, dk) < 0) return 0;
    dklen /= 2;
    if (PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw), salt, slen / 2, (int)iter,
                          EVP_sha256(), (int)dklen, calc) != 1)
        return 0;
    return CRYPTO_memcmp(dk, calc, dklen) == 0;
}

// ---------- rate limiter ----------
#define RL_BUCKETS 4096
#define RL_MAX_FAILS 5
#define RL_WINDOW_MS (15LL * 60 * 1000)

typedef struct {
    char ip[64];
    long long fails[RL_MAX_FAILS];
    int idx;
    long long last;
} RLSlot;

static RLSlot g_rl[RL_BUCKETS];
static pthread_mutex_t g_rl_mu = PTHREAD_MUTEX_INITIALIZER;

static RLSlot *rl_slot(const char *ip) {
    unsigned h = 2166136261u;
    for (const char *c = ip; *c; c++) h = (h ^ (unsigned char)*c) * 16777619u;
    unsigned idx = h % RL_BUCKETS;
    for (int probe = 0; probe < 8; probe++) {
        RLSlot *s = &g_rl[(idx + (unsigned)probe) % RL_BUCKETS];
        if (!s->ip[0] || strcmp(s->ip, ip) == 0) {
            if (!s->ip[0]) snprintf(s->ip, sizeof(s->ip), "%s", ip);
            return s;
        }
    }
    // table crowded: take over the most recently used expired slot in the chain
    for (int probe = 0; probe < 8; probe++) {
        RLSlot *s = &g_rl[(idx + (unsigned)probe) % RL_BUCKETS];
        if (s->last == 0 || now_ms() - s->last > RL_WINDOW_MS) {
            memset(s, 0, sizeof(*s));
            snprintf(s->ip, sizeof(s->ip), "%s", ip);
            return s;
        }
    }
    return &g_rl[idx]; // worst case: same-key collision (rare with 4096 slots)
}

int auth_rate_allow(const char *ip) {
    if (!ip || !ip[0]) return 0;
    pthread_mutex_lock(&g_rl_mu);
    long long now = now_ms();
    RLSlot *s = rl_slot(ip);
    s->last = now;
    int recent = 0;
    for (int i = 0; i < RL_MAX_FAILS; i++)
        if (s->fails[i] > 0 && now - s->fails[i] < RL_WINDOW_MS) recent++;
    pthread_mutex_unlock(&g_rl_mu);
    return recent < RL_MAX_FAILS;
}

void auth_rate_fail(const char *ip) {
    if (!ip || !ip[0]) return;
    pthread_mutex_lock(&g_rl_mu);
    RLSlot *s = rl_slot(ip);
    s->fails[s->idx % RL_MAX_FAILS] = now_ms();
    s->idx++;
    pthread_mutex_unlock(&g_rl_mu);
}

void auth_rate_reset(const char *ip) {
    if (!ip || !ip[0]) return;
    pthread_mutex_lock(&g_rl_mu);
    RLSlot *s = rl_slot(ip);
    memset(s->fails, 0, sizeof(s->fails));
    pthread_mutex_unlock(&g_rl_mu);
}

// ---------- panel_config ----------
char *auth_get_username(void) {
    char *v = db_str("SELECT username FROM panel_config WHERE id=1", NULL, 0);
    return v ? v : xstrdup("admin");
}

char *auth_get_password_hash(void) {
    return db_str("SELECT password_hash FROM panel_config WHERE id=1", NULL, 0);
}

char *auth_get_session_key(void) {
    return db_str("SELECT session_key FROM panel_config WHERE id=1", NULL, 0);
}

int auth_set_credentials(const char *username, const char *password_hash) {
    char err[256];
    if (username && password_hash)
        return db_exec2("UPDATE panel_config SET username=?, password_hash=? WHERE id=1",
                        username, password_hash, err, sizeof(err));
    if (username)
        return db_exec1("UPDATE panel_config SET username=? WHERE id=1",
                        username, err, sizeof(err));
    if (password_hash)
        return db_exec1("UPDATE panel_config SET password_hash=? WHERE id=1",
                        password_hash, err, sizeof(err));
    return 0;
}

void auth_ensure_session_key(void) {
    char *key = auth_get_session_key();
    if (key && key[0]) {
        free(key);
        return;
    }
    free(key);
    char hex[65];
    rand_hex(hex, 32);
    char err[256];
    db_exec1("UPDATE panel_config SET session_key=? WHERE id=1", hex, err, sizeof(err));
}

int auth_init_schema(char *err, size_t errcap) {
    // canonical schema v15 (subset used by C panel; compatible with Go panel DDL)
    const char *ddl =
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS panel_config ("
        " id INTEGER PRIMARY KEY CHECK (id = 1),"
        " username TEXT NOT NULL DEFAULT 'admin',"
        " password_hash TEXT NOT NULL DEFAULT '',"
        " port INTEGER NOT NULL DEFAULT 2860,"
        " web_base_path TEXT NOT NULL DEFAULT '/wdtt/',"
        " session_key TEXT NOT NULL DEFAULT '',"
        " web_listen TEXT NOT NULL DEFAULT '',"
        " web_domain TEXT NOT NULL DEFAULT '',"
        " web_cert_file TEXT NOT NULL DEFAULT '',"
        " web_key_file TEXT NOT NULL DEFAULT '',"
        " session_max_age INTEGER NOT NULL DEFAULT 60,"
        " page_size INTEGER NOT NULL DEFAULT 50,"
        " remark_model TEXT NOT NULL DEFAULT '-ieo',"
        " block_ping INTEGER NOT NULL DEFAULT 0,"
        " sub_enable INTEGER NOT NULL DEFAULT 1,"
        " sub_listen TEXT NOT NULL DEFAULT '',"
        " sub_port INTEGER NOT NULL DEFAULT 2096,"
        " sub_path TEXT NOT NULL DEFAULT '/sub/',"
        " sub_domain TEXT NOT NULL DEFAULT '',"
        " sub_cert_file TEXT NOT NULL DEFAULT '',"
        " sub_key_file TEXT NOT NULL DEFAULT '',"
        " sub_encrypt INTEGER NOT NULL DEFAULT 1,"
        " sub_title TEXT NOT NULL DEFAULT '',"
        " sub_support_url TEXT NOT NULL DEFAULT '',"
        " sub_profile_url TEXT NOT NULL DEFAULT '',"
        " sub_announce TEXT NOT NULL DEFAULT '',"
        " sub_uri TEXT NOT NULL DEFAULT '',"
        " sub_show_info INTEGER NOT NULL DEFAULT 1,"
        " dashboard_poll_sec INTEGER NOT NULL DEFAULT 2,"
        " users_poll_sec INTEGER NOT NULL DEFAULT 5,"
        " connections_poll_sec INTEGER NOT NULL DEFAULT 5);"
        "CREATE TABLE IF NOT EXISTS wdtt_global ("
        " id INTEGER PRIMARY KEY CHECK (id = 1),"
        " main_password TEXT NOT NULL DEFAULT '',"
        " admin_id TEXT NOT NULL DEFAULT '',"
        " bot_token TEXT NOT NULL DEFAULT '',"
        " users_rev INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS wdtt_users ("
        " password TEXT PRIMARY KEY,"
        " device_id TEXT NOT NULL DEFAULT '',"
        " max_devices INTEGER NOT NULL DEFAULT 0,"
        " expires_at INTEGER NOT NULL DEFAULT 0,"
        " down_bytes INTEGER NOT NULL DEFAULT 0,"
        " up_bytes INTEGER NOT NULL DEFAULT 0,"
        " total_bytes INTEGER NOT NULL DEFAULT 0,"
        " max_down_mbps REAL NOT NULL DEFAULT 0,"
        " max_up_mbps REAL NOT NULL DEFAULT 0,"
        " is_deactivated INTEGER NOT NULL DEFAULT 0,"
        " comment TEXT NOT NULL DEFAULT '',"
        " ports TEXT NOT NULL DEFAULT '',"
        " vk_hash TEXT NOT NULL DEFAULT '',"
        " sub_id TEXT NOT NULL DEFAULT '',"
        " last_seen_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_wdtt_users_sub_id ON wdtt_users(sub_id) WHERE sub_id != '';"
        "CREATE TABLE IF NOT EXISTS wdtt_user_devices ("
        " password TEXT NOT NULL,"
        " device_id TEXT NOT NULL,"
        " sort_order INTEGER NOT NULL DEFAULT 0,"
        " PRIMARY KEY (password, device_id),"
        " FOREIGN KEY (password) REFERENCES wdtt_users(password) ON DELETE CASCADE);"
        "CREATE TABLE IF NOT EXISTS wdtt_devices ("
        " device_id TEXT PRIMARY KEY,"
        " ip TEXT NOT NULL DEFAULT '',"
        " priv_key TEXT NOT NULL DEFAULT '',"
        " pub_key TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE IF NOT EXISTS wdtt_inbound ("
        " id INTEGER PRIMARY KEY CHECK (id = 1),"
        " tag TEXT NOT NULL DEFAULT 'wdtt-in',"
        " remark TEXT NOT NULL DEFAULT 'WDTT',"
        " enable INTEGER NOT NULL DEFAULT 1,"
        " listen_host TEXT NOT NULL DEFAULT '0.0.0.0',"
        " server_host TEXT NOT NULL DEFAULT '',"
        " dtls_port INTEGER NOT NULL DEFAULT 56000,"
        " wg_port INTEGER NOT NULL DEFAULT 56001,"
        " client_port INTEGER NOT NULL DEFAULT 9000,"
        " dns TEXT NOT NULL DEFAULT '1.1.1.1',"
        " mtu INTEGER NOT NULL DEFAULT 1280,"
        " max_users INTEGER NOT NULL DEFAULT 10,"
        " handshake_timeout_sec INTEGER NOT NULL DEFAULT 30,"
        " max_dtls_per_device INTEGER NOT NULL DEFAULT 0,"
        " online_timeout_sec INTEGER NOT NULL DEFAULT 15,"
        " wg_keepalive_sec INTEGER NOT NULL DEFAULT 25,"
        " stats_interval_sec INTEGER NOT NULL DEFAULT 2,"
        " admin_addr TEXT NOT NULL DEFAULT '127.0.0.1:2861',"
        " raw_enable INTEGER NOT NULL DEFAULT 1,"
        " raw_direct_port INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS xray_panel_meta ("
        " id INTEGER PRIMARY KEY CHECK (id = 1),"
        " outbound_test_url TEXT NOT NULL DEFAULT 'https://www.google.com/generate_204',"
        " warp TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE IF NOT EXISTS xray_inbound_meta ("
        " tag TEXT PRIMARY KEY,"
        " remark TEXT NOT NULL DEFAULT '',"
        " enable INTEGER NOT NULL DEFAULT 1,"
        " total INTEGER NOT NULL DEFAULT 0,"
        " expiry_time INTEGER NOT NULL DEFAULT 0,"
        " traffic_reset TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE IF NOT EXISTS xray_traffic_totals ("
        " id INTEGER PRIMARY KEY CHECK (id = 1),"
        " up INTEGER NOT NULL DEFAULT 0,"
        " down INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS xray_config ("
        " id INTEGER PRIMARY KEY CHECK (id = 1),"
        " raw_json TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE IF NOT EXISTS vpn_user_inbounds ("
        " sub_id TEXT PRIMARY KEY,"
        " protocols TEXT NOT NULL);"
        "INSERT OR IGNORE INTO schema_version (version) VALUES (15);"
        "INSERT OR IGNORE INTO panel_config (id) VALUES (1);"
        "INSERT OR IGNORE INTO wdtt_global (id) VALUES (1);"
        "INSERT OR IGNORE INTO wdtt_inbound (id) VALUES (1);"
        "INSERT OR IGNORE INTO xray_panel_meta (id) VALUES (1);"
        "INSERT OR IGNORE INTO xray_traffic_totals (id) VALUES (1);";
    return db_exec(ddl, err, errcap);
}

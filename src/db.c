#include "db.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

static sqlite3 *g_db = NULL;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

int db_open(const char *path, char *err, size_t errcap) {
    pthread_mutex_lock(&g_mu);
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    if (sqlite3_open_v2(path, &g_db, flags, NULL) != SQLITE_OK) {
        snprintf(err, errcap, "sqlite open %s: %s", path, g_db ? sqlite3_errmsg(g_db) : "?");
        if (g_db) sqlite3_close(g_db);
        g_db = NULL;
        pthread_mutex_unlock(&g_mu);
        return -1;
    }
    sqlite3_busy_timeout(g_db, 10000);
    char *msg = NULL;
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;", NULL, NULL, &msg);
    if (msg) sqlite3_free(msg);
    pthread_mutex_unlock(&g_mu);
    return 0;
}

void db_close(void) {
    pthread_mutex_lock(&g_mu);
    if (g_db) sqlite3_close(g_db);
    g_db = NULL;
    pthread_mutex_unlock(&g_mu);
}

// multi-statement exec (sqlite3_exec)
int db_exec(const char *sql, char *err, size_t errcap) {
    pthread_mutex_lock(&g_mu);
    char *msg = NULL;
    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &msg);
    int ret = 0;
    if (rc != SQLITE_OK) {
        snprintf(err, errcap, "sqlite exec: %s", msg ? msg : sqlite3_errmsg(g_db));
        ret = -1;
    }
    if (msg) sqlite3_free(msg);
    pthread_mutex_unlock(&g_mu);
    return ret;
}

// single statement with bound params
static int db_exec_bind(const char *sql, const char *p1, const char *p2, char *err, size_t errcap) {
    pthread_mutex_lock(&g_mu);
    sqlite3_stmt *st = NULL;
    int ret = 0;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) {
        snprintf(err, errcap, "sqlite prepare: %s", sqlite3_errmsg(g_db));
        pthread_mutex_unlock(&g_mu);
        return -1;
    }
    if (p1) sqlite3_bind_text(st, 1, p1, -1, SQLITE_TRANSIENT);
    if (p2) sqlite3_bind_text(st, 2, p2, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        snprintf(err, errcap, "sqlite exec: %s", sqlite3_errmsg(g_db));
        ret = -1;
    }
    sqlite3_finalize(st);
    pthread_mutex_unlock(&g_mu);
    return ret;
}

int db_exec1(const char *sql, const char *p1, char *err, size_t errcap) {
    return db_exec_bind(sql, p1, NULL, err, errcap);
}

int db_exec2(const char *sql, const char *p1, const char *p2, char *err, size_t errcap) {
    return db_exec_bind(sql, p1, p2, err, errcap);
}

int db_query(const char *sql, int (*cb)(sqlite3_stmt *, void *), void *ud,
             char *err, size_t errcap) {
    pthread_mutex_lock(&g_mu);
    sqlite3_stmt *st = NULL;
    int ret = 0;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) {
        snprintf(err, errcap, "sqlite prepare: %s", sqlite3_errmsg(g_db));
        pthread_mutex_unlock(&g_mu);
        return -1;
    }
    for (;;) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            if (cb && cb(st, ud) != 0) break;
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            snprintf(err, errcap, "sqlite step: %s", sqlite3_errmsg(g_db));
            ret = -1;
            break;
        }
    }
    sqlite3_finalize(st);
    pthread_mutex_unlock(&g_mu);
    return ret;
}

char *db_str(const char *sql, const char *param_text, long long param_ll) {
    pthread_mutex_lock(&g_mu);
    sqlite3_stmt *st = NULL;
    char *out = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (param_text) sqlite3_bind_text(st, 1, param_text, -1, SQLITE_TRANSIENT);
        else if (param_ll != 0 || strstr(sql, "?")) sqlite3_bind_int64(st, 1, param_ll);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const unsigned char *v = sqlite3_column_text(st, 0);
            if (v) out = xstrdup((const char *)v);
        }
    }
    sqlite3_finalize(st);
    pthread_mutex_unlock(&g_mu);
    return out;
}

long long db_int(const char *sql, long long defval) {
    pthread_mutex_lock(&g_mu);
    sqlite3_stmt *st = NULL;
    long long out = defval;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL)
            out = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    pthread_mutex_unlock(&g_mu);
    return out;
}

// SQLite helpers
#ifndef WDTT_DB_H
#define WDTT_DB_H

#include <sqlite3.h>
#include "util.h"

// open with WAL, foreign keys, busy timeout; serialized access via internal mutex
int  db_open(const char *path, char *err, size_t errcap);
void db_close(void);

// exec write statement; returns 0 ok
int db_exec(const char *sql, char *err, size_t errcap);

// exec with bound text params (NULL pointer = leave param unbound)
int db_exec1(const char *sql, const char *p1, char *err, size_t errcap);
int db_exec2(const char *sql, const char *p1, const char *p2, char *err, size_t errcap);

// run a query; cb receives one row; return nonzero from cb to stop.
// column values via sqlite3_column_text etc. on stmt
int db_query(const char *sql,
             int (*cb)(sqlite3_stmt *stmt, void *ud), void *ud,
             char *err, size_t errcap);

// scalar helpers: return malloc'd string or NULL
char *db_str(const char *sql, const char *param_i, long long param_ll);
long long db_int(const char *sql, long long defval);

#endif

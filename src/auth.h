// panel credentials: PBKDF2-HMAC-SHA256 storage + login rate limiting
#ifndef WDTT_AUTH_H
#define WDTT_AUTH_H

#include <stddef.h>

// hash format: $wdttpanel$1$<iter>$<salt_hex>$<dk_hex>
char *auth_hash_password(const char *pw);                 // malloc'd or NULL
int   auth_verify_password(const char *pw, const char *hash); // 1 ok

// login limiter: 5 failures / 15 min per real client IP (never trusts XFF)
int  auth_rate_allow(const char *ip);        // 1 allowed
void auth_rate_fail(const char *ip);
void auth_rate_reset(const char *ip);

// panel_config helpers (db.c must be open)
char *auth_get_username(void);     // malloc'd, default "admin"
char *auth_get_password_hash(void);// malloc'd or NULL
char *auth_get_session_key(void);  // malloc'd or NULL
int   auth_set_credentials(const char *username, const char *password_hash); // NULL = keep
void  auth_ensure_session_key(void); // generate 64-hex if empty
int   auth_init_schema(char *err, size_t errcap); // create tables at schema v15

#endif

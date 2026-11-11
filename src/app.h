// application layer: routing, sessions, auth glue
#ifndef WDTT_APP_H
#define WDTT_APP_H

#include "http.h"
#include "json.h"

typedef struct {
    const char *config_dir;   // /etc/wdtt
    const char *public_url;   // e.g. https://1.2.3.4:8443
    int         https;        // server is TLS
} AppCfg;

int  app_init(const AppCfg *cfg, char *err, size_t errcap);
void app_handle(const HttpReq *req, HttpRes *res);

// session helpers
// returns session token (64 hex) or NULL; cookie name WDTT_SESS
const char *app_session_token(const HttpReq *req);

// session bridge for api.c
int  app_is_https(void);
int  sess_create_pub(const char *ip, char *token_out, size_t tcap);
void sess_destroy_pub(const char *token);
void sess_destroy_all(void);

// respond helpers
void api_error(HttpRes *res, int status, const char *msg);

#endif

// TCP accept loop + worker threads; routes requests to app handler
#ifndef WDTT_SERVER_H
#define WDTT_SERVER_H

#include "http.h"

typedef void (*ReqHandler)(const HttpReq *req, HttpRes *res);

typedef struct {
    int port;
    SSL_CTX *ssl_ctx;   // NULL => plain HTTP
    ReqHandler handler;
} ServerCfg;

// binds and serves forever; returns only on fatal error (-1)
int server_run(const ServerCfg *cfg);

#endif

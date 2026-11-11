// wdttpanel: entry point. Config from args, then serve (or CLI ops).
#include "api.h"
#include "app.h"
#include "db.h"
#include "http.h"
#include "server.h"
#include "tls.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void) {
    fprintf(stderr,
            "wdttpanel — lightweight VPN panel (C edition)\n"
            "usage: wdttpanel [options]\n"
            "  -config-dir DIR    panel config dir (default /etc/wdtt)\n"
            "  -port N            listen port (default 8443)\n"
            "  -cert FILE         TLS certificate (omit => plain HTTP)\n"
            "  -key FILE          TLS private key\n"
            "  -public-url URL    public base URL for subscription links\n"
            "  -init-panel        create panel.db schema (+ password below)\n"
            "  -set-password PW   set admin password\n"
            "  -version           print version\n");
}

int main(int argc, char **argv) {
    const char *config_dir = "/etc/wdtt";
    const char *public_url = NULL;
    const char *set_password = NULL;
    int port = 8443;
    const char *cert = NULL, *key = NULL;
    int init_panel = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-config-dir") && i + 1 < argc) config_dir = argv[++i];
        else if (!strcmp(argv[i], "-port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-cert") && i + 1 < argc) cert = argv[++i];
        else if (!strcmp(argv[i], "-key") && i + 1 < argc) key = argv[++i];
        else if (!strcmp(argv[i], "-public-url") && i + 1 < argc) public_url = argv[++i];
        else if (!strcmp(argv[i], "-init-panel")) init_panel = 1;
        else if (!strcmp(argv[i], "-set-password") && i + 1 < argc) set_password = argv[++i];
        else if (!strcmp(argv[i], "-version")) { printf("wdttpanel 1.0.0\n"); return 0; }
        else { usage(); return 1; }
    }
    if ((cert && !key) || (!cert && key)) {
        fprintf(stderr, "wdttpanel: -cert and -key must be used together\n");
        return 1;
    }

    // CLI modes: open db (creates config dir), run op, exit
    if (init_panel || set_password) {
        AppCfg app = {config_dir, public_url, cert ? 1 : 0};
        char err[512];
        if (app_init(&app, err, sizeof(err)) != 0) {
            fprintf(stderr, "wdttpanel: init: %s\n", err);
            return 1;
        }
        int rc = 0;
        if (init_panel) {
            rc = api_init_panel(set_password, public_url);
        } else if (set_password) {
            rc = api_set_admin_password(set_password);
        }
        db_close();
        return rc;
    }

    SSL_CTX *ctx = NULL;
    if (cert) {
        char err[256];
        ctx = tls_ctx_new(cert, key, err, sizeof(err));
        if (!ctx) {
            fprintf(stderr, "wdttpanel: TLS init: %s\n", err);
            return 1;
        }
    }

    AppCfg app = {0};
    app.config_dir = config_dir;
    app.public_url = public_url;
    app.https = cert ? 1 : 0;
    char err[512];
    if (app_init(&app, err, sizeof(err)) != 0) {
        fprintf(stderr, "wdttpanel: init: %s\n", err);
        return 1;
    }

    ServerCfg cfg = {0};
    cfg.port = port;
    cfg.ssl_ctx = ctx;
    cfg.handler = app_handle;
    return server_run(&cfg);
}

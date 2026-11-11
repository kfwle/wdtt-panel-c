// API handlers
#ifndef WDTT_API_H
#define WDTT_API_H

#include "http.h"
#include "util.h"

// called with normalized path (no /wdtt prefix). auth/CSRF enforced inside.
void api_dispatch(const HttpReq *req, HttpRes *res, const char *path);

// login/logout/health handled here too; returns 1 if handled
int api_public(const HttpReq *req, HttpRes *res, const char *path);

// CLI: initialize panel db and set admin password (or NULL to keep)
int api_init_panel(const char *admin_password, const char *public_url);
// CLI: set admin password
int api_set_admin_password(const char *pw);

#endif

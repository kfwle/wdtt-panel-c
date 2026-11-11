// protocol server control: protocols.py ops, status, inbound
#ifndef WDTT_PROTO_H
#define WDTT_PROTO_H

#include <stddef.h>

// run protocols.py with op JSON on stdin (50s timeout). stdout JSON malloc'd or NULL.
char *proto_op(const char *op_json, char *err, size_t errcap);

// systemctl is-active <unit> -> 1 active
int svc_active(const char *unit);

// POST /admin/reload to data plane; fallback systemctl restart wdtt. 0 ok
int proto_reload_dataplane(char *err, size_t errcap);

#endif

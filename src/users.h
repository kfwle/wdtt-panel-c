// wdtt_users CRUD + push to WDTT server admin API
#ifndef WDTT_USERS_H
#define WDTT_USERS_H

#include "links.h"
#include <stddef.h>

// load one user; 1 found, 0 missing, -1 error
int users_load(const char *password, WdttUser *out);
int users_load_by_subid(const char *subid, char *password_out, size_t pcap, WdttUser *out);

// iterate users; cb receives each; return nonzero stops
int users_each(int (*cb)(const WdttUser *u, void *ud), void *ud);

// insert or replace; generates sub_id if empty. 0 ok
int users_upsert(WdttUser *u);

// bindings in wdtt_user_devices: replace with device_ids (NULL-terminated array or NULL)
int users_set_devices(const char *password, const char *const *device_ids);

// protocols in vpn_user_inbounds: protocols_json is a JSON array string like ["wdtt","qwdtt"]
int users_get_protocols(const char *subid, Buf *out);        // out: ["wdtt",...]
int users_set_protocols(const char *subid, const char *protocols_json);

int users_rename(const char *old_password, const char *new_password);
int users_delete(const char *password);
int users_reset_traffic(const char *password);

// main VPN password (wdtt_global.main_password)
char *users_main_password(void);
// migrate main to new password carrying the entry row (sub_id preserved). 0 ok
int users_set_main_password(const char *new_main);

// count of active (not expired, not deactivated) users
int users_count_active(void);
int users_max_users(void); // inbound.max_users

// push to data plane admin API (127.0.0.1:2861). 0 ok
int admin_push_user_update(const char *old_password, const char *new_password,
                           const WdttUser *u, const char *const *device_ids, int manage_devices,
                           char *err, size_t errcap);
int admin_push_user_delete(const char *password, char *err, size_t errcap);
int admin_post_reload(const char *addr, char *err, size_t errcap);
void admin_inbound_addr(char *out, size_t cap); // from wdtt_inbound.admin_addr or default
char *admin_session_key(void); // malloc'd session_key (also used as admin token)

// bump wdtt_global.users_rev
void users_bump_rev(void);

#endif

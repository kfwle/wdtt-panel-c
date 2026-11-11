// wdtt:// link building + password/subid generation (byte-compatible with Go panel)
#ifndef WDTT_LINKS_H
#define WDTT_LINKS_H

#include "json.h"
#include "util.h"

#define WDTT_PASS_CHARS "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"

typedef struct {
    char password[129];
    char device_id[130];
    char comment[256];
    char ports[64];       // "dtls,wg,client" or ""
    char vk_hash[512];
    char sub_id[64];
    int  max_devices;
    long long expires_at; // unix seconds, 0 = none
    long long total_bytes;
    long long up_bytes, down_bytes;
    double max_down_mbps;
    double max_up_mbps;
    int  is_deactivated;
    long long last_seen_at;
} WdttUser;

typedef struct {
    char server_host[256];
    char tag[64];
    char remark[128];
    int  enable;
    int  dtls_port;
    int  wg_port;
    int  client_port;
    int  raw_enable;
    int  raw_direct_port;
} WdttInbound;

// resolve user ports: ports override inbound defaults
void resolve_user_ports(const WdttUser *u, const WdttInbound *in, int *dtls, int *wg, int *client);

char *gen_password(void);   // malloc'd 16 chars from WDTT_PASS_CHARS
char *gen_subid(void);      // malloc'd 16 chars [a-z0-9]

// wdtt:// JSON link (BuildPanelLink equivalent).
// host/password required; others may be ""/0.
// raw_port 0 => omitted (client uses DTLS+3)
char *build_panel_link(const char *host, const char *password, const char *user_name,
                       const char *vpn_name, const char *device_id, const char *vk_hash,
                       const char *sub_url, int dtls_port, int raw_port);

// colon link: wdtt://host:dtls:wg:local:pass:hash[,hash..][#name]
// hash_limit: 0 => all hashes, 1 => single (iOS)
char *build_colon_link(const char *host, const char *password, const char *name,
                       const char *vk_hash, int dtls, int wg, int local, int with_name, int hash_limit);

// qwdtt://config?... link (pass raw at end)
char *build_qwdtt_link(const char *host, const char *password, const char *name,
                       const char *vk_hash, int port);

#endif

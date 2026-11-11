#include "server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define WDTT_MAX_BODY (8u * 1024u * 1024u)
#define WDTT_MAX_CONNS 128

static ServerCfg g_cfg;
static volatile int g_active_conns = 0;

static void *worker(void *arg) {
    int fd = *(int *)arg;
    free(arg);
    __atomic_sub_fetch(&g_active_conns, 1, __ATOMIC_RELAXED);

    struct timeval tv = {30, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    SSL *ssl = NULL;
    if (g_cfg.ssl_ctx) {
        ssl = SSL_new(g_cfg.ssl_ctx);
        if (!ssl) goto out;
        SSL_set_fd(ssl, fd);
        for (;;) {
            int r = SSL_accept(ssl);
            if (r == 1) break;
            int err = SSL_get_error(ssl, r);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                SSL_free(ssl);
                goto out;
            }
        }
    }

    Conn conn = {0};
    conn.fd = fd;
    conn.ssl = ssl;

    // client ip
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    char ip[64] = "?";
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) == 0) {
        if (ss.ss_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, ip, sizeof(ip));
        else if (ss.ss_family == AF_INET6)
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, ip, sizeof(ip));
    }

    // keep-alive loop (up to 100 requests per connection)
    for (int served = 0; served < 100; served++) {
        HttpReq req;
        int pr = http_req_parse(&conn, &req, WDTT_MAX_BODY);
        if (pr == -2) {
            const char *msg = "{\"error\":\"body too large\"}";
            Buf b;
            buf_init(&b);
            buf_printf(&b,
                       "HTTP/1.1 413 Payload Too Large\r\nContent-Length: %zu\r\n"
                       "Content-Type: application/json\r\nConnection: close\r\n\r\n%s",
                       strlen(msg), msg);
            conn_write(&conn, b.s, b.len);
            buf_free(&b);
            break;
        }
        if (pr != 0) break;

        snprintf(req.client_ip, sizeof(req.client_ip), "%s", ip);

        HttpRes res;
        http_res_init(&res);
        g_cfg.handler(&req, &res);
        int ka = res.status < 400 || (res.status != 401 && res.status != 403); // keep simple: honor Connection header absence => keep-alive
        if (http_res_send(&conn, &res, ka) != 0) {
            http_req_free(&req);
            http_res_free(&res);
            break;
        }
        http_req_free(&req);
        http_res_free(&res);
    }

    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
out:
    close(fd);
    return NULL;
}

int server_run(const ServerCfg *cfg) {
    g_cfg = *cfg;
    signal(SIGPIPE, SIG_IGN);

    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC); // don't leak the listener into forked children
    int no = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)); // dual-stack
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons((uint16_t)cfg->port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "wdttpanel: cannot bind port %d: %s\n", cfg->port, strerror(errno));
        return -1;
    }
    if (listen(fd, 128) < 0) {
        perror("listen");
        return -1;
    }

    fprintf(stderr, "[wdttpanel] listening on %s://0.0.0.0:%d (dual-stack)\n",
            cfg->ssl_ctx ? "https" : "http", cfg->port);

    for (;;) {
        int cfd = accept(fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        // shed load: hard cap on concurrent worker threads
        if (__atomic_add_fetch(&g_active_conns, 1, __ATOMIC_RELAXED) > WDTT_MAX_CONNS) {
            __atomic_sub_fetch(&g_active_conns, 1, __ATOMIC_RELAXED);
            close(cfd);
            continue;
        }
        int *arg = xmalloc(sizeof(int));
        *arg = cfd;
        pthread_t t;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&attr, 512 * 1024);
        if (pthread_create(&t, &attr, worker, arg) != 0) {
            // fallback: handle inline
            worker(arg);
            pthread_attr_destroy(&attr);
            continue;
        }
        pthread_detach(t);
        pthread_attr_destroy(&attr);
    }
    return 0;
}

#include "proto.h"
#include "users.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define PY_TIMEOUT_MS 50000

char *proto_op(const char *op_json, char *err, size_t errcap) {
    int inpipe[2], outpipe[2];
    if (pipe(inpipe) != 0 || pipe(outpipe) != 0) {
        snprintf(err, errcap, "pipe: %s", strerror(errno));
        return NULL;
    }
    pid_t pid = fork();
    if (pid < 0) {
        snprintf(err, errcap, "fork: %s", strerror(errno));
        close(inpipe[0]); close(inpipe[1]);
        close(outpipe[0]); close(outpipe[1]);
        return NULL;
    }
    if (pid == 0) {
        dup2(inpipe[0], 0);
        dup2(outpipe[1], 1);
        dup2(outpipe[1], 2);
        close(inpipe[0]); close(inpipe[1]);
        close(outpipe[0]); close(outpipe[1]);
        execl("/usr/bin/python3", "python3", "/usr/local/lib/wdtt/protocols.py", (char *)NULL);
        _exit(127);
    }
    close(inpipe[0]);
    close(outpipe[1]);

    if (write(inpipe[1], op_json, strlen(op_json)) < 0 || write(inpipe[1], "\n", 1) < 0) {
        // child may have exited early; ignore
    }
    close(inpipe[1]);

    Buf out;
    buf_init(&out);
    char tmp[4096];
    struct pollfd pfd = {outpipe[0], POLLIN, 0};
    long long deadline = now_ms() + PY_TIMEOUT_MS;
    int status = 0, exited = 0;
    for (;;) {
        long long left = deadline - now_ms();
        if (left <= 0) {
            kill(pid, SIGKILL);
            snprintf(err, errcap, "protocols.py: timeout 50s");
            buf_free(&out);
            close(outpipe[0]);
            waitpid(pid, &status, 0);
            return NULL;
        }
        int pr = poll(&pfd, 1, (int)(left > 500 ? 500 : left));
        if (pr > 0) {
            char tmp[4096];
            ssize_t r = read(outpipe[0], tmp, sizeof(tmp));
            if (r > 0) {
                buf_append(&out, tmp, (size_t)r);
                if (out.len > 4 * 1024 * 1024) break;
                continue;
            }
            if (r == 0) break; // EOF: child closed stdout
        }
        // check child exit (means pipes will close soon)
        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid) {
            exited = 1;
            // drain remaining output
            for (;;) {
                ssize_t r = read(outpipe[0], tmp, sizeof(tmp));
                if (r <= 0) break;
                buf_append(&out, tmp, (size_t)r);
            }
            break;
        }
    }
    close(outpipe[0]);
    if (!exited) waitpid(pid, &status, 0);

    if (!out.s || !out.s[0]) {
        snprintf(err, errcap, "protocols.py: empty response (exit %d)", WEXITSTATUS(status));
        buf_free(&out);
        return NULL;
    }
    return buf_detach(&out);
}

int svc_active(const char *unit) {
    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, 1);
            dup2(devnull, 2);
        }
        execl("/bin/sh", "sh", "-c", "systemctl is-active --quiet \"$1\"", "sh", unit, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int proto_reload_dataplane(char *err, size_t errcap) {
    // POST /admin/reload with empty body
    char addr[128];
    admin_inbound_addr(addr, sizeof(addr));
    // reuse admin_post via a delete-style empty post: build minimal request
    // (admin_post is static in users.c; expose through helper there)
    extern int admin_post_reload(const char *addr, char *err, size_t errcap);
    int rc = admin_post_reload(addr, err, errcap);
    if (rc != 0) {
        // fallback: restart service
        pid_t pid = fork();
        if (pid == 0) {
            execl("/bin/systemctl", "systemctl", "restart", "wdtt", (char *)NULL);
            _exit(127);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
    }
    return 0;
}

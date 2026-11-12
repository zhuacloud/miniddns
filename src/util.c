/* util.c — §03 paths / permissions, small pure helpers */
#include "util.h"
#include "log.h"
#include "cfg.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

const char *mn_err_name(int rc)
{
    switch (rc) {
    case MN_OK:             return "MN_OK";
    case E_CFG:             return "E_CFG";
    case E_DNS:             return "E_DNS";
    case E_CONNECT:         return "E_CONNECT";
    case E_TIMEOUT:         return "E_TIMEOUT";
    case E_TLS_HANDSHAKE:   return "E_TLS_HANDSHAKE";
    case E_TLS_CERT:        return "E_TLS_CERT";
    case E_TLS_TIME:        return "E_TLS_TIME";
    case E_HTTP_STATUS:     return "E_HTTP_STATUS";
    case E_RATELIMIT:       return "E_RATELIMIT";
    case E_PARSE:           return "E_PARSE";
    case E_API:             return "E_API";
    case E_CA_LOAD:         return "E_CA_LOAD";
    case E_NO_IP:           return "E_NO_IP";
    case E_BUSY:            return "E_BUSY";
    default:                return "E_UNKNOWN";
    }
}

int64_t mn_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

time_t mn_wall(void) { return time(NULL); }

static int is_space_ch(int c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'; }

char *mn_trim(char *s)
{
    char *e;
    if (!s) return s;
    while (*s && is_space_ch((unsigned char)*s)) s++;
    e = s + strlen(s);
    while (e > s && is_space_ch((unsigned char)e[-1])) e--;
    *e = '\0';
    return s;
}

int mn_strlcpy(char *dst, size_t cap, const char *src)
{
    int n;
    if (cap == 0) return -1;
    n = snprintf(dst, cap, "%s", src);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

int mn_strlcat(char *dst, size_t cap, const char *src)
{
    size_t used = strlen(dst);
    int n;
    if (used >= cap) return -1;
    n = snprintf(dst + used, cap - used, "%s", src);
    return (n < 0 || (size_t)n >= cap - used) ? -1 : 0;
}

void mn_secure_zero(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n-- > 0) *q++ = 0;
}

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;
    if (!err || errlen == 0) return;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static void parent_dir(const char *path, char *out, size_t cap)
{
    const char *slash = strrchr(path, '/');
    if (!slash) { snprintf(out, cap, "."); return; }
    if (slash == path) { snprintf(out, cap, "/"); return; }
    size_t n = (size_t)(slash - path);
    if (n >= cap) n = cap - 1;
    memcpy(out, path, n);
    out[n] = '\0';
}

/* §03: probe concrete FILES, not directories. readlink("/proc/self/exe"). */
int mn_find_artifact_root(char *out, size_t cap)
{
    char exe[MN_PATH_MAX], dir[MN_PATH_MAX], updir[MN_PATH_MAX], probe[MN_PATH_MAX * 2];
    ssize_t n;
    out[0] = '\0';
    n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) return 0;
    exe[n] = '\0';
    parent_dir(exe, dir, sizeof(dir));
    snprintf(probe, sizeof(probe), "%s/conf/miniddns.conf", dir);
    if (access(probe, F_OK) == 0) { snprintf(out, cap, "%s", dir); return 1; }
    snprintf(probe, sizeof(probe), "%s/ca/ca-certificates.crt", dir);
    if (access(probe, F_OK) == 0) { snprintf(out, cap, "%s", dir); return 1; }
    parent_dir(dir, updir, sizeof(updir));
    snprintf(probe, sizeof(probe), "%s/conf/miniddns.conf", updir);
    if (access(probe, F_OK) == 0) { snprintf(out, cap, "%s", updir); return 1; }
    snprintf(probe, sizeof(probe), "%s/ca/ca-certificates.crt", updir);
    if (access(probe, F_OK) == 0) { snprintf(out, cap, "%s", updir); return 1; }
    return 0;
}

int mn_resolve_conf_path(const char *cli_path, const char *root,
                         char *out, size_t cap, char *err, size_t errlen)
{
    char cand[MN_PATH_MAX];
    if (cli_path && cli_path[0]) {
        if (access(cli_path, F_OK) != 0) {
            set_err(err, errlen, "config not found path=%s", cli_path);
            return -1;
        }
        return mn_strlcpy(out, cap, cli_path);
    }
    if (root && root[0]) {
        if (snprintf(cand, sizeof(cand), "%s/conf/miniddns.conf", root) < (int)sizeof(cand)
            && access(cand, F_OK) == 0)
            return mn_strlcpy(out, cap, cand);
    }
    if (access("/etc/miniddns/miniddns.conf", F_OK) == 0)
        return mn_strlcpy(out, cap, "/etc/miniddns/miniddns.conf");
    set_err(err, errlen, "no config file; tried %s/conf/miniddns.conf and /etc/miniddns/miniddns.conf",
            (root && root[0]) ? root : "<root>");
    return -1;
}

int mn_resolve_ca_path(const struct mn_cfg *cfg, char *out, size_t cap,
                       char *err, size_t errlen)
{
    static const char *sys_candidates[] = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
        "/etc/ssl/ca-bundle.pem"
    };
    char cand[MN_PATH_MAX];
    size_t i;
    if (cfg->core.ca_bundle[0]) {
        if (access(cfg->core.ca_bundle, F_OK) != 0) {
            set_err(err, errlen, "ca_bundle not found path=%s", cfg->core.ca_bundle);
            return -1;
        }
        return mn_strlcpy(out, cap, cfg->core.ca_bundle);
    }
    if (cfg->has_root) {
        if (snprintf(cand, sizeof(cand), "%s/ca/ca-certificates.crt", cfg->root) < (int)sizeof(cand)
            && access(cand, F_OK) == 0)
            return mn_strlcpy(out, cap, cand);
    }
    for (i = 0; i < sizeof(sys_candidates) / sizeof(sys_candidates[0]); i++) {
        if (access(sys_candidates[i], F_OK) == 0)
            return mn_strlcpy(out, cap, sys_candidates[i]);
    }
    set_err(err, errlen, "no CA bundle; tried <root>/ca, /etc/ssl/certs/ca-certificates.crt, "
            "/etc/pki/tls/certs/ca-bundle.crt, /etc/ssl/cert.pem, /etc/ssl/ca-bundle.pem");
    return -1;
}

/* §03 graded symlink policy + size/owner/mode checks.
   Returns 0 ok, -1 otherwise (err describes which check failed). */
int mn_checked_read(const char *path, int cls, char *buf, size_t cap,
                    size_t *len, int allow_non_root_owner,
                    char *err, size_t errlen)
{
    char resolved[PATH_MAX], real[MN_PATH_MAX];
    struct stat st;
    int fd;
    size_t total = 0, maxsize, maxread;
    const char *obj = (cls == MN_FILE_TOKEN) ? "token" : (cls == MN_FILE_CA ? "ca" : "config");

    if (!path || !path[0] || !buf || cap == 0) {
        set_err(err, errlen, "%s: empty path or buffer", obj); return -1;
    }
    maxsize = (cls == MN_FILE_CA) ? MN_LIMIT_CA_FILE : MN_LIMIT_CONF_FILE;
    if (cls == MN_FILE_TOKEN) maxsize = MN_LIMIT_TOKEN_FILE;

    if (cls == MN_FILE_TOKEN) {
        fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            set_err(err, errlen, "token: open failed path=%s errno=%d%s", path, errno,
                    (errno == ELOOP ? " (symlink rejected)" : ""));
            return -1;
        }
        if (snprintf(real, sizeof(real), "%s", path) >= (int)sizeof(real)) { close(fd); return -1; }
    } else {
        if (!realpath(path, resolved)) {
            set_err(err, errlen, "%s: realpath failed path=%s errno=%d", obj, path, errno);
            return -1;
        }
        fd = open(resolved, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            set_err(err, errlen, "%s: open failed path=%s errno=%d", obj, resolved, errno);
            return -1;
        }
        if (mn_strlcpy(real, sizeof(real), resolved) != 0) { close(fd); return -1; }
    }

    if (fstat(fd, &st) != 0) {
        set_err(err, errlen, "%s: fstat failed path=%s errno=%d", obj, real, errno);
        close(fd); return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        set_err(err, errlen, "%s: not a regular file path=%s", obj, real);
        close(fd); return -1;
    }
    if (st.st_uid != 0 && !allow_non_root_owner) {
        set_err(err, errlen, "%s: owner is not root path=%s (use --allow-non-root-owner)", obj, real);
        close(fd); return -1;
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        set_err(err, errlen, "%s: group/world writable path=%s", obj, real);
        close(fd); return -1;
    }
    if ((size_t)st.st_size > maxsize) {
        set_err(err, errlen, "%s: file too large path=%s size=%lld limit=%zu", obj, real,
                (long long)st.st_size, maxsize);
        close(fd); return -1;
    }
    if ((size_t)st.st_size >= cap) {
        set_err(err, errlen, "%s: read buffer too small path=%s", obj, real);
        close(fd); return -1;
    }
    /* §03: CA bundle realpath must stay inside trusted directories. */
    if (cls == MN_FILE_CA) {
        char root[MN_PATH_MAX], inside[MN_PATH_MAX];
        int ok = 0;
        if (strncmp(real, "/etc/", 5) == 0 || strncmp(real, "/usr/share/", 11) == 0) ok = 1;
        if (!ok && mn_find_artifact_root(root, sizeof(root)) && root[0]) {
            if (snprintf(inside, sizeof(inside), "%s/", root) < (int)sizeof(inside)
                && strncmp(real, inside, strlen(inside)) == 0) ok = 1;
        }
        if (!ok) {
            set_err(err, errlen, "ca: path outside whitelist path=%s", real);
            close(fd); return -1;
        }
    }

    maxread = cap - 1;
    if (maxread > maxsize) maxread = maxsize;
    while (total < maxread) {
        ssize_t r = read(fd, buf + total, maxread - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            set_err(err, errlen, "%s: read failed path=%s errno=%d", obj, real, errno);
            close(fd); return -1;
        }
        if (r == 0) break;
        total += (size_t)r;
    }
    if (total == maxread) {
        unsigned char extra;
        ssize_t r;
        do {
            r = read(fd, &extra, 1);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            set_err(err, errlen, "%s: read failed path=%s errno=%d", obj, real, errno);
            close(fd); return -1;
        }
        if (r > 0) {
            if (maxread < maxsize)
                set_err(err, errlen, "%s: read buffer too small path=%s", obj, real);
            else
                set_err(err, errlen, "%s: file too large path=%s", obj, real);
            close(fd); return -1;
        }
    }
    close(fd);
    buf[total] = '\0';
    if (len) *len = total;
    return 0;
}

int mn_expand_creds_dir(const char *value, char *out, size_t cap,
                        int diagnostic, int *skipped, char *err, size_t errlen)
{
    const char *env;
    if (skipped) *skipped = 0;
    if (strncmp(value, "$CREDENTIALS_DIRECTORY/", 23) != 0)
        return mn_strlcpy(out, cap, value);
    env = getenv("CREDENTIALS_DIRECTORY");
    if (!env || !env[0]) {
        if (diagnostic) {
            mn_log(MN_LOG_WARN, "credentials_directory_missing skip=1 hint=systemd_LoadCredential");
            if (skipped) *skipped = 1;
            out[0] = '\0';
            return 0;
        }
        set_err(err, errlen, "token_file needs $CREDENTIALS_DIRECTORY (systemd LoadCredential=) but it is unset");
        return -1;
    }
    if (snprintf(out, cap, "%s/%s", env, value + 23) >= (int)cap) {
        set_err(err, errlen, "token_file path too long");
        return -1;
    }
    return 0;
}

int mn_parse_https_url(const char *url, char *host, size_t hostcap,
                       int *port, char *path, size_t pathcap,
                       char *err, size_t errlen)
{
    const char *p, *h, *q;
    size_t hlen;
    if (strncasecmp(url, "https://", 8) != 0) {
        set_err(err, errlen, "url must be https url=%s", url); return -1;
    }
    p = url + 8;
    h = p;
    while (*p && *p != '/' && *p != ':' && *p != '?' && *p != '@') p++;
    if (*p == '@') { set_err(err, errlen, "url userinfo not allowed"); return -1; }
    hlen = (size_t)(p - h);
    if (hlen == 0 || hlen >= hostcap) {
        set_err(err, errlen, "url host empty or too long"); return -1;
    }
    memcpy(host, h, hlen); host[hlen] = '\0';
    *port = 443;
    if (*p == ':') {
        long v = 0; const char *d = ++p;
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; if (v > 65535) break; }
        if (p == d || v <= 0 || v > 65535) { set_err(err, errlen, "url bad port"); return -1; }
        *port = (int)v;
    }
    if (*p == '\0' || *p == '?') {
        if (*p == '?') {
            if (snprintf(path, pathcap, "/%s", p) >= (int)pathcap) { set_err(err, errlen, "url path too long"); return -1; }
        } else {
            snprintf(path, pathcap, "/");
        }
    } else {
        q = p;
        if (snprintf(path, pathcap, "%s", q) >= (int)pathcap) { set_err(err, errlen, "url path too long"); return -1; }
    }
    return 0;
}

int mn_iface_match(const char *pattern, const char *name)
{
    size_t n;
    while (*pattern == ' ' || *pattern == '\t') pattern++;
    n = strlen(pattern);
    while (n > 0 && (pattern[n-1] == ' ' || pattern[n-1] == '\t')) n--;
    if (n == 0) return 0;
    if (pattern[n-1] == '*') return strncmp(pattern, name, n - 1) == 0;
    return strlen(name) == n && strncmp(pattern, name, n) == 0;
}

const char *mn_mask(const char *s, char *out, size_t cap)
{
    size_t n = s ? strlen(s) : 0;
    if (n == 0) { snprintf(out, cap, "****"); return out; }
    if (n <= 8) { snprintf(out, cap, "****"); return out; }
    snprintf(out, cap, "%c%c****%c%c", s[0], s[1], s[n-2], s[n-1]);
    return out;
}

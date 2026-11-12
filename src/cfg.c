/* cfg.c — §04 strict INI subset, defaults, cross validation, §03 path resolution */
#include "cfg.h"
#include "util.h"
#include "log.h"
#include "provider.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define CFG_ERR_MAX 512

enum { SEC_NONE = 0, SEC_CORE, SEC_DETECT, SEC_PROVIDER, SEC_RECORD };

/* key ids, also used as bit positions for duplicate detection */
enum {
    K_INSTANCE, K_FALLBACK, K_DEBOUNCE, K_MEMO, K_CA_BUNDLE, K_HTTP_TIMEOUT,
    K_CONNECT_TIMEOUT, K_BACKOFF, K_LOG_LEVEL, K_LOG_TARGET, K_LOG_FILE,
    K_LOCK_FILE, K_CLOCK_GUARD, K_CORE_MAX
};
enum {
    D_IPV4_MODE, D_IPV6_MODE, D_IFACE_INCLUDE, D_IFACE_EXCLUDE, D_ECHO_URL,
    D_ALLOW_PRIVATE, D_ALLOW_TEMP, D_MAX
};
enum { P_ID, P_KIND, P_ZONE, P_TOKEN_FILE, P_TOKEN, P_MAX };
enum { R_PROVIDER, R_NAME, R_TYPE, R_TTL, R_PROXIED, R_CREATE, R_ENABLED, R_MAX };

static const char *core_keys[K_CORE_MAX] = {
    "instance", "interval_fallback", "debounce_ms", "write_memo_ms", "ca_bundle",
    "http_timeout_ms", "connect_timeout_ms", "retry_backoff", "log_level",
    "log_target", "log_file", "lock_file", "clock_guard_epoch"
};
static const char *detect_keys[D_MAX] = {
    "ipv4_mode", "ipv6_mode", "iface_include", "iface_exclude", "ipv4_echo_url",
    "allow_private_ipv4", "allow_temporary_ipv6"
};
static const char *prov_keys[P_MAX] = {
    "id", "kind", "zone_id", "token_file", "token"
};
static const char *rec_keys[R_MAX] = {
    "provider", "name", "type", "ttl", "proxied", "create_if_missing", "enabled"
};

static const char *ip4_mode_names[] = { "off", "iface", "external", "auto" };
static const char *ip6_mode_names[] = { "off", "iface" };

const char *mn_log_level_name(int level)
{
    switch (level) {
    case MN_LOG_ERROR: return "error";
    case MN_LOG_WARN:  return "warn";
    case MN_LOG_INFO:  return "info";
    case MN_LOG_DEBUG: return "debug";
    default:           return "info";
    }
}

int mn_log_level_parse(const char *s, int *out)
{
    if (!strcasecmp(s, "error")) { *out = MN_LOG_ERROR; return 0; }
    if (!strcasecmp(s, "warn"))  { *out = MN_LOG_WARN;  return 0; }
    if (!strcasecmp(s, "info"))  { *out = MN_LOG_INFO;  return 0; }
    if (!strcasecmp(s, "debug")) { *out = MN_LOG_DEBUG; return 0; }
    return -1;
}

const char *mn_ip4_mode_name(int m)
{
    return (m >= 0 && m <= MN_IP4_AUTO) ? ip4_mode_names[m] : "?";
}
const char *mn_ip6_mode_name(int m)
{
    return (m >= 0 && m <= MN_IP6_IFACE) ? ip6_mode_names[m] : "?";
}

void mn_cfg_defaults(struct mn_cfg *cfg, const char *root)
{
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->core.instance, sizeof(cfg->core.instance), "default");
    cfg->core.interval_fallback = 900;
    cfg->core.debounce_ms = 1500;
    cfg->core.write_memo_ms = 60000;
    cfg->core.http_timeout_ms = 8000;
    cfg->core.connect_timeout_ms = 5000;
    cfg->core.retry_backoff[0] = 5;
    cfg->core.retry_backoff[1] = 15;
    cfg->core.retry_backoff[2] = 60;
    cfg->core.retry_backoff[3] = 300;
    cfg->core.n_backoff = 4;
    cfg->core.log_level = MN_LOG_INFO;
    cfg->core.log_target = MN_LOG_JOURNALD;
    cfg->core.clock_guard_epoch = 1700000000;
    cfg->detect.ipv4_mode = MN_IP4_AUTO;
    cfg->detect.ipv6_mode = MN_IP6_IFACE;
    snprintf(cfg->detect.iface_exclude, sizeof(cfg->detect.iface_exclude),
             "lo,docker0,veth*,br-*,virbr*,tun*,tap*,wg*");
    snprintf(cfg->detect.ipv4_echo_url, sizeof(cfg->detect.ipv4_echo_url),
             "https://api.ipify.org,https://ipv4.icanhazip.com,https://ipv4.ident.me");
    if (root && root[0]) {
        snprintf(cfg->root, sizeof(cfg->root), "%s", root);
        cfg->has_root = 1;
    }
}

struct parser {
    struct mn_cfg *cfg;
    int section;
    int index;
    uint64_t seen;
    int seen_core, seen_detect;
    uint64_t seen_core_mask, seen_detect_mask;
    char err[CFG_ERR_MAX];
};

static void perr(struct parser *ps, int line, const char *fmt, ...)
{
    va_list ap;
    char msg[384];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    snprintf(ps->err, sizeof(ps->err), "line=%d %s", line, msg);
}

static int lookup_key(const char *const *keys, int n, const char *key)
{
    int i;
    for (i = 0; i < n; i++) if (strcasecmp(keys[i], key) == 0) return i;
    return -1;
}

static int parse_int(const char *v, long lo, long hi, int *out)
{
    char *end;
    long x;
    if (!v || !v[0]) return -1;
    errno = 0;
    x = strtol(v, &end, 10);
    if (errno || *end != '\0' || x < lo || x > hi) return -1;
    *out = (int)x;
    return 0;
}

static int parse_bool(const char *v, int *out)
{
    if (!strcasecmp(v, "true") || !strcasecmp(v, "yes") || !strcasecmp(v, "on") || !strcmp(v, "1")) {
        *out = 1; return 0;
    }
    if (!strcasecmp(v, "false") || !strcasecmp(v, "no") || !strcasecmp(v, "off") || !strcmp(v, "0")) {
        *out = 0; return 0;
    }
    return -1;
}

static int parse_enum(const char *v, const char *const *names, int n, int *out)
{
    int i;
    for (i = 0; i < n; i++) if (strcasecmp(names[i], v) == 0) { *out = i; return 0; }
    return -1;
}

static int set_str(char *dst, size_t cap, const char *v, struct parser *ps,
                   int line, const char *key)
{
    if (mn_strlcpy(dst, cap, v) != 0) {
        perr(ps, line, "value too long key=%s", key);
        return -1;
    }
    return 0;
}

static int parse_backoff(const char *v, struct parser *ps, int line)
{
    struct mn_cfg *c = ps->cfg;
    char buf[512], *p;
    size_t n = 0;
    if (snprintf(buf, sizeof(buf), "%s", v) >= (int)sizeof(buf)) {
        perr(ps, line, "retry_backoff too long"); return -1;
    }
    p = buf;
    while (*p) {
        char *comma = strchr(p, ',');
        int val;
        if (comma) *comma = '\0';
        if (parse_int(mn_trim(p), 1, 86400, &val) != 0) {
            perr(ps, line, "retry_backoff item invalid value=%s", p); return -1;
        }
        if (n >= MN_BACKOFF_MAX) {
            perr(ps, line, "retry_backoff max_items=%d", MN_BACKOFF_MAX); return -1;
        }
        c->core.retry_backoff[n++] = val;
        if (!comma) break;
        p = comma + 1;
    }
    if (n == 0) { perr(ps, line, "retry_backoff empty"); return -1; }
    c->core.n_backoff = n;
    return 0;
}

static int parse_core(struct parser *ps, int id, const char *v, int line)
{
    struct mn_cfg *c = ps->cfg;
    int iv;
    switch (id) {
    case K_INSTANCE:
        {
            size_t i, n = strlen(v);
            if (n == 0 || n > 32) { perr(ps, line, "instance length invalid"); return -1; }
            for (i = 0; i < n; i++) {
                unsigned char ch = (unsigned char)v[i];
                if (!(isalnum(ch) || ch == '.' || ch == '_' || ch == '-')) {
                    perr(ps, line, "instance invalid char"); return -1;
                }
            }
            return set_str(c->core.instance, sizeof(c->core.instance), v, ps, line, "instance");
        }
    case K_FALLBACK:
        if (parse_int(v, 0, 86400, &iv)) { perr(ps, line, "interval_fallback range=0..86400"); return -1; }
        c->core.interval_fallback = iv; return 0;
    case K_DEBOUNCE:
        if (parse_int(v, 100, 60000, &iv)) { perr(ps, line, "debounce_ms range=100..60000"); return -1; }
        c->core.debounce_ms = iv; return 0;
    case K_MEMO:
        if (parse_int(v, 0, 600000, &iv)) { perr(ps, line, "write_memo_ms range=0..600000"); return -1; }
        c->core.write_memo_ms = iv; return 0;
    case K_CA_BUNDLE:      return set_str(c->core.ca_bundle, sizeof(c->core.ca_bundle), v, ps, line, "ca_bundle");
    case K_HTTP_TIMEOUT:
        if (parse_int(v, 100, 600000, &iv)) { perr(ps, line, "http_timeout_ms range=100..600000"); return -1; }
        c->core.http_timeout_ms = iv; return 0;
    case K_CONNECT_TIMEOUT:
        if (parse_int(v, 100, 600000, &iv)) { perr(ps, line, "connect_timeout_ms range=100..600000"); return -1; }
        c->core.connect_timeout_ms = iv; return 0;
    case K_BACKOFF:         return parse_backoff(v, ps, line);
    case K_LOG_LEVEL:
        if (mn_log_level_parse(v, &iv)) { perr(ps, line, "log_level enum=error|warn|info|debug"); return -1; }
        c->core.log_level = iv; return 0;
    case K_LOG_TARGET:
        if (!strcasecmp(v, "journald")) c->core.log_target = MN_LOG_JOURNALD;
        else if (!strcasecmp(v, "file")) c->core.log_target = MN_LOG_FILE;
        else { perr(ps, line, "log_target enum=journald|file"); return -1; }
        return 0;
    case K_LOG_FILE:        return set_str(c->core.log_file, sizeof(c->core.log_file), v, ps, line, "log_file");
    case K_LOCK_FILE:       return set_str(c->core.lock_file, sizeof(c->core.lock_file), v, ps, line, "lock_file");
    case K_CLOCK_GUARD:
        if (parse_int(v, 0, 2147483647, &iv)) { perr(ps, line, "clock_guard_epoch invalid"); return -1; }
        c->core.clock_guard_epoch = (time_t)iv; return 0;
    }
    return -1;
}

static int parse_detect(struct parser *ps, int id, const char *v, int line)
{
    struct mn_cfg *c = ps->cfg;
    int iv;
    switch (id) {
    case D_IPV4_MODE:
        if (parse_enum(v, ip4_mode_names, 4, &iv)) { perr(ps, line, "ipv4_mode enum=off|iface|external|auto"); return -1; }
        c->detect.ipv4_mode = iv; return 0;
    case D_IPV6_MODE:
        if (parse_enum(v, ip6_mode_names, 2, &iv)) { perr(ps, line, "ipv6_mode enum=off|iface"); return -1; }
        c->detect.ipv6_mode = iv; return 0;
    case D_IFACE_INCLUDE:   return set_str(c->detect.iface_include, sizeof(c->detect.iface_include), v, ps, line, "iface_include");
    case D_IFACE_EXCLUDE:   return set_str(c->detect.iface_exclude, sizeof(c->detect.iface_exclude), v, ps, line, "iface_exclude");
    case D_ECHO_URL:        return set_str(c->detect.ipv4_echo_url, sizeof(c->detect.ipv4_echo_url), v, ps, line, "ipv4_echo_url");
    case D_ALLOW_PRIVATE:
        if (parse_bool(v, &iv)) { perr(ps, line, "allow_private_ipv4 bool"); return -1; }
        c->detect.allow_private_ipv4 = iv; return 0;
    case D_ALLOW_TEMP:
        if (parse_bool(v, &iv)) { perr(ps, line, "allow_temporary_ipv6 bool"); return -1; }
        c->detect.allow_temporary_ipv6 = iv; return 0;
    }
    return -1;
}

static int parse_provider(struct parser *ps, int id, const char *v, int line)
{
    struct mn_provider_cfg *p = &ps->cfg->providers[ps->index];
    switch (id) {
    case P_ID:       return set_str(p->id, sizeof(p->id), v, ps, line, "id");
    case P_KIND:     return set_str(p->kind, sizeof(p->kind), v, ps, line, "kind");
    case P_ZONE:     return set_str(p->zone_id, sizeof(p->zone_id), v, ps, line, "zone_id");
    case P_TOKEN_FILE: return set_str(p->token_file, sizeof(p->token_file), v, ps, line, "token_file");
    case P_TOKEN:
        if (set_str(p->token_inline, sizeof(p->token_inline), v, ps, line, "token")) return -1;
        p->has_token_inline = 1; return 0;
    }
    return -1;
}

static int parse_record(struct parser *ps, int id, const char *v, int line)
{
    struct mn_record_cfg *r = &ps->cfg->records[ps->index];
    int iv;
    switch (id) {
    case R_PROVIDER: return set_str(r->provider_id, sizeof(r->provider_id), v, ps, line, "provider");
    case R_NAME:     return set_str(r->name, sizeof(r->name), v, ps, line, "name");
    case R_TYPE:
        if (!strcasecmp(v, "A")) r->family = AF_INET;
        else if (!strcasecmp(v, "AAAA")) r->family = AF_INET6;
        else { perr(ps, line, "type enum=A|AAAA"); return -1; }
        return 0;
    case R_TTL:
        if (parse_int(v, 1, 86400, &iv)) { perr(ps, line, "ttl range=1(auto) or 60..86400"); return -1; }
        if (iv != 1 && iv < 60) { perr(ps, line, "ttl must be 1 or 60..86400"); return -1; }
        r->ttl = iv; return 0;
    case R_PROXIED:
        if (parse_bool(v, &iv)) { perr(ps, line, "proxied bool"); return -1; }
        r->proxied = iv; return 0;
    case R_CREATE:
        if (parse_bool(v, &iv)) { perr(ps, line, "create_if_missing bool"); return -1; }
        r->create_if_missing = iv; return 0;
    case R_ENABLED:
        if (parse_bool(v, &iv)) { perr(ps, line, "enabled bool"); return -1; }
        r->enabled = iv; return 0;
    }
    return -1;
}

static int parse_lines(struct parser *ps, char *buf)
{
    char *p = buf;
    int line = 0;
    while (*p || line == 0) {
        char *eol = strchr(p, '\n');
        char *linebuf = p, *s, *eq, *key, *val, *tmp;
        int id, nkeys;
        const char *const *keys;
        uint64_t *seen;
        line++;
        if (eol) { *eol = '\0'; p = eol + 1; } else { p += strlen(p); }
        s = mn_trim(linebuf);
        if (*s == '\0' || *s == '#' || *s == ';') { if (!eol) break; continue; }
        if (*s == '[') {
            char *close = strrchr(s, ']');
            size_t n;
            if (!close || close[1] != '\0') { perr(ps, line, "bad section header"); return -1; }
            *close = '\0';
            n = (size_t)(close - (s + 1));
            tmp = s + 1;
            /* trailing spaces inside the header are not allowed by the strict subset */
            if (!strcasecmp(tmp, "core")) {
                if (ps->seen_core) { perr(ps, line, "duplicate section=core"); return -1; }
                ps->section = SEC_CORE; ps->seen_core = 1; ps->seen = 0;
            } else if (!strcasecmp(tmp, "detect")) {
                if (ps->seen_detect) { perr(ps, line, "duplicate section=detect"); return -1; }
                ps->section = SEC_DETECT; ps->seen_detect = 1; ps->seen = 0;
            } else if (!strcasecmp(tmp, "provider")) {
                if (ps->cfg->n_providers >= MN_MAX_PROVIDERS) { perr(ps, line, "too many [provider]"); return -1; }
                ps->section = SEC_PROVIDER; ps->index = (int)ps->cfg->n_providers++;
                ps->cfg->providers[ps->index].line = line;
                ps->seen = 0;
            } else if (!strcasecmp(tmp, "record")) {
                struct mn_record_cfg *r;
                if (ps->cfg->n_records >= MN_MAX_RECORDS) { perr(ps, line, "too many [record]"); return -1; }
                ps->section = SEC_RECORD; ps->index = (int)ps->cfg->n_records++;
                r = &ps->cfg->records[ps->index];
                r->line = line; r->ttl = 60; r->create_if_missing = 1; r->enabled = 1;
                ps->seen = 0;
            } else {
                perr(ps, line, "unknown section=%s", tmp); return -1;
            }
            (void)n;
            if (!eol) break;
            continue;
        }
        if (ps->section == SEC_NONE) { perr(ps, line, "key outside section"); return -1; }
        eq = strchr(s, '=');
        if (!eq) { perr(ps, line, "missing '='"); return -1; }
        *eq = '\0';
        key = mn_trim(s);
        val = mn_trim(eq + 1);
        if (*key == '\0') { perr(ps, line, "empty key"); return -1; }
        {
            char lower[64];
            size_t i;
            if (strlen(key) >= sizeof(lower)) { perr(ps, line, "key too long"); return -1; }
            for (i = 0; key[i]; i++) lower[i] = (char)tolower((unsigned char)key[i]);
            lower[i] = '\0';
            snprintf(key, strlen(key) + 1, "%s", lower);
        }
        switch (ps->section) {
        case SEC_CORE:     keys = core_keys;   nkeys = K_CORE_MAX;   seen = &ps->seen_core_mask; break;
        case SEC_DETECT:   keys = detect_keys; nkeys = D_MAX;        seen = &ps->seen_detect_mask; break;
        case SEC_PROVIDER: keys = prov_keys;   nkeys = P_MAX;        seen = &ps->seen; break;
        default:           keys = rec_keys;    nkeys = R_MAX;        seen = &ps->seen; break;
        }
        id = lookup_key(keys, nkeys, key);
        if (id < 0) {
            perr(ps, line, "unknown key=%s section=%d", key, ps->section);
            return -1;
        }
        if (*seen & (1ull << id)) {
            perr(ps, line, "duplicate key=%s", key);
            return -1;
        }
        *seen |= (1ull << id);
        switch (ps->section) {
        case SEC_CORE:     if (parse_core(ps, id, val, line)) return -1; break;
        case SEC_DETECT:   if (parse_detect(ps, id, val, line)) return -1; break;
        case SEC_PROVIDER: if (parse_provider(ps, id, val, line)) return -1; break;
        default:           if (parse_record(ps, id, val, line)) return -1; break;
        }
        if (!eol) break;
    }
    return 0;
}

static int valid_fqdn(const char *s)
{
    size_t i, n = strlen(s);
    if (n == 0 || n > 253 || strchr(s, '.') == NULL) return 0;
    if (s[n - 1] == '.') return 0;   /* §04.5: no trailing dot */
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_')) return 0;
    }
    return 1;
}

static int validate(struct parser *ps, int diagnostic)
{
    struct mn_cfg *c = ps->cfg;
    size_t i, j;
    char eb[256];
    if (c->core.connect_timeout_ms > c->core.http_timeout_ms) {
        snprintf(ps->err, sizeof(ps->err), "connect_timeout_ms must be <= http_timeout_ms");
        return -1;
    }
    if (c->core.log_target == MN_LOG_FILE) {
        const char *lf = c->core.log_file;
        const char *ld = getenv("LOGS_DIRECTORY");
        int ok = 0;

        if (!lf[0]) {
            snprintf(ps->err, sizeof(ps->err),
                     "log_target=file requires log_file under $LOGS_DIRECTORY or /var/log/miniddns/");
            return -1;
        }
        if (strncmp(lf, "$LOGS_DIRECTORY/", 16) == 0) {
            if (ld && ld[0]) {
                char expanded[MN_PATH_MAX];
                int n = snprintf(expanded, sizeof(expanded), "%s/%s", ld, lf + 16);

                if (n < 0 || (size_t)n >= sizeof(expanded)) {
                    snprintf(ps->err, sizeof(ps->err),
                             "log_file expanded path too long");
                    return -1;
                }
                snprintf(c->core.log_file, sizeof(c->core.log_file), "%s", expanded);
                lf = c->core.log_file;
                ok = 1;
            } else if (diagnostic) {
                /* Diagnostics run outside systemd; the unit provides the env. */
                mn_log(MN_LOG_WARN,
                       "logs_directory_unset diagnostic=1 fallback=stdout");
                c->core.log_target = MN_LOG_JOURNALD;
                c->core.log_file[0] = '\0';
                ok = 1;
            } else {
                snprintf(ps->err, sizeof(ps->err),
                         "log_file needs $LOGS_DIRECTORY (systemd LogsDirectory=) but it is unset");
                return -1;
            }
        }
        if (c->core.log_target == MN_LOG_FILE) {
            if (!ok && strncmp(lf, "/var/log/miniddns/", 18) == 0) ok = 1;
            else if (!ok && ld && ld[0] && strncmp(lf, ld, strlen(ld)) == 0
                     && (lf[strlen(ld)] == '/' || lf[strlen(ld)] == '\0')) ok = 1;
            if (!ok) {
                snprintf(ps->err, sizeof(ps->err),
                         "log_file must be under $LOGS_DIRECTORY or /var/log/miniddns/ (ProtectSystem=strict)");
                return -1;
            }
        }
    }
    /* lock_file default: $RUNTIME_DIRECTORY/<instance>.lock, else /run/miniddns, else /tmp */
    if (!c->core.lock_file[0]) {
        const char *rd = getenv("RUNTIME_DIRECTORY");
        char dir[MN_PATH_MAX];
        if (rd && rd[0])
            snprintf(c->core.lock_file, sizeof(c->core.lock_file), "%s/%s.lock", rd, c->core.instance);
        else
            snprintf(c->core.lock_file, sizeof(c->core.lock_file), "/run/miniddns/%s.lock", c->core.instance);
        /* fall back to /tmp when the runtime dir is not writable */
        {
            char tmp[MN_PATH_MAX];
            snprintf(tmp, sizeof(tmp), "%s", c->core.lock_file);
            char *slash = strrchr(tmp, '/');
            if (slash) {
                *slash = '\0';
                snprintf(dir, sizeof(dir), "%s", tmp);
                if (access(dir, W_OK) != 0)
                    snprintf(c->core.lock_file, sizeof(c->core.lock_file),
                             "/tmp/miniddns-%s.lock", c->core.instance);
            }
        }
    }
    /* echo URLs: https only, default port 443, bounded count */
    {
        char urls[1024], host[128], path[512], *p;
        int port, count = 0;
        snprintf(urls, sizeof(urls), "%s", c->detect.ipv4_echo_url);
        p = urls;
        while (*p) {
            char *comma = strchr(p, ',');
            if (comma) *comma = '\0';
            if (mn_parse_https_url(mn_trim(p), host, sizeof(host), &port, path, sizeof(path),
                                   eb, sizeof(eb)) != 0 || port != 443) {
                snprintf(ps->err, sizeof(ps->err), "ipv4_echo_url invalid url=%.200s (%.200s)", p, eb);
                return -1;
            }
            count++;
            if (count > MN_MAX_ECHO_URLS) {
                snprintf(ps->err, sizeof(ps->err), "ipv4_echo_url too many endpoints");
                return -1;
            }
            if (!comma) break;
            p = comma + 1;
        }
        if (count == 0 &&
            (c->detect.ipv4_mode == MN_IP4_EXTERNAL ||
             c->detect.ipv4_mode == MN_IP4_AUTO)) {
            snprintf(ps->err, sizeof(ps->err),
                     "ipv4_echo_url must not be empty when ipv4_mode=%s",
                     c->detect.ipv4_mode == MN_IP4_EXTERNAL ? "external" : "auto");
            return -1;
        }
    }
    for (i = 0; i < c->n_providers; i++) {
        struct mn_provider_cfg *p = &c->providers[i];
        size_t k;
        if (!p->id[0]) { snprintf(ps->err, sizeof(ps->err), "line=%d provider.id required", p->line); return -1; }
        if (!p->kind[0]) { snprintf(ps->err, sizeof(ps->err), "line=%d provider.kind required", p->line); return -1; }
        if (!mn_provider_lookup(p->kind)) {
            snprintf(ps->err, sizeof(ps->err), "line=%d unknown provider kind=%s", p->line, p->kind);
            return -1;
        }
        if (strlen(p->zone_id) != 32) {
            snprintf(ps->err, sizeof(ps->err), "line=%d zone_id must be 32 hex chars", p->line);
            return -1;
        }
        for (k = 0; k < 32; k++)
            if (!isxdigit((unsigned char)p->zone_id[k])) {
                snprintf(ps->err, sizeof(ps->err), "line=%d zone_id must be 32 hex chars", p->line);
                return -1;
            }
        if (!p->token_file[0] && !p->has_token_inline) {
            snprintf(ps->err, sizeof(ps->err), "line=%d token_file or token required", p->line);
            return -1;
        }
        if (p->token_file[0] && p->has_token_inline)
            mn_log(MN_LOG_WARN, "inline_token_ignored provider=%s hint=token_file_wins", p->id);
        if (p->has_token_inline)
            mn_log(MN_LOG_WARN, "inline_token_in_config provider=%s hint=test_only", p->id);
        for (j = 0; j < i; j++)
            if (strcasecmp(c->providers[j].id, p->id) == 0) {
                snprintf(ps->err, sizeof(ps->err), "duplicate provider.id=%s line=%d line=%d",
                         p->id, c->providers[j].line, p->line);
                return -1;
            }
    }
    for (i = 0; i < c->n_records; i++) {
        struct mn_record_cfg *r = &c->records[i];
        int found = 0;
        if (!valid_fqdn(r->name)) {
            snprintf(ps->err, sizeof(ps->err), "line=%d record.name invalid=%s", r->line, r->name);
            return -1;
        }
        if (r->family != AF_INET && r->family != AF_INET6) {
            snprintf(ps->err, sizeof(ps->err), "line=%d record.type required (A|AAAA)", r->line);
            return -1;
        }
        for (j = 0; j < c->n_providers; j++)
            if (strcasecmp(c->providers[j].id, r->provider_id) == 0) found = 1;
        if (!found) {
            snprintf(ps->err, sizeof(ps->err), "line=%d record.provider unknown=%s", r->line, r->provider_id);
            return -1;
        }
        /* cross-section uniqueness of (provider,name,type), with BOTH line numbers */
        for (j = 0; j < i; j++) {
            struct mn_record_cfg *o = &c->records[j];
            if (strcmp(o->provider_id, r->provider_id) == 0 &&
                strcasecmp(o->name, r->name) == 0 && o->family == r->family) {
                snprintf(ps->err, sizeof(ps->err),
                         "duplicate record (provider,name,type) name=%s line=%d line=%d",
                         r->name, o->line, r->line);
                return -1;
            }
        }
    }
    return 0;
}

int mn_cfg_load(const char *cli_path, int diagnostic, int allow_non_root_owner,
                struct mn_cfg *cfg, char *err, size_t errlen)
{
    char root[MN_PATH_MAX], path[MN_PATH_MAX], *buf;
    size_t len = 0;
    struct parser ps;
    int rc;
    memset(&ps, 0, sizeof(ps));
    ps.cfg = cfg;
    mn_find_artifact_root(root, sizeof(root));
    mn_cfg_defaults(cfg, root);
    if (mn_resolve_conf_path(cli_path, root, path, sizeof(path), ps.err, sizeof(ps.err)) != 0)
        goto fail;
    buf = (char *)malloc(MN_LIMIT_CONF_FILE + 1);
    if (!buf) { snprintf(ps.err, sizeof(ps.err), "out of memory"); goto fail; }
    if (mn_checked_read(path, MN_FILE_CONF, buf, MN_LIMIT_CONF_FILE + 1, &len,
                        allow_non_root_owner, ps.err, sizeof(ps.err)) != 0) {
        free(buf); goto fail;
    }
    (void)len;
    rc = parse_lines(&ps, buf);
    free(buf);
    if (rc != 0) goto fail;
    if (validate(&ps, diagnostic) != 0) goto fail;
    snprintf(cfg->conf_path, sizeof(cfg->conf_path), "%s", path);
    return 0;
fail:
    if (err && errlen) snprintf(err, errlen, "%s", ps.err);
    return E_CFG;
}

void mn_cfg_print(const struct mn_cfg *cfg)
{
    size_t i;
    char masked[128];
    printf("config=%s\n", cfg->conf_path[0] ? cfg->conf_path : "(none)");
    printf("root=%s\n", cfg->has_root ? cfg->root : "(system)");
    printf("[core]\n");
    printf("  instance=%s\n", cfg->core.instance);
    printf("  interval_fallback=%d\n", cfg->core.interval_fallback);
    printf("  debounce_ms=%d\n", cfg->core.debounce_ms);
    printf("  write_memo_ms=%d\n", cfg->core.write_memo_ms);
    printf("  ca_bundle=%s\n", cfg->core.ca_bundle[0] ? cfg->core.ca_bundle : "(auto)");
    printf("  http_timeout_ms=%d\n", cfg->core.http_timeout_ms);
    printf("  connect_timeout_ms=%d\n", cfg->core.connect_timeout_ms);
    printf("  retry_backoff=");
    for (i = 0; i < cfg->core.n_backoff; i++) printf("%s%d", i ? "," : "", cfg->core.retry_backoff[i]);
    printf("\n");
    printf("  log_level=%s log_target=%s\n", mn_log_level_name(cfg->core.log_level),
           cfg->core.log_target == MN_LOG_FILE ? "file" : "journald");
    printf("  log_file=%s\n", cfg->core.log_file[0] ? cfg->core.log_file : "(none)");
    printf("  lock_file=%s\n", cfg->core.lock_file);
    printf("  clock_guard_epoch=%lld\n", (long long)cfg->core.clock_guard_epoch);
    printf("[detect]\n");
    printf("  ipv4_mode=%s ipv6_mode=%s\n", mn_ip4_mode_name(cfg->detect.ipv4_mode),
           mn_ip6_mode_name(cfg->detect.ipv6_mode));
    printf("  iface_include=%s\n", cfg->detect.iface_include);
    printf("  iface_exclude=%s\n", cfg->detect.iface_exclude);
    printf("  ipv4_echo_url=%s\n", cfg->detect.ipv4_echo_url);
    printf("  allow_private_ipv4=%d allow_temporary_ipv6=%d\n",
           cfg->detect.allow_private_ipv4, cfg->detect.allow_temporary_ipv6);
    for (i = 0; i < cfg->n_providers; i++) {
        const struct mn_provider_cfg *p = &cfg->providers[i];
        printf("[provider] #%zu line=%d\n", i + 1, p->line);
        printf("  id=%s kind=%s\n", p->id, p->kind);
        printf("  zone_id=%s\n", mn_mask(p->zone_id, masked, sizeof(masked)));
        printf("  token_file=%s\n", p->token_file[0] ? p->token_file : "(none)");
        if (p->has_token_inline)
            printf("  token=%s\n", mn_mask(p->token_inline, masked, sizeof(masked)));
    }
    for (i = 0; i < cfg->n_records; i++) {
        const struct mn_record_cfg *r = &cfg->records[i];
        printf("[record] #%zu line=%d\n", i + 1, r->line);
        printf("  provider=%s name=%s type=%s ttl=%d proxied=%d create_if_missing=%d enabled=%d\n",
               r->provider_id, r->name, r->family == AF_INET ? "A" : "AAAA", r->ttl,
               r->proxied, r->create_if_missing, r->enabled);
    }
}

int mn_cfg_check_defaults(char *err, size_t errlen)
{
    struct mn_cfg c;
    int iv;
    mn_cfg_defaults(&c, NULL);
    if (mn_log_level_parse(mn_log_level_name(c.core.log_level), &iv) != 0 || iv != c.core.log_level) {
        snprintf(err, errlen, "default log_level not in enum"); return -1;
    }
    if (parse_enum(mn_ip4_mode_name(c.detect.ipv4_mode), ip4_mode_names, 4, &iv) != 0
        || iv != c.detect.ipv4_mode) {
        snprintf(err, errlen, "default ipv4_mode not in enum"); return -1;
    }
    if (parse_enum(mn_ip6_mode_name(c.detect.ipv6_mode), ip6_mode_names, 2, &iv) != 0
        || iv != c.detect.ipv6_mode) {
        snprintf(err, errlen, "default ipv6_mode not in enum"); return -1;
    }
    if (c.core.debounce_ms < 100 || c.core.debounce_ms > 60000) {
        snprintf(err, errlen, "default debounce_ms out of range"); return -1;
    }
    if (c.core.connect_timeout_ms > c.core.http_timeout_ms) {
        snprintf(err, errlen, "default connect_timeout > http_timeout"); return -1;
    }
    return 0;
}

void mn_cfg_wipe_secrets(struct mn_cfg *cfg)
{
    size_t i;
    for (i = 0; i < cfg->n_providers; i++)
        mn_secure_zero(cfg->providers[i].token_inline, sizeof(cfg->providers[i].token_inline));
}

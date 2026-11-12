/* miniddns — IP classification, normalisation and deterministic selection (design.md §06) */
#include "detect.h"
#include "log.h"
#include "util.h"
#include "tls_http.h"

#include <arpa/inet.h>
#include <linux/if_addr.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#define IP4(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | \
     ((uint32_t)(c) << 8) | (uint32_t)(d))

#define MASK4  { 0xff, 0xff, 0xff, 0xff }
#define MASK8  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
#define MASK12 { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
                 0xff, 0xff, 0xff, 0xff }
#define MASK16 { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }

struct ip4_prefix {
    uint32_t prefix;
    uint32_t mask;
};

struct ip6_prefix {
    uint8_t prefix[16];
    uint8_t mask[16];
};

static const struct ip4_prefix ip4_deny[] = {
    { IP4(10, 0, 0, 0),       0xff000000u }, /* 10.0.0.0/8 */
    { IP4(172, 16, 0, 0),     0xfff00000u }, /* 172.16.0.0/12 */
    { IP4(192, 168, 0, 0),    0xffff0000u }, /* 192.168.0.0/16 */
    { IP4(100, 64, 0, 0),     0xffc00000u }, /* 100.64.0.0/10 */
    { IP4(127, 0, 0, 0),      0xff000000u }, /* 127.0.0.0/8 */
    { IP4(169, 254, 0, 0),    0xffff0000u }, /* 169.254.0.0/16 */
    { IP4(0, 0, 0, 0),        0xff000000u }, /* 0.0.0.0/8 */
    { IP4(192, 0, 0, 0),      0xffffff00u }, /* 192.0.0.0/24 */
    { IP4(192, 0, 2, 0),      0xffffff00u }, /* 192.0.2.0/24 */
    { IP4(198, 18, 0, 0),     0xfffe0000u }, /* 198.18.0.0/15 */
    { IP4(198, 51, 100, 0),   0xffffff00u }, /* 198.51.100.0/24 */
    { IP4(203, 0, 113, 0),    0xffffff00u }, /* 203.0.113.0/24 */
    { IP4(240, 0, 0, 0),      0xf0000000u }, /* 240.0.0.0/4 */
    { IP4(224, 0, 0, 0),      0xf0000000u }, /* 224.0.0.0/4 */
    { IP4(255, 255, 255, 255),0xffffffffu }  /* 255.255.255.255/32 */
};

static const struct ip6_prefix ip6_deny[] = {
    { { 0xfc }, { 0xfe } },                         /* fc00::/7 */
    { { 0xfe, 0x80 }, { 0xff, 0xc0 } },             /* fe80::/10 */
    { { [15] = 0x01 }, MASK16 },                    /* ::1/128 */
    { { 0 }, MASK16 },                              /* ::/128 */
    { { 0xff }, { 0xff } },                         /* ff00::/8 */
    { { 0x01 }, MASK8 },                            /* 100::/64 */
    { { 0x20, 0x01, 0x0d, 0xb8 }, MASK4 },         /* 2001:db8::/32 */
    { { 0xfe, 0xc0 }, { 0xff, 0xc0 } },             /* fec0::/10 */
    { { [10] = 0xff, [11] = 0xff }, MASK12 },       /* ::ffff:0:0/96 */
    { { 0x00, 0x64, 0xff, 0x9b }, MASK12 }         /* 64:ff9b::/96 */
};

static void det_copy_str(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (dst == NULL || cap == 0)
        return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    n = strlen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void det_set_err(char *err, size_t errlen, const char *text)
{
    det_copy_str(err, errlen, text);
}

static void det_reset(struct mn_detect_result *res, char *err, size_t errlen)
{
    if (res != NULL)
        memset(res, 0, sizeof(*res));
    det_set_err(err, errlen, "");
}

static int ip6_match(const uint8_t b[16], const uint8_t p[16],
                     const uint8_t m[16])
{
    size_t i;

    for (i = 0; i < 16; i++) {
        if ((uint8_t)(b[i] & m[i]) != (uint8_t)(p[i] & m[i]))
            return 0;
    }
    return 1;
}

int mn_ip4_publishable(uint32_t addr_be)
{
    uint32_t h = ntohl(addr_be);
    size_t i;

    for (i = 0; i < sizeof(ip4_deny) / sizeof(ip4_deny[0]); i++) {
        if ((h & ip4_deny[i].mask) == ip4_deny[i].prefix)
            return 0;
    }
    return 1;
}

int mn_ip6_publishable(const uint8_t b[16])
{
    size_t i;

    if (b == NULL)
        return 0;
    if ((b[0] & 0xe0u) != 0x20u)
        return 0;
    for (i = 0; i < sizeof(ip6_deny) / sizeof(ip6_deny[0]); i++) {
        if (ip6_match(b, ip6_deny[i].prefix, ip6_deny[i].mask))
            return 0;
    }
    return 1;
}

static int ip4_leading_zero(const char *s)
{
    const char *p = s;

    while (*p != '\0') {
        if (*p < '0' || *p > '9')
            return 0; /* Let inet_pton report the real syntax error. */
        if (*p == '0' && p[1] >= '0' && p[1] <= '9')
            return 1;
        while (*p >= '0' && *p <= '9')
            p++;
        if (*p == '.') {
            p++;
            continue;
        }
        return 0;
    }
    return 0;
}

static int ip_parse_raw(int family, const char *text, uint8_t raw[16])
{
    char clean[MN_IP_STRLEN];
    const char *pct;
    size_t len;

    if (text == NULL || (family != AF_INET && family != AF_INET6))
        return 0;
    pct = strchr(text, '%');
    if (pct != NULL && family != AF_INET6)
        return 0;
    len = pct != NULL ? (size_t)(pct - text) : strlen(text);
    if (len == 0 || len >= sizeof(clean))
        return 0;
    memcpy(clean, text, len);
    clean[len] = '\0';
    if (family == AF_INET && ip4_leading_zero(clean))
        return 0;
    return inet_pton(family, clean, raw) == 1;
}

int mn_ip_normalize(int family, const char *text, char out[MN_IP_STRLEN])
{
    uint8_t raw[16];

    if (out == NULL)
        return -1;
    out[0] = '\0';
    if (!ip_parse_raw(family, text, raw))
        return -1;
    if (inet_ntop(family, raw, out, MN_IP_STRLEN) == NULL) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

int mn_ip_equal(int family, const char *a, const char *b)
{
    uint8_t ra[16], rb[16];
    size_t n;

    if (family == AF_INET)
        n = 4;
    else if (family == AF_INET6)
        n = 16;
    else
        return 0;
    if (!ip_parse_raw(family, a, ra) || !ip_parse_raw(family, b, rb))
        return 0;
    return memcmp(ra, rb, n) == 0;
}

static int list_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Returns 1 for each non-empty comma-separated item, 0 at end of list. */
static int next_list_token(const char **cur, char *dst, size_t cap)
{
    for (;;) {
        const char *p = *cur;
        const char *start, *end;
        size_t len;

        while (list_space(*p))
            p++;
        if (*p == '\0') {
            *cur = p;
            return 0;
        }
        start = p;
        while (*p != '\0' && *p != ',')
            p++;
        end = p;
        while (end > start && list_space(end[-1]))
            end--;
        if (*p == ',')
            *cur = p + 1;
        else
            *cur = p;
        len = (size_t)(end - start);
        if (len == 0)
            continue;
        if (cap == 0)
            return 1;
        if (len >= cap) {
            dst[0] = '\0';
            return 1;
        }
        memcpy(dst, start, len);
        dst[len] = '\0';
        return 1;
    }
}

int mn_iface_allowed(const char *name, const char *include,
                     const char *exclude)
{
    char tok[MN_PATH_MAX];
    const char *cur;
    int have_include = 0;
    int include_ok = 0;

    if (name == NULL)
        return 0;
    cur = include != NULL ? include : "";
    while (next_list_token(&cur, tok, sizeof(tok))) {
        have_include = 1;
        if (tok[0] != '\0' && mn_iface_match(tok, name))
            include_ok = 1;
    }
    if (have_include && !include_ok)
        return 0;

    cur = exclude != NULL ? exclude : "";
    while (next_list_token(&cur, tok, sizeof(tok))) {
        if (tok[0] != '\0' && mn_iface_match(tok, name))
            return 0;
    }
    return 1;
}

static void det_log_v4_success(const struct mn_detect_result *res,
                               const char *source)
{
    mn_log(MN_LOG_DEBUG, "detect family=inet4 source=%s ip=%s candidates=%d",
           source, res->ip, res->candidates);
}

static void det_log_private_reason(const char *source,
                                   const struct mn_detect_result *res)
{
    mn_log(MN_LOG_WARN,
           "detect family=inet4 source=%s reason=private-cgnat-only "
           "detail=no-public-ipv4 candidates=%d filtered_private=%d",
           source, res->candidates, res->filtered_private);
}

static void det_v4_be(const uint8_t bytes[16], uint32_t *be, uint32_t *host)
{
    memcpy(be, bytes, sizeof(*be));
    *host = ntohl(*be);
}

static int det_v4_iface(const struct mn_cfg *cfg,
                        const struct mn_addr_set *addrs,
                        struct mn_detect_result *res)
{
    uint32_t best_be = 0;
    uint32_t best_host = 0;
    int found = 0;
    size_t i, n;

    if (addrs == NULL)
        return 0;
    n = addrs->n;
    if (n > MN_MAX_ADDRS)
        n = MN_MAX_ADDRS;
    for (i = 0; i < n; i++) {
        const struct mn_addr *a = &addrs->a[i];
        uint32_t be, host;
        int rejected = 0;

        if (a->family != AF_INET)
            continue;
        res->candidates++;
        if (a->scope != RT_SCOPE_UNIVERSE) {
            res->filtered_scope++;
            rejected = 1;
        }
        if (!a->if_up) {
            res->filtered_iface_down++;
            rejected = 1;
        }
        if (!mn_iface_allowed(a->ifname, cfg->detect.iface_include,
                              cfg->detect.iface_exclude)) {
            res->filtered_iface_name++;
            rejected = 1;
        }
        det_v4_be(a->bytes, &be, &host);
        if (!cfg->detect.allow_private_ipv4 && !mn_ip4_publishable(be)) {
            res->filtered_private++;
            rejected = 1;
        }
        if (rejected)
            continue;
        if (!found || host < best_host) {
            found = 1;
            best_be = be;
            best_host = host;
        }
    }
    if (found) {
        struct in_addr in;

        in.s_addr = best_be;
        if (inet_ntop(AF_INET, &in, res->ip, sizeof(res->ip)) == NULL)
            return 0;
        res->source = 1;
        det_log_v4_success(res, "iface");
        return 1;
    }
    if (res->filtered_private > 0)
        det_log_private_reason("iface", res);
    return 0;
}

static int det_v4_external(const struct mn_cfg *cfg, struct mn_ca *ca,
                           struct mn_detect_result *res, int *transport_rc,
                           char *transport_err, size_t transport_cap)
{
    const char *cur = cfg->detect.ipv4_echo_url;
    char url[1024];
    char host[MN_FQDN_MAX];
    char path[MN_PATH_MAX];
    char parse_err[256];
    char req_err[256];
    struct mn_http_result resp;
    int attempted = 0;

    while (attempted < MN_MAX_ECHO_URLS &&
           next_list_token(&cur, url, sizeof(url))) {
        int port = 443;
        int errcode = 0;
        int rc;

        if (url[0] == '\0')
            continue;
        attempted++;
        res->candidates++;
        parse_err[0] = '\0';
        path[0] = '\0';
        if (mn_parse_https_url(url, host, sizeof(host), &port, path,
                               sizeof(path), parse_err,
                               sizeof(parse_err)) != 0)
            continue;

        memset(&resp, 0, sizeof(resp));
        req_err[0] = '\0';
        rc = mn_http_request(cfg, ca,
            &(struct mn_http_req){
                .method = "GET",
                .host = host,
                .path = path,
                .port = port,
                .want_json = 0,
                .allow_redirect = 1,
                .extra_headers = NULL
            }, &resp, &errcode, req_err, sizeof(req_err));
        if (rc < 0 || errcode < 0) {
            int use = rc < 0 ? rc : errcode;

            if (use != E_NO_IP) {
                *transport_rc = use;
                det_copy_str(transport_err, transport_cap, req_err);
            }
            mn_http_result_free(&resp);
            continue;
        }
        if (resp.status < 200 || resp.status >= 300) {
            mn_http_result_free(&resp);
            continue;
        }
        if (resp.body != NULL) {
            char *body = mn_trim(resp.body);
            char ip[MN_IP_STRLEN];

            if (mn_ip_normalize(AF_INET, body, ip) == 0) {
                uint8_t raw[4];
                uint32_t be;

                if (inet_pton(AF_INET, ip, raw) == 1) {
                    memcpy(&be, raw, sizeof(be));
                    if (cfg->detect.allow_private_ipv4 ||
                        mn_ip4_publishable(be)) {
                        det_copy_str(res->ip, sizeof(res->ip), ip);
                        res->source = 2;
                        det_log_v4_success(res, "external");
                        mn_http_result_free(&resp);
                        return 1;
                    }
                    res->filtered_private++;
                }
            }
        }
        mn_http_result_free(&resp);
    }
    if (res->filtered_private > 0)
        det_log_private_reason("external", res);
    return 0;
}

int mn_detect_ipv4(const struct mn_cfg *cfg,
                   const struct mn_addr_set *addrs, struct mn_ca *ca,
                   struct mn_detect_result *res, char *err, size_t errlen)
{
    char transport_err[256];
    int transport_rc = E_NO_IP;

    if (cfg == NULL || addrs == NULL || res == NULL) {
        det_set_err(err, errlen, "detect ipv4: invalid argument");
        return E_CFG;
    }
    det_reset(res, err, errlen);
    transport_err[0] = '\0';

    switch (cfg->detect.ipv4_mode) {
    case MN_IP4_OFF:
        return E_NO_IP;
    case MN_IP4_IFACE:
        if (det_v4_iface(cfg, addrs, res))
            return MN_OK;
        return E_NO_IP;
    case MN_IP4_EXTERNAL:
        if (det_v4_external(cfg, ca, res, &transport_rc, transport_err,
                            sizeof(transport_err)))
            return MN_OK;
        if (transport_rc != E_NO_IP) {
            det_copy_str(err, errlen, transport_err);
            return transport_rc;
        }
        return E_NO_IP;
    case MN_IP4_AUTO: {
        int private_iface;

        if (det_v4_iface(cfg, addrs, res))
            return MN_OK;
        private_iface = res->filtered_private > 0;
        if (det_v4_external(cfg, ca, res, &transport_rc, transport_err,
                            sizeof(transport_err)))
            return MN_OK;
        if (private_iface) {
            mn_log(MN_LOG_WARN,
                   "detect family=inet4 source=auto "
                   "reason=no-public-ipv4-after-external candidates=%d "
                   "filtered_private=%d",
                   res->candidates, res->filtered_private);
            return E_NO_IP;
        }
        if (transport_rc != E_NO_IP) {
            det_copy_str(err, errlen, transport_err);
            return transport_rc;
        }
        return E_NO_IP;
    }
    default:
        det_set_err(err, errlen, "detect ipv4: invalid mode");
        return E_CFG;
    }
}

int mn_detect_ipv6(const struct mn_cfg *cfg,
                   const struct mn_addr_set *addrs,
                   struct mn_detect_result *res, char *err, size_t errlen)
{
    uint8_t best[16];
    int have_best = 0;
    size_t i, n;

    if (cfg == NULL || addrs == NULL || res == NULL) {
        det_set_err(err, errlen, "detect ipv6: invalid argument");
        return E_CFG;
    }
    det_reset(res, err, errlen);
    if (cfg->detect.ipv6_mode == MN_IP6_OFF) {
        /* §04.3 / §06.3: off means no AAAA candidate at all. */
        return E_NO_IP;
    }
    n = addrs->n;
    if (n > MN_MAX_ADDRS)
        n = MN_MAX_ADDRS;
    for (i = 0; i < n; i++) {
        const struct mn_addr *a = &addrs->a[i];
        int rejected = 0;

        if (a->family != AF_INET6)
            continue;
        res->candidates++;
        if ((a->flags & IFA_F_TEMPORARY) != 0 &&
            !cfg->detect.allow_temporary_ipv6) {
            res->filtered_temporary++;
            rejected = 1;
        }
        if ((a->flags & IFA_F_OPTIMISTIC) != 0) {
            res->filtered_optimistic++;
            rejected = 1;
        }
        if ((a->flags & IFA_F_DADFAILED) != 0) {
            res->filtered_dadfailed++;
            rejected = 1;
        }
        if ((a->flags & IFA_F_DEPRECATED) != 0) {
            res->filtered_deprecated++;
            rejected = 1;
        }
        if ((a->flags & IFA_F_TENTATIVE) != 0) {
            res->filtered_tentative++;
            rejected = 1;
        }
        if (a->has_cacheinfo && a->valid_lft == 0) {
            res->filtered_lifetime++;
            rejected = 1;
        }
        if (a->scope != RT_SCOPE_UNIVERSE) {
            res->filtered_scope++;
            rejected = 1;
        }
        if (!a->if_up) {
            res->filtered_iface_down++;
            rejected = 1;
        }
        if (!mn_iface_allowed(a->ifname, cfg->detect.iface_include,
                              cfg->detect.iface_exclude)) {
            res->filtered_iface_name++;
            rejected = 1;
        }
        if (!mn_ip6_publishable(a->bytes)) {
            res->filtered_private++;
            rejected = 1;
        }
        if (rejected)
            continue;
        if (!have_best || memcmp(a->bytes, best, sizeof(best)) < 0) {
            memcpy(best, a->bytes, sizeof(best));
            have_best = 1;
        }
    }
    if (!have_best)
        return E_NO_IP;
    if (inet_ntop(AF_INET6, best, res->ip, sizeof(res->ip)) == NULL) {
        det_set_err(err, errlen, "detect ipv6: inet_ntop failed");
        return E_CFG;
    }
    res->source = 1;
    mn_log(MN_LOG_DEBUG, "detect family=inet6 source=iface ip=%s candidates=%d",
           res->ip, res->candidates);
    return MN_OK;
}

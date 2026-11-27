/* tests/unit.c — §14.1 unit tests (single binary, all pure/module seams) */
#include "miniddns.h"
#include "util.h"
#include "log.h"
#include "cfg.h"
#include "sched.h"
#include "ca.h"
#include "tls_http.h"
#include "nl_addr.h"
#include "detect.h"
#include "json_util.h"
#include "provider.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

static int checks, failures;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { \
        failures++; \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr); \
    } \
} while (0)

static char cap_lines[128][2048];
static int cap_n;
static void sink(int level, const char *line, void *ctx)
{
    (void)level; (void)ctx;
    if (cap_n < 128) snprintf(cap_lines[cap_n++], 2048, "%s", line);
}

static int write_file(const char *path, const char *data)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(data, f);
    fclose(f);
    chmod(path, 0644);   /* §03 rejects group/world writable config files */
    return 0;
}

static int read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n;
    if (!f) return -1;
    n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ cfg */
static void test_cfg(void)
{
    char err[512];
    struct mn_cfg c;
    const char *good =
        "[core]\ninstance = home\ninterval_fallback = 900\ndebounce_ms = 1500\n"
        "write_memo_ms = 60000\nlog_level = info\n\n"
        "[detect]\nipv4_mode = auto\nipv6_mode = iface\n"
        "iface_exclude = lo,docker0,veth*\n\n"
        "[provider]\nid = cf-main\nkind = cloudflare\n"
        "zone_id = 023e105f4ecef8ad9ca31a8372d0c353\ntoken = inline-test-token\n\n"
        "[record]\nprovider = cf-main\nname = home.example.com\ntype = A\n\n"
        "[record]\nprovider = cf-main\nname = home.example.com\ntype = AAAA\n";
    const char *dup =
        "[provider]\nid = p\nkind = cloudflare\nzone_id = 023e105f4ecef8ad9ca31a8372d0c353\ntoken = t\n"
        "[record]\nprovider = p\nname = a.example.com\ntype = A\n"
        "[record]\nprovider = p\nname = a.example.com\ntype = A\n";
    CHECK(mn_cfg_check_defaults(err, sizeof(err)) == 0, "defaults: %s", err);
    write_file("tmp/good.conf", good);
    CHECK(mn_cfg_load("tmp/good.conf", 1, 1, &c, err, sizeof(err)) == 0, "good config: %s", err);
    CHECK(c.n_providers == 1 && c.n_records == 2, "counts p=%zu r=%zu", c.n_providers, c.n_records);
    CHECK(c.detect.ipv6_mode == MN_IP6_IFACE, "ipv6 default must be iface");
    CHECK(c.detect.ipv4_mode == MN_IP4_AUTO, "ipv4 default must be auto");
    CHECK(c.core.debounce_ms == 1500 && c.core.write_memo_ms == 60000, "core defaults");
    CHECK(c.core.n_backoff == 4 && c.core.retry_backoff[3] == 300, "backoff default");
    CHECK(c.records[0].ttl == 60 && c.records[0].create_if_missing == 1 && c.records[0].enabled == 1,
          "record defaults");

    write_file("tmp/unknown_key.conf", "[core]\nfoo = 1\n");
    CHECK(mn_cfg_load("tmp/unknown_key.conf", 1, 1, &c, err, sizeof(err)) != 0, "unknown key rejected");
    CHECK(strstr(err, "line=2") && strstr(err, "unknown key"), "unknown key line number: %s", err);

    write_file("tmp/unknown_sec.conf", "[bogus]\nx = 1\n");
    CHECK(mn_cfg_load("tmp/unknown_sec.conf", 1, 1, &c, err, sizeof(err)) != 0, "unknown section rejected");
    CHECK(strstr(err, "unknown section"), "unknown section message: %s", err);

    write_file("tmp/record_id.conf", "[record]\nrecord_id = abc\n");
    CHECK(mn_cfg_load("tmp/record_id.conf", 1, 1, &c, err, sizeof(err)) != 0,
          "record_id must be an unknown key");
    CHECK(strstr(err, "unknown key"), "record_id msg: %s", err);

    write_file("tmp/dup.conf", dup);
    CHECK(mn_cfg_load("tmp/dup.conf", 1, 1, &c, err, sizeof(err)) != 0, "duplicate record rejected");
    {
        const char *p = strstr(err, "line=");
        CHECK(p && strstr(p + 5, "line="), "duplicate error must name BOTH lines: %s", err);
    }

    write_file("tmp/backoff9.conf", "[core]\nretry_backoff = 1,2,3,4,5,6,7,8,9\n");
    CHECK(mn_cfg_load("tmp/backoff9.conf", 1, 1, &c, err, sizeof(err)) != 0, "9 backoff items rejected");

    write_file("tmp/dupkey.conf", "[core]\ninstance = a\ninstance = b\n");
    CHECK(mn_cfg_load("tmp/dupkey.conf", 1, 1, &c, err, sizeof(err)) != 0, "duplicate key rejected");

    write_file("tmp/bad_default.conf", "[detect]\nipv6_mode = auto\n");
    CHECK(mn_cfg_load("tmp/bad_default.conf", 1, 1, &c, err, sizeof(err)) != 0,
          "ipv6_mode=auto must be rejected");

    write_file("tmp/bad_logfile.conf", "[core]\nlog_target = file\nlog_file = /tmp/miniddns.log\n");
    CHECK(mn_cfg_load("tmp/bad_logfile.conf", 1, 1, &c, err, sizeof(err)) != 0,
          "log_file outside LogsDirectory must be rejected");
    CHECK(strstr(err, "LOGS_DIRECTORY") != NULL, "log_file error hints: %s", err);

    write_file("tmp/trailing_dot.conf",
               "[provider]\nid = p\nkind = cloudflare\n"
               "zone_id = 023e105f4ecef8ad9ca31a8372d0c353\ntoken = t\n"
               "[record]\nprovider = p\nname = home.example.com.\ntype = A\n");
    CHECK(mn_cfg_load("tmp/trailing_dot.conf", 1, 1, &c, err, sizeof(err)) != 0,
          "FQDN trailing dot must be rejected: %s", err);

    write_file("tmp/provider_case.conf",
               "[provider]\nid = CF-MAIN\nkind = cloudflare\n"
               "zone_id = 023e105f4ecef8ad9ca31a8372d0c353\ntoken = t\n"
               "[record]\nprovider = cf-main\nname = home.example.com\ntype = A\n");
    CHECK(mn_cfg_load("tmp/provider_case.conf", 1, 1, &c, err, sizeof(err)) == 0,
          "provider id reference is case-insensitive: %s", err);

    write_file("tmp/empty_echo.conf", "[detect]\nipv4_mode = external\nipv4_echo_url =\n");
    CHECK(mn_cfg_load("tmp/empty_echo.conf", 1, 1, &c, err, sizeof(err)) != 0,
          "empty ipv4_echo_url must be rejected in external mode: %s", err);

    setenv("LOGS_DIRECTORY", "/tmp/miniddns-logs-test", 1);
    write_file("tmp/logs_dir.conf",
               "[core]\nlog_target = file\nlog_file = $LOGS_DIRECTORY/miniddns.log\n");
    CHECK(mn_cfg_load("tmp/logs_dir.conf", 1, 1, &c, err, sizeof(err)) == 0,
          "LOGS_DIRECTORY config loads: %s", err);
    CHECK(!strcmp(c.core.log_file, "/tmp/miniddns-logs-test/miniddns.log"),
          "LOGS_DIRECTORY expanded: %s", c.core.log_file);
    unsetenv("LOGS_DIRECTORY");
}

/* ----------------------------------------------------------------- util */
static void test_util(void)
{
    char host[128], path[512], err[256], out[128];
    int port, rc;
    char buf[256];
    size_t len = 0;
    CHECK(mn_parse_https_url("https://api.ipify.org", host, sizeof(host), &port,
                             path, sizeof(path), err, sizeof(err)) == 0, "url parse");
    CHECK(port == 443 && !strcmp(path, "/") && !strcmp(host, "api.ipify.org"), "url fields");
    CHECK(mn_parse_https_url("https://host:8443/x", host, sizeof(host), &port,
                             path, sizeof(path), err, sizeof(err)) == 0 && port == 8443, "url port");
    CHECK(mn_parse_https_url("http://x/", host, sizeof(host), &port, path, sizeof(path),
                             err, sizeof(err)) != 0, "http rejected");
    CHECK(mn_iface_match("veth*", "veth123"), "trailing glob");
    CHECK(!mn_iface_match("veth*", "eth0"), "glob negative");
    CHECK(mn_iface_match("docker0", "docker0"), "exact");
    CHECK(!mn_iface_match("docker0", "docker1"), "exact negative");
    CHECK(strstr(mn_mask("supersecrettoken", out, sizeof(out)), "supersecrettoken") == NULL,
          "mask must hide token");
    CHECK(mn_strlcpy(buf, 6, "abcdef") != 0, "strlcpy truncation detected");
    {
        char out[64];
        int skipped = 0;
        unsetenv("CREDENTIALS_DIRECTORY");
        CHECK(mn_expand_creds_dir("$CREDENTIALS_DIRECTORY/token", out, sizeof(out),
                                  1, &skipped, err, sizeof(err)) == 0 && skipped == 1 && out[0] == 0,
              "diagnostic creds-dir missing => warn+skip");
        CHECK(mn_expand_creds_dir("$CREDENTIALS_DIRECTORY/token", out, sizeof(out),
                                  0, &skipped, err, sizeof(err)) != 0,
              "daemon creds-dir missing => E_CFG");
        setenv("CREDENTIALS_DIRECTORY", "/run/credentials", 1);
        CHECK(mn_expand_creds_dir("$CREDENTIALS_DIRECTORY/token", out, sizeof(out),
                                  0, &skipped, err, sizeof(err)) == 0
              && !strcmp(out, "/run/credentials/token"), "creds-dir expansion");
        unsetenv("CREDENTIALS_DIRECTORY");
    }

    /* token symlink must be rejected, config/ca symlink allowed (owner check bypassed) */
    write_file("tmp/target.txt", "hello\n");
    unlink("tmp/link.txt");
    CHECK(symlink("target.txt", "tmp/link.txt") == 0, "create symlink");
    rc = mn_checked_read("tmp/link.txt", MN_FILE_TOKEN, buf, sizeof(buf), &len, 1, err, sizeof(err));
    CHECK(rc != 0, "token symlink rejected");
    rc = mn_checked_read("tmp/link.txt", MN_FILE_CONF, buf, sizeof(buf), &len, 1, err, sizeof(err));
    CHECK(rc == 0 && !strcmp(buf, "hello\n"), "config symlink allowed: %s", err);
    /* a CA outside the whitelisted roots must be refused (§03) */
    write_file("/tmp/miniddns-outside-ca.pem", "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n");
    chmod("/tmp/miniddns-outside-ca.pem", 0644);
    rc = mn_checked_read("/tmp/miniddns-outside-ca.pem", MN_FILE_CA, buf, sizeof(buf), &len, 1, err, sizeof(err));
    CHECK(rc != 0 && strstr(err, "whitelist") != NULL, "CA outside whitelist rejected: %s", err);

    /* exact size boundary: == limit is accepted, limit+1 is rejected */
    {
        char *big = (char *)malloc((size_t)MN_LIMIT_CONF_FILE + 2);
        char *rbuf = (char *)malloc((size_t)MN_LIMIT_CONF_FILE + 1);
        FILE *f;
        CHECK(big != NULL && rbuf != NULL, "boundary buffers allocated");
        if (big != NULL && rbuf != NULL) {
            memset(big, '#', (size_t)MN_LIMIT_CONF_FILE + 1);
            big[MN_LIMIT_CONF_FILE] = '\n';
            f = fopen("tmp/exact.conf", "wb");
            CHECK(f != NULL, "exact.conf created");
            if (f != NULL) {
                fwrite(big, 1, (size_t)MN_LIMIT_CONF_FILE, f);
                fclose(f);
                chmod("tmp/exact.conf", 0644);
                rc = mn_checked_read("tmp/exact.conf", MN_FILE_CONF, rbuf,
                                     (size_t)MN_LIMIT_CONF_FILE + 1, &len, 1,
                                     err, sizeof(err));
                CHECK(rc == 0 && len == (size_t)MN_LIMIT_CONF_FILE,
                      "exactly limit bytes accepted: rc=%d len=%zu err=%s", rc, len, err);
            }
            f = fopen("tmp/over.conf", "wb");
            CHECK(f != NULL, "over.conf created");
            if (f != NULL) {
                fwrite(big, 1, (size_t)MN_LIMIT_CONF_FILE + 1, f);
                fclose(f);
                chmod("tmp/over.conf", 0644);
                rc = mn_checked_read("tmp/over.conf", MN_FILE_CONF, rbuf,
                                     (size_t)MN_LIMIT_CONF_FILE + 1, &len, 1,
                                     err, sizeof(err));
                CHECK(rc != 0 && strstr(err, "too large") != NULL,
                      "limit+1 bytes rejected: %s", err);
            }
        }
        free(big);
        free(rbuf);
    }
}

/* -------------------------------------------------------------- netlink */
static void add_rta(char *buf, size_t *off, int type, const void *data, size_t len)
{
    struct rtattr *rta = (struct rtattr *)(buf + *off);
    rta->rta_type = (unsigned short)type;
    rta->rta_len = (unsigned short)RTA_LENGTH(len);
    if (len > 0) memcpy(RTA_DATA(rta), data, len);
    *off += RTA_ALIGN(rta->rta_len);
}

struct nl_test_msg {
    struct nlmsghdr nlh;
    struct ifaddrmsg ifa;
    char attrs[128];
};

/* Append one RTM_NEWADDR message (IFA_ADDRESS + optional IFA_FLAGS / IFA_CACHEINFO)
   to a suitably aligned buffer and return its NLMSG_ALIGN'ed length. */
static size_t put_newaddr(unsigned char *buf, sa_family_t family, unsigned ifindex,
                          uint8_t scope, const void *addr, size_t alen,
                          const uint32_t *flags, const struct ifa_cacheinfo *ci)
{
    struct nl_test_msg *m = (struct nl_test_msg *)buf;
    size_t off = 0;

    memset(m, 0, sizeof(*m));
    m->nlh.nlmsg_type = RTM_NEWADDR;
    m->nlh.nlmsg_len = NLMSG_LENGTH(sizeof(m->ifa));
    m->ifa.ifa_family = family;
    m->ifa.ifa_prefixlen = (family == AF_INET) ? 32 : 64;
    m->ifa.ifa_scope = scope;
    m->ifa.ifa_index = ifindex;
    add_rta(m->attrs, &off, IFA_ADDRESS, addr, alen);
    if (flags != NULL)
        add_rta(m->attrs, &off, IFA_FLAGS, flags, sizeof(*flags));
    if (ci != NULL)
        add_rta(m->attrs, &off, IFA_CACHEINFO, ci, sizeof(*ci));
    m->nlh.nlmsg_len += (uint32_t)off;
    return NLMSG_ALIGN(m->nlh.nlmsg_len);
}

static void test_nl_decode(void)
{
    struct mn_nl nl;
    struct mn_addr a;
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
        char attrs[128];
    } msg;
    unsigned lo = if_nametoindex("lo");
    unsigned char v6[16];
    uint32_t flags = 0x20;   /* deprecated */
    struct ifa_cacheinfo ci;
    size_t off = 0;

    memset(&nl, 0, sizeof(nl));
    memset(&a, 0, sizeof(a));
    memset(&msg, 0, sizeof(msg));
    if (lo == 0)
        lo = 1;
    nl.n_links = 1;
    nl.links[0].idx = lo;
    nl.links[0].up = 1;
    snprintf(nl.links[0].name, sizeof(nl.links[0].name), "lo");

    CHECK(inet_pton(AF_INET6, "2001:4860:4860::8888", v6) == 1, "v6 fixture");
    memset(&ci, 0, sizeof(ci));

    msg.nlh.nlmsg_type = RTM_NEWADDR;
    msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifa));
    msg.ifa.ifa_family = AF_INET6;
    msg.ifa.ifa_prefixlen = 64;
    msg.ifa.ifa_flags = 0x01;       /* must be overridden by IFA_FLAGS */
    msg.ifa.ifa_scope = 0;
    msg.ifa.ifa_index = lo;
    add_rta(msg.attrs, &off, IFA_ADDRESS, v6, sizeof(v6));
    add_rta(msg.attrs, &off, IFA_FLAGS, &flags, sizeof(flags));
    add_rta(msg.attrs, &off, IFA_CACHEINFO, &ci, sizeof(ci));
    msg.nlh.nlmsg_len += (uint32_t)RTA_ALIGN(off);

    CHECK(mn_nl_decode_addr(&nl, &msg.nlh, &a) == 1, "nl_decode_addr accepts v6 message");
    CHECK(a.family == AF_INET6 && a.flags == 0x20,
          "IFA_FLAGS 32-bit overrides ifa_flags: family=%d flags=0x%x", a.family, a.flags);
    CHECK(a.has_cacheinfo && a.valid_lft == 0, "IFA_CACHEINFO decoded");
    CHECK(a.if_up == 1 && !strcmp(a.ifname, "lo"),
          "if_indextoname + IFF_UP table: name=%s up=%d", a.ifname, a.if_up);

    /* v1.3.1: an IPv6 address whose IFA_CACHEINFO.ifa_prefered == 0 is deprecated no
       matter what IFA_FLAGS says. During an RA lifetime update the kernel clears
       IFA_F_DEPRECATED before the first RTM_NEWADDR (addrconf_prefix_rcv_add_addr)
       and sets it again in addrconf_verify(), so the transient first message must be
       normalised to the same effective state the dump reports. ifa_prefered > 0 keeps
       IFA_FLAGS untouched, and IPv4 (no deprecation concept) is never rewritten. */
    {
        uint32_t f_mta = 0x100;                       /* IFA_F_MANAGETEMPADDR */
        uint32_t f0 = 0;
        unsigned char v4[4] = { 192, 0, 2, 1 };
        struct ifa_cacheinfo cdep = { 0, 1694230, 0, 0 };
        struct ifa_cacheinfo cpref = { 604800, 2592000, 0, 0 };
        struct nl_test_msg m;

        memset(&m, 0, sizeof(m));
        put_newaddr((unsigned char *)&m, AF_INET6, lo, RT_SCOPE_UNIVERSE, v6, 16,
                    &f_mta, &cdep);
        CHECK(mn_nl_decode_addr(&nl, &m.nlh, &a) == 1 && a.flags == (f_mta | IFA_F_DEPRECATED),
              "ifa_prefered=0 normalises DEPRECATED: flags=0x%x", a.flags);
        CHECK(a.has_cacheinfo && a.valid_lft == 1694230,
              "ifa_valid decoded alongside normalisation: valid=%u", a.valid_lft);

        memset(&m, 0, sizeof(m));
        put_newaddr((unsigned char *)&m, AF_INET6, lo, RT_SCOPE_UNIVERSE, v6, 16,
                    &f_mta, &cpref);
        CHECK(mn_nl_decode_addr(&nl, &m.nlh, &a) == 1 && a.flags == f_mta,
              "ifa_prefered>0 keeps IFA_FLAGS: flags=0x%x", a.flags);

        memset(&m, 0, sizeof(m));
        put_newaddr((unsigned char *)&m, AF_INET, lo, RT_SCOPE_UNIVERSE, v4, 4,
                    &f0, &cdep);
        CHECK(mn_nl_decode_addr(&nl, &m.nlh, &a) == 1 && a.flags == 0,
              "IPv4 ifa_prefered=0 does not set DEPRECATED: flags=0x%x", a.flags);
    }

    /* v1.3 REQ-07: filtered drain suppresses RA IFA_CACHEINFO refresh and noise,
       while passing real address changes and allowed-interface IFF_RUNNING flips. */
    {
        int sv[2];
        struct mn_nl fnl;
        struct mn_addr_set snap;
        struct mn_detect_cfg dcfg;
        struct {
            struct nlmsghdr nlh;
            struct ifinfomsg ifi;
        } lmsg;
        char derr[128];
        int ov = 0, carrier = 0, dr;
        uint32_t f_norm = 0x100; /* IFA_F_MANAGETEMPADDR */
        uint32_t f_depr = 0x120; /* + IFA_F_DEPRECATED */

        CHECK(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, sv) == 0,
              "socketpair for netlink drain filter");
        if (sv[0] >= 0) {
            memset(&fnl, 0, sizeof(fnl));
            memset(&snap, 0, sizeof(snap));
            memset(&dcfg, 0, sizeof(dcfg));
            fnl.fd = sv[0];
            fnl.n_links = 1;
            fnl.links[0].idx = lo;
            fnl.links[0].up = 1;
            fnl.links[0].running = 1;
            snprintf(fnl.links[0].name, sizeof(fnl.links[0].name), "lo");
            dcfg.ipv4_mode = MN_IP4_AUTO;
            dcfg.ipv6_mode = MN_IP6_IFACE;
            /* allow lo for this synthetic test */
            snprintf(dcfg.iface_exclude, sizeof(dcfg.iface_exclude), "docker0,veth*");

            snap.n = 1;
            snap.a[0].family = AF_INET6;
            memcpy(snap.a[0].bytes, v6, 16);
            snap.a[0].scope = RT_SCOPE_UNIVERSE;
            snap.a[0].flags = f_norm;
            snap.a[0].has_cacheinfo = 1;
            snap.a[0].valid_lft = 2592000;
            snap.a[0].ifindex = lo;
            snap.a[0].if_up = 1;
            mn_nl_snapshot_fps(&fnl, &snap);

            /* 1) Pure IPv6 RA lifetime refresh (pref/valid updated, same addr+flags) => filtered (0) */
            memset(&msg, 0, sizeof(msg));
            off = 0;
            ci.ifa_prefered = 604800;
            ci.ifa_valid = 2500000;
            msg.nlh.nlmsg_type = RTM_NEWADDR;
            msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifa));
            msg.ifa.ifa_family = AF_INET6;
            msg.ifa.ifa_prefixlen = 64;
            msg.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
            msg.ifa.ifa_index = lo;
            add_rta(msg.attrs, &off, IFA_ADDRESS, v6, sizeof(v6));
            add_rta(msg.attrs, &off, IFA_FLAGS, &f_norm, sizeof(f_norm));
            add_rta(msg.attrs, &off, IFA_CACHEINFO, &ci, sizeof(ci));
            msg.nlh.nlmsg_len += (uint32_t)RTA_ALIGN(off);
            CHECK(send(sv[1], &msg, msg.nlh.nlmsg_len, 0) == (ssize_t)msg.nlh.nlmsg_len,
                  "send RA refresh");
            dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
            CHECK(dr == 0 && ov == 0 && carrier == 0,
                  "RA pure lifetime refresh filtered: dr=%d ov=%d carrier=%d", dr, ov, carrier);

            /* 1b) Production RA burst on a deprecated address (v1.3.1 regression,
               captured on kernel 6.12 with an ISP prefix transition). One RA yields
               three RTM_NEWADDR in a single datagram: the preferred address refresh,
               then the deprecated address twice: IFA_FLAGS=0x100 (DEPRECATED cleared
               by addrconf_prefix_rcv_add_addr) and IFA_FLAGS=0x120 (re-set by
               addrconf_verify()); both carry ifa_prefered=0. The dump fingerprint of
               the deprecated address is 0x120, so the transient message must not
               be reported as interesting (rc3 armed the debounce on every RA). */
            {
                struct mn_addr_set snap2;
                union {
                    struct nl_test_msg m[3];
                    unsigned long align_u;
                    unsigned char b[3 * sizeof(struct nl_test_msg)];
                } pk;
                unsigned char v6dep[16];
                const unsigned char *addr3[3];
                uint32_t fl[3] = { f_norm, f_norm, f_depr };
                struct ifa_cacheinfo ci3[3] = {
                    { 604800, 2592000, 0, 0 }, { 0, 1694230, 0, 0 }, { 0, 1694230, 0, 0 }
                };
                size_t total = 0;
                int i;

                CHECK(inet_pton(AF_INET6, "2001:4860:4860:1::8888", v6dep) == 1, "v6dep fixture");
                addr3[0] = v6;
                addr3[1] = v6dep;
                addr3[2] = v6dep;
                memcpy(&snap2, &snap, sizeof(snap2));
                snap2.n = 2;
                memcpy(&snap2.a[1], &snap.a[0], sizeof(snap2.a[1]));
                memcpy(snap2.a[1].bytes, v6dep, 16);
                snap2.a[1].flags = f_depr;            /* as reported by RTM_GETADDR */
                snap2.a[1].valid_lft = 1694276;
                mn_nl_snapshot_fps(&fnl, &snap2);

                memset(&pk, 0, sizeof(pk));
                for (i = 0; i < 3; i++)
                    total += put_newaddr(pk.b + total, AF_INET6, lo,
                                         RT_SCOPE_UNIVERSE, addr3[i], 16,
                                         &fl[i], &ci3[i]);
                CHECK(send(sv[1], pk.b, total, 0) == (ssize_t)total, "send production RA burst");
                dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
                CHECK(dr == 0 && ov == 0 && carrier == 0,
                      "RA clear/re-set DEPRECATED pair filtered: dr=%d ov=%d carrier=%d",
                      dr, ov, carrier);

                /* 1c) deprecated -> preferred is a real change: same IFA_FLAGS=0x100
                   shape but ifa_prefered > 0 => triggers (1) */
                {
                    struct nl_test_msg m;
                    struct ifa_cacheinfo cip = { 604800, 1694276, 0, 0 };
                    size_t len;

                    memset(&m, 0, sizeof(m));
                    len = put_newaddr((unsigned char *)&m, AF_INET6, lo, RT_SCOPE_UNIVERSE,
                                      v6dep, 16, &f_norm, &cip);
                    (void)send(sv[1], &m, len, 0);
                    dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
                    CHECK(dr == 1, "deprecated -> preferred triggers: dr=%d", dr);
                }

                /* 1d) preferred -> deprecated by lifetime only (IFA_FLAGS unchanged,
                   ifa_prefered drops to 0) => triggers (1) */
                {
                    struct nl_test_msg m;
                    struct ifa_cacheinfo cid = { 0, 1694276, 0, 0 };
                    size_t len;

                    memset(&m, 0, sizeof(m));
                    len = put_newaddr((unsigned char *)&m, AF_INET6, lo, RT_SCOPE_UNIVERSE,
                                      v6, 16, &f_norm, &cid);
                    (void)send(sv[1], &m, len, 0);
                    dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
                    CHECK(dr == 1, "preferred -> deprecated by lifetime triggers: dr=%d", dr);
                }

                /* restore the single-address snapshot used by the cases below */
                mn_nl_snapshot_fps(&fnl, &snap);
            }

            /* 2) Flag transition to DEPRECATED => triggers (1) */
            memset(&msg, 0, sizeof(msg));
            off = 0;
            msg.nlh.nlmsg_type = RTM_NEWADDR;
            msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifa));
            msg.ifa.ifa_family = AF_INET6;
            msg.ifa.ifa_prefixlen = 64;
            msg.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
            msg.ifa.ifa_index = lo;
            add_rta(msg.attrs, &off, IFA_ADDRESS, v6, sizeof(v6));
            add_rta(msg.attrs, &off, IFA_FLAGS, &f_depr, sizeof(f_depr));
            add_rta(msg.attrs, &off, IFA_CACHEINFO, &ci, sizeof(ci));
            msg.nlh.nlmsg_len += (uint32_t)RTA_ALIGN(off);
            (void)send(sv[1], &msg, msg.nlh.nlmsg_len, 0);
            dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
            CHECK(dr == 1 && carrier == 0, "DEPRECATED flag change triggers: dr=%d", dr);

            /* 3) valid_lft -> 0 => triggers (1) */
            memset(&msg, 0, sizeof(msg));
            off = 0;
            ci.ifa_prefered = 0;
            ci.ifa_valid = 0;
            msg.nlh.nlmsg_type = RTM_NEWADDR;
            msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifa));
            msg.ifa.ifa_family = AF_INET6;
            msg.ifa.ifa_prefixlen = 64;
            msg.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
            msg.ifa.ifa_index = lo;
            add_rta(msg.attrs, &off, IFA_ADDRESS, v6, sizeof(v6));
            add_rta(msg.attrs, &off, IFA_FLAGS, &f_norm, sizeof(f_norm));
            add_rta(msg.attrs, &off, IFA_CACHEINFO, &ci, sizeof(ci));
            msg.nlh.nlmsg_len += (uint32_t)RTA_ALIGN(off);
            (void)send(sv[1], &msg, msg.nlh.nlmsg_len, 0);
            dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
            CHECK(dr == 1, "valid_lft=0 triggers: dr=%d", dr);

            /* 4) Excluded interface (exclude lo) => filtered (0) */
            snprintf(dcfg.iface_exclude, sizeof(dcfg.iface_exclude), "lo");
            (void)send(sv[1], &msg, msg.nlh.nlmsg_len, 0);
            dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
            CHECK(dr == 0, "excluded iface filtered: dr=%d", dr);

            /* 5) RTM_NEWLINK with unchanged IFF_UP|IFF_RUNNING => filtered (0) */
            snprintf(dcfg.iface_exclude, sizeof(dcfg.iface_exclude), "docker0");
            memset(&lmsg, 0, sizeof(lmsg));
            lmsg.nlh.nlmsg_type = RTM_NEWLINK;
            lmsg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(lmsg.ifi));
            lmsg.ifi.ifi_index = (int)lo;
            lmsg.ifi.ifi_flags = IFF_UP | IFF_RUNNING;
            (void)send(sv[1], &lmsg, lmsg.nlh.nlmsg_len, 0);
            dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
            CHECK(dr == 0 && carrier == 0, "unchanged link flags filtered: dr=%d", dr);

            /* 6) RTM_NEWLINK with IFF_RUNNING flip (NAT carrier loss) => triggers + carrier=1 */
            lmsg.ifi.ifi_flags = IFF_UP; /* RUNNING cleared */
            (void)send(sv[1], &lmsg, lmsg.nlh.nlmsg_len, 0);
            dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
            CHECK(dr == 1 && carrier == 1, "IFF_RUNNING flip sets carrier_changed: dr=%d carrier=%d", dr, carrier);

            /* 7) Non-global scope (RT_SCOPE_LINK fe80::1) => filtered (0) */
            {
                unsigned char ll6[16];
                CHECK(inet_pton(AF_INET6, "fe80::1", ll6) == 1, "ll6 fixture");
                memset(&msg, 0, sizeof(msg));
                off = 0;
                msg.nlh.nlmsg_type = RTM_NEWADDR;
                msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifa));
                msg.ifa.ifa_family = AF_INET6;
                msg.ifa.ifa_prefixlen = 64;
                msg.ifa.ifa_scope = RT_SCOPE_LINK;
                msg.ifa.ifa_index = lo;
                add_rta(msg.attrs, &off, IFA_ADDRESS, ll6, sizeof(ll6));
                msg.nlh.nlmsg_len += (uint32_t)RTA_ALIGN(off);
                (void)send(sv[1], &msg, msg.nlh.nlmsg_len, 0);
                dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
                CHECK(dr == 0, "link-local scope filtered: dr=%d", dr);
            }

            /* 8) IFA_F_TENTATIVE and IFA_F_TEMPORARY (allow_temporary_ipv6=0) => filtered (0) */
            {
                uint32_t f_tent = 0x40; /* IFA_F_TENTATIVE */
                uint32_t f_temp = 0x01; /* IFA_F_TEMPORARY */
                unsigned char v6new[16];
                CHECK(inet_pton(AF_INET6, "2001:4860:4860::9999", v6new) == 1, "v6new fixture");
                memset(&msg, 0, sizeof(msg));
                off = 0;
                msg.nlh.nlmsg_type = RTM_NEWADDR;
                msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifa));
                msg.ifa.ifa_family = AF_INET6;
                msg.ifa.ifa_prefixlen = 64;
                msg.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
                msg.ifa.ifa_index = lo;
                add_rta(msg.attrs, &off, IFA_ADDRESS, v6new, sizeof(v6new));
                add_rta(msg.attrs, &off, IFA_FLAGS, &f_tent, sizeof(f_tent));
                msg.nlh.nlmsg_len += (uint32_t)RTA_ALIGN(off);
                (void)send(sv[1], &msg, msg.nlh.nlmsg_len, 0);
                dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
                CHECK(dr == 0, "TENTATIVE v6 filtered: dr=%d", dr);

                memset(&msg, 0, sizeof(msg));
                off = 0;
                msg.nlh.nlmsg_type = RTM_NEWADDR;
                msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifa));
                msg.ifa.ifa_family = AF_INET6;
                msg.ifa.ifa_prefixlen = 64;
                msg.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
                msg.ifa.ifa_index = lo;
                add_rta(msg.attrs, &off, IFA_ADDRESS, v6new, sizeof(v6new));
                add_rta(msg.attrs, &off, IFA_FLAGS, &f_temp, sizeof(f_temp));
                msg.nlh.nlmsg_len += (uint32_t)RTA_ALIGN(off);
                (void)send(sv[1], &msg, msg.nlh.nlmsg_len, 0);
                dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
                CHECK(dr == 0, "TEMPORARY v6 filtered when disallowed: dr=%d", dr);

                /* 9) Unknown ifindex (if_indextoname fails) => fail-open triggers (1) */
                memset(&msg, 0, sizeof(msg));
                off = 0;
                msg.nlh.nlmsg_type = RTM_NEWADDR;
                msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifa));
                msg.ifa.ifa_family = AF_INET6;
                msg.ifa.ifa_prefixlen = 64;
                msg.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
                msg.ifa.ifa_index = 999999u;
                add_rta(msg.attrs, &off, IFA_ADDRESS, v6new, sizeof(v6new));
                add_rta(msg.attrs, &off, IFA_FLAGS, &f_norm, sizeof(f_norm));
                msg.nlh.nlmsg_len += (uint32_t)RTA_ALIGN(off);
                (void)send(sv[1], &msg, msg.nlh.nlmsg_len, 0);
                dr = mn_nl_drain_filtered(&fnl, &dcfg, &ov, &carrier, derr, sizeof(derr));
                CHECK(dr == 1, "unknown ifindex fails open: dr=%d", dr);
            }

            close(sv[0]);
            close(sv[1]);
        }
    }

    {
        int overflow = 0;
        char err[256];
        err[0] = '\0';
        CHECK(mn_nl_recv_error(ENOBUFS, &overflow, err, sizeof(err)) == 1 && overflow == 1,
              "ENOBUFS sets overflow");
        CHECK(strstr(err, "buffer") != NULL, "ENOBUFS error text: %s", err);
        overflow = 0;
        CHECK(mn_nl_recv_error(EAGAIN, &overflow, err, sizeof(err)) == 1 && overflow == 0,
              "EAGAIN drains cleanly");
        CHECK(mn_nl_recv_error(EPIPE, &overflow, err, sizeof(err)) == -1,
              "other errno is a hard error");
    }
}

/* ------------------------------------------------------------------ log */
static void test_log(void)
{
    int i;
    const char *keys[2] = { "message", "x" };
    char longval[2048];
    const char *vals[2];
    cap_n = 0;
    mn_log_set_sink(sink, NULL);
    mn_log_init(MN_LOG_DEBUG, MN_LOG_JOURNALD, NULL);
    mn_log(MN_LOG_ERROR, "boom err=E_CFG");
    mn_log(MN_LOG_WARN, "careful");
    mn_log(MN_LOG_INFO, "hello");
    mn_log(MN_LOG_DEBUG, "detail");
    CHECK(cap_n == 4, "4 log lines, got %d", cap_n);
    CHECK(strncmp(cap_lines[0], "<3>miniddns: ", 13) == 0, "error PRI: %s", cap_lines[0]);
    CHECK(strstr(cap_lines[0], "level=error") != NULL, "level=error");
    CHECK(strncmp(cap_lines[1], "<4>miniddns: ", 13) == 0, "warn PRI");
    CHECK(strncmp(cap_lines[2], "<6>miniddns: ", 13) == 0, "info PRI");
    CHECK(strncmp(cap_lines[3], "<7>miniddns: ", 13) == 0, "debug PRI");

    cap_n = 0;
    vals[0] = "he said \"hi\"\nnext";
    vals[1] = "ok";
    mn_logkv(MN_LOG_INFO, "event", keys, vals, 2);
    CHECK(cap_n == 1 && strstr(cap_lines[0], "\\\"hi\\\"") && strstr(cap_lines[0], "\\nnext"),
          "value escaping: %s", cap_n ? cap_lines[0] : "(none)");
    CHECK(strchr(cap_lines[0], '\n') == NULL, "no raw newline in log line");

    memset(longval, 'x', sizeof(longval) - 1);
    longval[sizeof(longval) - 1] = '\0';
    cap_n = 0;
    vals[0] = longval;
    mn_logkv(MN_LOG_INFO, "event", keys, vals, 1);
    CHECK(strstr(cap_lines[0], "truncated=1") != NULL, "long field truncated=1");

    cap_n = 0;
    for (i = 0; i < 10; i++) mn_log_repeat(MN_LOG_INFO, "k1", "record action=unchanged ip=1.1.1.1");
    CHECK(cap_n == 1 && strstr(cap_lines[0], "repeat=10"), "fold 10:1, got %d lines", cap_n);
    cap_n = 0;
    for (i = 0; i < 3; i++) mn_log_repeat(MN_LOG_INFO, "k2", "record action=unchanged ip=2.2.2.2");
    mn_log_repeat_flush();
    CHECK(cap_n == 1 && strstr(cap_lines[0], "repeat=3"), "flush residual, got %d", cap_n);

    cap_n = 0;
    for (i = 0; i < 10; i++)
        mn_log(MN_LOG_INFO, "record action=update ip=1.1.1.1");
    CHECK(cap_n == 10, "action=update must never fold, got %d", cap_n);

    memset(longval, 'x', sizeof(longval) - 1);
    longval[sizeof(longval) - 1] = '\0';
    cap_n = 0;
    mn_log(MN_LOG_INFO, "%s", longval);
    CHECK(strlen(cap_lines[0]) <= 1024 && strstr(cap_lines[0], "truncated=1"),
          "log line capped at 1024 with truncated=1 (len=%zu)", strlen(cap_lines[0]));
    mn_log_set_sink(NULL, NULL);
}

/* --------------------------------------------------------------- sched */
static void test_sched(void)
{
    int seq[4] = { 5, 15, 60, 300 };
    struct mn_memo m;
    struct mn_debounce d;
    memset(&m, 0, sizeof(m));
    memset(&d, 0, sizeof(d));
    CHECK(mn_memo_hit(&m, "1.1.1.1", 1000, 60000) == 0, "empty memo");
    mn_memo_set(&m, "1.1.1.1", 1000);
    CHECK(mn_memo_hit(&m, "1.1.1.1", 2000, 60000) == 1, "memo hit");
    CHECK(mn_memo_hit(&m, "1.1.1.2", 2000, 60000) == 0, "memo different ip");
    CHECK(mn_memo_hit(&m, "1.1.1.1", 62000, 60000) == 0, "memo expired");
    CHECK(mn_memo_hit(&m, "1.1.1.1", 2000, 0) == 0, "memo disabled");

    CHECK(mn_backoff_delay_ms(seq, 4, 0, 0, 0, 0, -1) == 5000, "backoff fallback=0 must be 5s");
    CHECK(mn_backoff_delay_ms(seq, 4, 0, 10, 0, 0, -1) == 5000, "backoff min(fallback)");
    CHECK(mn_backoff_delay_ms(seq, 4, 3, 10, 0, 0, -1) == 10000, "backoff clamps to fallback");
    CHECK(mn_backoff_delay_ms(seq, 4, 3, 0, 0, 0, -1) == 300000, "backoff last step");
    CHECK(mn_backoff_delay_ms(seq, 4, 0, 0, E_TLS_TIME, 0, -1) == 30000, "clock guard 30s");
    CHECK(mn_backoff_delay_ms(seq, 4, 0, 900, E_RATELIMIT, 429, 30) == 30000, "Retry-After override");
    CHECK(mn_backoff_delay_ms(seq, 4, 0, 0, E_HTTP_STATUS, 403, -1) == 300000, "4xx max backoff");
    CHECK(mn_backoff_delay_ms(seq, 4, 0, 0, E_TLS_CERT, 0, -1) == 300000, "cert max backoff");
    CHECK(mn_backoff_delay_ms(seq, 4, 0, 0, E_PARSE, 0, -1) == 300000, "E_PARSE max backoff");
    {
        size_t idx = 0;
        CHECK(mn_backoff_take(seq, 4, &idx, 0, 0, 0, -1) == 5000 && idx == 1,
              "first failure uses seq[0]=5s");
        CHECK(mn_backoff_take(seq, 4, &idx, 0, 0, 0, -1) == 15000 && idx == 2,
              "second failure uses seq[1]=15s");
    }
    CHECK(mn_backoff_delay_ms(seq, 4, 0, 0, 0, 0, 100000) == 86400000, "Retry-After clamp");
    CHECK(mn_backoff_next(3, 4) == 3 && mn_backoff_next(0, 4) == 1, "backoff index");

    CHECK(mn_retry_after_seconds("30", 0) == 30, "retry-after seconds");
    CHECK(mn_retry_after_seconds("0", 0) == 1, "retry-after clamp low");
    CHECK(mn_retry_after_seconds("100000", 0) == 86400, "retry-after clamp high");
    CHECK(mn_retry_after_seconds("Wed, 09 Jun 2021 10:00:00 GMT", 1623232800) <= 86400,
          "retry-after HTTP-date");
    CHECK(mn_retry_after_seconds("garbage", 0) == -1, "retry-after invalid");

    mn_debounce_event(&d, 0, 1500, 15000);
    CHECK(!mn_debounce_due(&d, 1499) && mn_debounce_due(&d, 1500), "single event 1.5s");
    mn_debounce_event(&d, 1000, 1500, 15000);
    CHECK(d.deadline_ms == 2500, "sliding window resets deadline");
    {
        int i;
        for (i = 0; i < 40; i++) mn_debounce_event(&d, i * 500, 1500, 15000);
        CHECK(d.deadline_ms <= d.first_ms + 15000, "hard defer cap 15s");
    }
    mn_debounce_clear(&d);
    CHECK(!mn_debounce_due(&d, 99999), "debounce cleared");
    CHECK(mn_clock_unsynced(1200, 1700000000) == 1, "clock guard on");
    CHECK(mn_clock_unsynced(1800000000, 1700000000) == 0, "clock guard off");
}

/* -------------------------------------------------------------- detect */
static uint32_t v4(const char *s)
{
    struct in_addr a;
    inet_pton(AF_INET, s, &a);
    return a.s_addr;
}
static void v6(const char *s, uint8_t out[16])
{
    inet_pton(AF_INET6, s, out);
}

static void test_detect(void)
{
    uint8_t b[16];
    char o1[MN_IP_STRLEN], o2[MN_IP_STRLEN];
    static const char *blocked[] = {
        "10.0.0.1","172.16.0.1","192.168.1.1","100.64.0.1","127.0.0.1",
        "169.254.1.1","0.1.2.3","192.0.0.1","192.0.2.1","198.18.0.1",
        "198.51.100.1","203.0.113.1","240.0.0.1","224.0.0.1","255.255.255.255"
    };
    static const char *allowed[] = {
        "8.8.8.8","1.1.1.1","172.15.0.1","172.32.0.1","100.63.255.255","100.128.0.0"
    };
    size_t i;
    for (i = 0; i < sizeof(blocked)/sizeof(blocked[0]); i++)
        CHECK(mn_ip4_publishable(v4(blocked[i])) == 0, "v4 must block %s", blocked[i]);
    for (i = 0; i < sizeof(allowed)/sizeof(allowed[0]); i++)
        CHECK(mn_ip4_publishable(v4(allowed[i])) == 1, "v4 must allow %s", allowed[i]);

    CHECK(mn_ip_normalize(AF_INET6, "2001:db8::1", o1) == 0, "v6 normalize");
    CHECK(mn_ip_normalize(AF_INET6, "2001:0db8:0000:0000:0000:0000:0000:0001", o2) == 0,
          "v6 normalize full");
    CHECK(strcmp(o1, o2) == 0 && mn_ip_equal(AF_INET6, o1, o2), "v6 canonical compare");
    CHECK(mn_ip_normalize(AF_INET6, "2001:DB8::1", o2) == 0 && strcmp(o1, o2) == 0,
          "v6 lowercase");
    CHECK(mn_ip_normalize(AF_INET6, "::", o2) == 0, "v6 ::");
    CHECK(mn_ip_normalize(AF_INET6, "::1", o2) == 0, "v6 ::1");
    CHECK(mn_ip_normalize(AF_INET6, "fe80::1%eth0", o2) == 0, "v6 zone-id stripped");
    CHECK(mn_ip_normalize(AF_INET, "01.2.3.4", o2) != 0, "v4 leading zeros rejected");
    CHECK(mn_ip_equal(AF_INET, "1.1.1.1", "1.1.1.1"), "v4 equal");
    CHECK(!mn_ip_equal(AF_INET, "1.1.1.1", "1.1.1.2"), "v4 different");

    {
        static const char *bad6[] = {
            "2001:db8::1","fc00::1","fe80::1","::1","::","ff02::1",
            "100::1","fec0::1","::ffff:1.2.3.4","64:ff9b::1","4000::1"
        };
        for (i = 0; i < sizeof(bad6)/sizeof(bad6[0]); i++) {
            v6(bad6[i], b);
            CHECK(mn_ip6_publishable(b) == 0, "v6 must block %s", bad6[i]);
        }
        v6("2001:4860:4860::8888", b);
        CHECK(mn_ip6_publishable(b) == 1, "v6 global unicast");
        v6("2000::1", b);
        CHECK(mn_ip6_publishable(b) == 1, "v6 2000::/3 lower bound");
    }

    CHECK(mn_iface_allowed("eth0", "", "lo,docker0,veth*"), "iface allowed");
    CHECK(!mn_iface_allowed("veth123", "", "lo,docker0,veth*"), "iface excluded");
    CHECK(mn_iface_allowed("eth0", "eth0", "lo"), "iface include");
    CHECK(!mn_iface_allowed("eth1", "eth0", ""), "iface not included");
    CHECK(!mn_iface_allowed("wg0", "", "wg*"), "iface trailing glob exclude");

    /* §14.1 ipv6_filter + iface_up + IFA_FLAGS, built as plain addr structs */
    {
        struct mn_cfg cfg;
        struct mn_addr_set set;
        struct mn_detect_result res;
        char err[256];
        mn_cfg_defaults(&cfg, NULL);
        memset(&set, 0, sizeof(set));
        memset(&res, 0, sizeof(res));
        cfg.detect.ipv6_mode = MN_IP6_IFACE;
#define ADDADDR(flagbits, up, valid, hasci, ifn, text) do { \
            struct mn_addr *x = &set.a[set.n++]; \
            x->family = AF_INET6; x->scope = 0; x->flags = (flagbits); \
            x->if_up = (up); x->valid_lft = (valid); x->has_cacheinfo = (hasci); \
            v6((text), x->bytes); snprintf(x->ifname, sizeof(x->ifname), "%s", (ifn)); \
        } while (0)
        ADDADDR(0x01, 1, 9999, 0, "eth0", "2001:4860:4860::1111");  /* temporary */
        ADDADDR(0x08, 1, 9999, 0, "eth0", "2001:4860:4860::2222");  /* dadfailed */
        ADDADDR(0x40, 1, 9999, 0, "eth0", "2001:4860:4860::3333");  /* tentative */
        ADDADDR(0x20, 1, 9999, 0, "eth0", "2001:4860:4860::4444");  /* deprecated */
        ADDADDR(0, 1, 0, 1, "eth0", "2001:4860:4860::5555");         /* valid_lft=0 */
        ADDADDR(0, 0, 9999, 0, "eth0", "2001:4860:4860::6666");       /* if down */
        ADDADDR(0, 1, 9999, 0, "docker0", "2001:4860:4860::7777");   /* excluded iface */
        ADDADDR(0, 1, 9999, 0, "eth0", "2001:4860:4860::8888");       /* good */
#undef ADDADDR
        CHECK(mn_detect_ipv6(&cfg, &set, &res, err, sizeof(err)) == MN_OK,
              "detect ipv6 should find the good address: %s", err);
        CHECK(strcmp(res.ip, "2001:4860:4860::8888") == 0, "deterministic winner: %s", res.ip);
        CHECK(res.filtered_temporary >= 1 && res.filtered_dadfailed >= 1 &&
              res.filtered_iface_down >= 1 && res.filtered_lifetime >= 1,
              "filter counters");
        /* all filtered -> E_NO_IP */
        set.n = 1;
        set.a[0].flags = 0x01;
        CHECK(mn_detect_ipv6(&cfg, &set, &res, err, sizeof(err)) == E_NO_IP,
              "temporary-only must be E_NO_IP");
    }

    {
        struct mn_cfg cfg;
        struct mn_addr_set set;
        struct mn_detect_result res;
        char err[256];
        mn_cfg_defaults(&cfg, NULL);
        memset(&set, 0, sizeof(set));
        memset(&res, 0, sizeof(res));
        cfg.detect.ipv4_mode = MN_IP4_OFF;
        CHECK(mn_detect_ipv4(&cfg, &set, NULL, &res, err, sizeof(err)) == E_NO_IP,
              "ipv4 off => no ip");
        cfg.detect.ipv6_mode = MN_IP6_OFF;
        CHECK(mn_detect_ipv6(&cfg, &set, &res, err, sizeof(err)) == E_NO_IP,
              "ipv6 off => no ip");
        cfg.detect.ipv4_mode = MN_IP4_IFACE;
        set.n = 1;
        set.a[0].family = AF_INET; set.a[0].scope = 0; set.a[0].if_up = 1;
        inet_pton(AF_INET, "192.168.1.5", set.a[0].bytes);
        snprintf(set.a[0].ifname, sizeof(set.a[0].ifname), "eth0");
        CHECK(mn_detect_ipv4(&cfg, &set, NULL, &res, err, sizeof(err)) == E_NO_IP,
              "private ipv4 must not be published");
        cfg.detect.allow_private_ipv4 = 1;
        CHECK(mn_detect_ipv4(&cfg, &set, NULL, &res, err, sizeof(err)) == MN_OK,
              "allow_private_ipv4=1: %s", err);
        CHECK(strcmp(res.ip, "192.168.1.5") == 0, "private allowed ip=%s", res.ip);
    }
}

/* ---------------------------------------------------------- http_parse */
static void test_http_parse(void)
{
    struct mn_http_result r;
    int ec, rc;
    char err[256], big[MN_LIMIT_BODY + 32768];
    const char *cl =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n"
        "{\"success\":true}";
    const char *eof = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n1.1.1.1\n";
    const char *chunked =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: x\r\n\r\n";
    const char *badstatus = "NOTHTTP 200 OK\r\n\r\n";
    const char *te = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nxx";
    const char *ce = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nxx";
    const char *ra = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\nContent-Length: 2\r\n\r\n{}";
    const char *radate = "HTTP/1.1 429 Too Many Requests\r\n"
                         "Retry-After: Wed, 09 Jun 2021 10:00:00 GMT\r\nContent-Length: 2\r\n\r\n{}";
    const char *badchunk = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nhi\r\n0\r\n\r\n";

    memset(&r, 0, sizeof(r));
    rc = mn_http_parse_raw(cl, strlen(cl), &r, &ec, err, sizeof(err));
    CHECK(rc == 0 && r.status == 200 && r.body_len == 16 && strstr(r.body, "success"),
          "Content-Length parse rc=%d status=%d len=%zu err=%s", rc, r.status, r.body_len, err);
    mn_http_result_free(&r);

    memset(&r, 0, sizeof(r));
    rc = mn_http_parse_raw(eof, strlen(eof), &r, &ec, err, sizeof(err));
    CHECK(rc == 0 && r.body && !strncmp(r.body, "1.1.1.1", 7), "EOF parse rc=%d err=%s", rc, err);
    mn_http_result_free(&r);

    memset(&r, 0, sizeof(r));
    rc = mn_http_parse_raw(chunked, strlen(chunked), &r, &ec, err, sizeof(err));
    CHECK(rc == 0 && r.body && !strcmp(r.body, "hello world"),
          "chunked parse rc=%d body=%s err=%s", rc, r.body ? r.body : "(null)", err);
    mn_http_result_free(&r);

    memset(&r, 0, sizeof(r));
    rc = mn_http_parse_raw(badstatus, strlen(badstatus), &r, &ec, err, sizeof(err));
    CHECK(rc != 0 && ec == E_PARSE && strstr(err, "bad_status_line"), "bad status line: %s", err);
    mn_http_result_free(&r);

    memset(&r, 0, sizeof(r));
    rc = mn_http_parse_raw(te, strlen(te), &r, &ec, err, sizeof(err));
    CHECK(rc != 0 && strstr(err, "transfer_encoding"), "TE gzip: %s", err);
    mn_http_result_free(&r);

    memset(&r, 0, sizeof(r));
    rc = mn_http_parse_raw(ce, strlen(ce), &r, &ec, err, sizeof(err));
    CHECK(rc != 0 && strstr(err, "encoded_body"), "CE gzip: %s", err);
    mn_http_result_free(&r);

    memset(&r, 0, sizeof(r));
    rc = mn_http_parse_raw(ra, strlen(ra), &r, &ec, err, sizeof(err));
    CHECK(rc == 0 && r.status == 429 && r.retry_after_secs == 30,
          "Retry-After seconds rc=%d ra=%d", rc, r.retry_after_secs);
    mn_http_result_free(&r);

    memset(&r, 0, sizeof(r));
    rc = mn_http_parse_raw(radate, strlen(radate), &r, &ec, err, sizeof(err));
    CHECK(rc == 0 && r.retry_after_secs >= 1, "Retry-After HTTP-date ra=%d", r.retry_after_secs);
    mn_http_result_free(&r);

    memset(&r, 0, sizeof(r));
    rc = mn_http_parse_raw(badchunk, strlen(badchunk), &r, &ec, err, sizeof(err));
    CHECK(rc != 0 && strstr(err, "bad_chunk"), "bad chunk: %s", err);
    mn_http_result_free(&r);

    /* header too large */
    {
        size_t n = 0;
        n += (size_t)snprintf(big + n, sizeof(big) - n, "HTTP/1.1 200 OK\r\nX-Big: ");
        memset(big + n, 'a', MN_LIMIT_HEADER + 100);
        n += MN_LIMIT_HEADER + 100;
        memcpy(big + n, "\r\n\r\nbody", 9);
        n += 9;
        memset(&r, 0, sizeof(r));
        rc = mn_http_parse_raw(big, n, &r, &ec, err, sizeof(err));
        CHECK(rc != 0 && strstr(err, "header_too_large"), "header limit: %s", err);
        mn_http_result_free(&r);
    }

    /* body too large */
    {
        size_t n = 0;
        n += (size_t)snprintf(big + n, sizeof(big) - n,
                              "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n",
                              MN_LIMIT_BODY + 10);
        memset(big + n, 'b', MN_LIMIT_BODY + 10);
        n += MN_LIMIT_BODY + 10;
        memset(&r, 0, sizeof(r));
        rc = mn_http_parse_raw(big, n, &r, &ec, err, sizeof(err));
        CHECK(rc != 0 && strstr(err, "body_too_large"), "body limit: %s", err);
        mn_http_result_free(&r);
    }
    CHECK(!strcmp(mn_tls_version_name(BR_TLS12), "1.2"), "TLS version name 1.2");
    CHECK(!strcmp(mn_tls_version_name(0), "unknown"), "TLS unknown version name");

    /* v1.3 REQ-05: in-place HTTP parser parity across CL, EOF, chunked, errors */
    {
        const char *cases[] = { cl, eof, chunked, ra, badchunk, te };
        int expect_ok[] = { 1, 1, 1, 1, 0, 0 };
        size_t ci;
        for (ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ++ci) {
            size_t clen = strlen(cases[ci]);
            char *heap_buf = (char *)malloc(clen + 1);
            struct mn_http_result r1, r2;
            int ec1 = 0, ec2 = 0, rc1, rc2;
            char e1[128], e2[128];
            CHECK(heap_buf != NULL, "in-place alloc case %zu", ci);
            if (!heap_buf) continue;
            memcpy(heap_buf, cases[ci], clen + 1);
            rc1 = mn_http_parse_raw(cases[ci], clen, &r1, &ec1, e1, sizeof(e1));
            rc2 = mn_http_parse_in_place(&heap_buf, clen, &r2, &ec2, e2, sizeof(e2));
            CHECK(heap_buf == NULL && rc1 == rc2 && ec1 == ec2 && (rc2 == 0) == expect_ok[ci],
                  "in-place case %zu rc1=%d rc2=%d", ci, rc1, rc2);
            if (rc1 == 0 && rc2 == 0) {
                CHECK(r1.status == r2.status && r1.body_len == r2.body_len
                      && r1.retry_after_secs == r2.retry_after_secs
                      && !strcmp(r1.body, r2.body),
                      "in-place parity case %zu body='%s'", ci, r2.body ? r2.body : "");
            }
            mn_http_result_free(&r1);
            mn_http_result_free(&r2);
        }
    }
}

/* ----------------------------------------------------------- json_util */
static void test_json(void)
{
    char id[64], content[64], code[64], msg[256], err[256];
    int success = -1, nres = -1, rc;
    const char *ok = "{\"success\":true,\"result\":[{\"id\":\"abc123\",\"content\":\"1.1.1.1\"}],\"errors\":[]}";
    const char *none = "{\"success\":true,\"result\":[],\"errors\":[]}";
    const char *fail = "{\"success\":false,\"result\":[],\"errors\":[{\"code\":9109,\"message\":\"Invalid \\\"access\\\" token\"}]}";
    memset(id, 0, sizeof(id)); memset(content, 0, sizeof(content));
    rc = mn_cf_parse(ok, strlen(ok), &success, id, sizeof(id), content, sizeof(content),
                     &nres, code, sizeof(code), msg, sizeof(msg), err, sizeof(err));
    CHECK(rc == 0 && success == 1 && nres == 1 && !strcmp(id, "abc123")
          && !strcmp(content, "1.1.1.1"), "cf parse ok: rc=%d success=%d id=%s content=%s err=%s",
          rc, success, id, content, err);
    rc = mn_cf_parse(none, strlen(none), &success, id, sizeof(id), content, sizeof(content),
                     &nres, code, sizeof(code), msg, sizeof(msg), err, sizeof(err));
    CHECK(rc == 0 && nres == 0, "cf parse empty result rc=%d", rc);
    rc = mn_cf_parse(fail, strlen(fail), &success, id, sizeof(id), content, sizeof(content),
                     &nres, code, sizeof(code), msg, sizeof(msg), err, sizeof(err));
    CHECK(rc == 0 && success == 0 && !strcmp(code, "9109") && strstr(msg, "access"),
          "cf parse errors: code=%s msg=%s", code, msg);
    rc = mn_cf_parse("{oops", 5, &success, id, sizeof(id), content, sizeof(content),
                     &nres, code, sizeof(code), msg, sizeof(msg), err, sizeof(err));
    CHECK(rc == E_PARSE, "malformed JSON rejected");

    /* v1.3 REQ-08: dual-stack A + AAAA single-GET parser + pagination detection */
    {
        struct mn_cf_dual_result dual;
        const char *dual_ok =
            "{\"success\":true,\"result\":["
            "{\"id\":\"txt1\",\"type\":\"TXT\",\"content\":\"v=spf1\"},"
            "{\"id\":\"id-a1\",\"type\":\"A\",\"content\":\"203.0.113.1\"},"
            "{\"id\":\"id-v6\",\"type\":\"AAAA\",\"content\":\"2001:db8::1\"},"
            "{\"id\":\"id-a2\",\"type\":\"A\",\"content\":\"203.0.113.2\"}"
            "],\"result_info\":{\"page\":1,\"total_pages\":1},\"errors\":[]}";
        const char *dual_paged =
            "{\"success\":true,\"result\":[],\"result_info\":{\"page\":1,\"total_pages\":2},\"errors\":[]}";
        rc = mn_cf_parse_dual(dual_ok, strlen(dual_ok), &dual, err, sizeof(err));
        CHECK(rc == MN_OK && dual.success == 1 && dual.total_pages == 1
              && dual.n_a == 2 && !strcmp(dual.a_id, "id-a1") && !strcmp(dual.a_content, "203.0.113.1")
              && dual.n_aaaa == 1 && !strcmp(dual.aaaa_id, "id-v6") && !strcmp(dual.aaaa_content, "2001:db8::1"),
              "cf dual parse A+AAAA: rc=%d na=%d n6=%d", rc, dual.n_a, dual.n_aaaa);
        rc = mn_cf_parse_dual(dual_paged, strlen(dual_paged), &dual, err, sizeof(err));
        CHECK(rc == MN_OK && dual.total_pages == 2,
              "cf dual parse total_pages=2: rc=%d tp=%d", rc, dual.total_pages);
    }
}

/* -------------------------------------------------------------- ca load */
static void test_ca(void)
{
    char buf[MN_LIMIT_CA_FILE + 1], err[512], root[MN_PATH_MAX], path[MN_PATH_MAX];
    struct mn_ca ca;
    br_x509_trust_anchor *ta = NULL;
    void *arena = NULL;
    size_t n = 0, len = 0;
    struct mn_ca_info info;
    memset(&info, 0, sizeof(info));
    memset(&ca, 0, sizeof(ca));

    if (read_file("tmp/ca.pem", buf, sizeof(buf)) != 0) {
        fprintf(stderr, "SKIP ca tests: tmp/ca.pem missing (run via run.sh)\n");
        return;
    }
    len = strlen(buf);
    CHECK(mn_ca_parse_bundle(buf, len, &ta, &n, &arena, &info, err, sizeof(err)) == 0,
          "CA parse: %s", err);
    CHECK(n >= 1 && ta != NULL && arena != NULL, "CA anchors n=%zu", n);
    free(arena);

    /* empty / non-PEM must fail */
    CHECK(mn_ca_parse_bundle("", 0, &ta, &n, &arena, &info, err, sizeof(err)) != 0,
          "empty CA fails");
    CHECK(mn_ca_parse_bundle("not a pem file\n", 15, &ta, &n, &arena, &info, err, sizeof(err)) != 0,
          "non-PEM CA fails");
    if (read_file("tmp/bad.pem", buf, sizeof(buf)) == 0) {
        int rc = mn_ca_parse_bundle(buf, strlen(buf), &ta, &n, &arena, &info, err, sizeof(err));
        if (rc == 0) free(arena);
        CHECK(rc != 0 || info.n_skipped > 0 || n < 2, "bad base64 skipped/counted");
    }

    /* §14.1 symlink CA path (whitelisted under artifact root) */
    mn_find_artifact_root(root, sizeof(root));
    if (root[0]) {
        snprintf(path, sizeof(path), "%.400s/ca/test-ca-link.pem", root);
        if (access(path, F_OK) == 0) {
            CHECK(mn_ca_init(&ca, path, 1, err, sizeof(err)) == 0, "symlink CA loads: %s", err);
            if (ca.anchors) {
                size_t got = 0;
                mn_ca_current(&ca, &got);
                CHECK(got >= 1, "symlink CA anchors=%zu", got);
            }
            /* §14.3: mtime change with identical content reloads successfully */
            {
                char target[MN_PATH_MAX];
                snprintf(target, sizeof(target), "%.400s/ca/test-ca.pem", root);
                utime(target, NULL);
                CHECK(mn_ca_refresh(&ca) == 0, "CA reload on mtime change");
                CHECK(ca.n_anchors >= 1, "CA anchors retained after reload");
            }
            mn_ca_free(&ca);
        }
        /* v1.3 REQ-03: streaming 4 KiB CA loader matches full-buffer parser across chunk boundaries */
        snprintf(path, sizeof(path), "%.400s/../ca/ca-certificates.crt", root);
        if (access(path, F_OK) == 0) {
            char *full = (char *)malloc(MN_LIMIT_CA_FILE + 1);
            CHECK(full != NULL, "alloc full CA bundle for parity test");
            if (full && read_file(path, full, MN_LIMIT_CA_FILE + 1) == 0) {
                br_x509_trust_anchor *ta2 = NULL;
                void *arena2 = NULL;
                size_t n2 = 0, got2 = 0;
                struct mn_ca_info info2;
                memset(&info2, 0, sizeof(info2));
                memset(&ca, 0, sizeof(ca));
                CHECK(mn_ca_parse_bundle(full, strlen(full), &ta2, &n2, &arena2, &info2,
                                         err, sizeof(err)) == 0,
                      "full CA bundle parse: %s", err);
                /* Put a symlink inside tests/ca -> real bundle so whitelist allows it */
                {
                    char linkp[MN_PATH_MAX];
                    snprintf(linkp, sizeof(linkp), "%.400s/ca/stream-test.crt", root);
                    unlink(linkp);
                    if (symlink(path, linkp) == 0) {
                        /* symlink resolves outside tests/ca -> rejected unless copied; test copy */
                        unlink(linkp);
                    }
                    {
                        FILE *out = fopen(linkp, "wb");
                        if (out) {
                            fwrite(full, 1, strlen(full), out);
                            fclose(out);
                            chmod(linkp, 0644);
                            CHECK(mn_ca_init(&ca, linkp, 1, err, sizeof(err)) == 0,
                                  "streaming CA init multi-cert (>4KiB): %s", err);
                            mn_ca_current(&ca, &got2);
                            CHECK(got2 == n2 && got2 > 50,
                                  "streaming CA count matches buffer parse: stream=%zu buf=%zu",
                                  got2, n2);
                            /* Reload failure on corrupted bundle keeps old anchors */
                            {
                                FILE *badf = fopen(linkp, "wb");
                                if (badf) {
                                    fputs("not a valid pem\n", badf);
                                    fclose(badf);
                                    chmod(linkp, 0644);
                                    CHECK(mn_ca_refresh(&ca) == 0,
                                          "streaming CA refresh failure keeps old anchors");
                                    got2 = 0;
                                    mn_ca_current(&ca, &got2);
                                    CHECK(got2 == n2,
                                          "old anchors preserved after failed reload: %zu vs %zu",
                                          got2, n2);
                                }
                            }
                            mn_ca_free(&ca);
                            unlink(linkp);
                        }
                    }
                }
                free(arena2);
            }
            free(full);
        }
    }
}

/* ----------------------------------------------------------- provider */
static void test_provider(void)
{
    const struct mn_provider_ops *ops = mn_provider_lookup("cloudflare");
    CHECK(ops != NULL, "cloudflare registered");
    if (ops) {
        CHECK(!strcmp(ops->kind, "cloudflare"), "kind");
        CHECK((ops->caps & MN_CAP_PATCH_CONTENT) && (ops->caps & MN_CAP_CREATE)
              && (ops->caps & MN_CAP_DISCOVER), "CF capabilities");
    }
    CHECK(mn_provider_lookup("desec") == NULL, "only cloudflare in v1");

    /* v1.3 REQ-03: token_file bounded read rejects >MN_TOKEN_MAX-1 token line */
    {
        FILE *f = fopen("tmp/long.token", "wb");
        char bigtok[MN_TOKEN_MAX + 32];
        char err[256];
        struct mn_cfg cfg;
        struct mn_provider provs[1];
        memset(bigtok, 'T', sizeof(bigtok));
        bigtok[sizeof(bigtok) - 1] = '\n';
        CHECK(f != NULL, "long.token created");
        if (f) {
            fwrite(bigtok, 1, sizeof(bigtok), f);
            fclose(f);
            chmod("tmp/long.token", 0600);
            mn_cfg_defaults(&cfg, ".");
            cfg.allow_non_root_owner = 1;
            cfg.n_providers = 1;
            snprintf(cfg.providers[0].id, sizeof(cfg.providers[0].id), "cf");
            snprintf(cfg.providers[0].kind, sizeof(cfg.providers[0].kind), "cloudflare");
            snprintf(cfg.providers[0].token_file, sizeof(cfg.providers[0].token_file), "tmp/long.token");
            memset(provs, 0, sizeof(provs));
            CHECK(mn_provider_init_all(&cfg, provs, 1, 0, err, sizeof(err)) != 0
                  && strstr(err, "token_too_long") != NULL,
                  "oversized token line rejected: %s", err);
            unlink("tmp/long.token");
        }
    }

    /* v1.3 REQ-08: dual-stack cycle_begin handles AAAA declared before A across multiple names */
    if (ops && ops->cycle_begin && ops->cycle_end) {
        struct mn_cfg cfg;
        struct mn_provider p;
        mn_cfg_defaults(&cfg, ".");
        cfg.n_records = 4;
        snprintf(cfg.records[0].provider_id, sizeof(cfg.records[0].provider_id), "cf");
        snprintf(cfg.records[0].name, sizeof(cfg.records[0].name), "first.example.com");
        cfg.records[0].family = AF_INET6;
        cfg.records[0].enabled = 1;
        snprintf(cfg.records[1].provider_id, sizeof(cfg.records[1].provider_id), "cf");
        snprintf(cfg.records[1].name, sizeof(cfg.records[1].name), "first.example.com");
        cfg.records[1].family = AF_INET;
        cfg.records[1].enabled = 1;
        snprintf(cfg.records[2].provider_id, sizeof(cfg.records[2].provider_id), "cf");
        snprintf(cfg.records[2].name, sizeof(cfg.records[2].name), "second.example.com");
        cfg.records[2].family = AF_INET;
        cfg.records[2].enabled = 1;
        snprintf(cfg.records[3].provider_id, sizeof(cfg.records[3].provider_id), "cf");
        snprintf(cfg.records[3].name, sizeof(cfg.records[3].name), "second.example.com");
        cfg.records[3].family = AF_INET6;
        cfg.records[3].enabled = 1;
        memset(&p, 0, sizeof(p));
        p.id = "cf";
        p.ops = ops;
        ops->cycle_begin(&p, &cfg);
        CHECK(p.priv != NULL, "cf_cycle_begin initializes dual-stack cache when AAAA precedes A");
        ops->cycle_end(&p);
        CHECK(p.priv == NULL, "cf_cycle_end clears dual-stack cache");
    }

    /* v1.3 REQ-07: quiet local snapshot detection emits zero logs on NAT private IPv4 */
    {
        struct mn_cfg cfg;
        struct mn_addr_set set;
        struct mn_detect_result r4, r6;
        uint64_t sig = 0;
        unsigned char priv4[4] = { 192, 168, 1, 50 };
        mn_cfg_defaults(&cfg, ".");
        cfg.detect.ipv4_mode = MN_IP4_EXTERNAL;
        memset(&set, 0, sizeof(set));
        set.n = 1;
        set.a[0].family = AF_INET;
        memcpy(set.a[0].bytes, priv4, 4);
        set.a[0].scope = RT_SCOPE_UNIVERSE;
        set.a[0].ifindex = 2;
        set.a[0].if_up = 1;
        snprintf(set.a[0].ifname, sizeof(set.a[0].ifname), "eth0");
        cap_n = 0;
        mn_log_set_sink(sink, NULL);
        mn_log_init(MN_LOG_DEBUG, MN_LOG_JOURNALD, NULL);
        CHECK(mn_detect_ipv4_iface_only(&cfg, &set, &r4, &sig) == E_NO_IP && sig != 0,
              "external mode iface_only returns E_NO_IP with non-zero v4_if_sig");
        CHECK(mn_detect_ipv6_quiet(&cfg, &set, &r6) == E_NO_IP,
              "ipv6_quiet returns E_NO_IP when no v6 present");
        CHECK(cap_n == 0, "quiet local snap emits zero logs, got %d", cap_n);
        mn_log_set_sink(NULL, NULL);
    }
}

int main(void)
{
    mkdir("tmp", 0755);
    printf("== miniddns unit tests ==\n");
    test_cfg();
    test_util();
    test_nl_decode();
    test_log();
    test_sched();
    test_detect();
    test_http_parse();
    test_json();
    test_ca();
    test_provider();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}

/* main.c — §05 lifecycle, §11 CLI, single-threaded ppoll event loop */
#include "miniddns.h"
#include "util.h"
#include "log.h"
#include "cfg.h"
#include "sched.h"
#include "ca.h"
#include "tls_http.h"
#include "nl_addr.h"
#include "detect.h"
#include "provider.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#if defined(__GLIBC__)
#include <malloc.h>
#endif

static void maybe_trim_heap(void)
{
#if defined(__GLIBC__)
    (void)malloc_trim(0);
#endif
}

struct cli {
    const char *config;
    const char *log_level;
    int foreground, once, dry_run, print_ip;
    int check_config, check_ca, version, help, allow_non_root_owner;
};

static void usage(FILE *o)
{
    fprintf(o,
        "miniddns " MN_VERSION " — event-driven dynamic DNS updater\n"
        "usage: miniddns [options]\n"
        "  -c, --config PATH          explicit config (missing = error)\n"
        "  -f, --foreground           foreground daemon (default)\n"
        "  -1, --once                 one cycle then exit (takes flock)\n"
        "  -n, --dry-run              implies --once; no writes, no flock\n"
        "      --print-ip             detect IP only, no provider, no token\n"
        "      --check-config         parse+validate config and print normalized values\n"
        "      --check-ca             load CA and TLS handshake against every endpoint\n"
        "  -l, --log-level L          error|warn|info|debug (overrides config)\n"
        "      --allow-non-root-owner skip the root-owner file check (tests)\n"
        "  -v, --version              version and build information\n"
        "  -h, --help                 this help\n");
}

static void version_info(void)
{
    printf("miniddns %s\n", MN_VERSION);
    printf("bearssl=0.6 (vendored) jsmn=vendored (single header)\n");
#ifdef __GLIBC__
#define MN_LIBC_NAME "glibc"
#else
#define MN_LIBC_NAME "musl"
#endif
#ifdef MN_STATIC_BUILD
    printf("build=static libc=%s\n", MN_LIBC_NAME);
#else
    printf("build=dynamic libc=%s (use `make static` for the static artifact)\n", MN_LIBC_NAME);
#endif
    printf("tls=1.2 provider=cloudflare\n");
}

static int opt_value(int argc, char **argv, int *i, const char *arg,
                     const char *opt, const char **out)
{
    size_t n = strlen(opt);
    if (strcmp(arg, opt) == 0) {
        if (*i + 1 >= argc) return -1;
        *out = argv[++(*i)];
        return 0;
    }
    if (strncmp(arg, opt, n) == 0 && arg[n] == '=') { *out = arg + n + 1; return 0; }
    return 1;
}

static int parse_cli(int argc, char **argv, struct cli *c)
{
    int i;
    memset(c, 0, sizeof(*c));
    /* §11 rule 5: --version/--help win over everything, immediately. */
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) c->version = 1;
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) c->help = 1;
    }
    if (c->version || c->help) return 0;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        int r;
        if ((r = opt_value(argc, argv, &i, a, "--config", &c->config)) == 0) {
            if (c->config[0] == '\0') {
                fprintf(stderr, "--config needs a path\n");
                return -1;
            }
            continue;
        } else if (r < 0) { fprintf(stderr, "--config needs a path\n"); return -1; }
        if (!strcmp(a, "-c")) {
            if (i + 1 >= argc) { fprintf(stderr, "-c needs a path\n"); return -1; }
            c->config = argv[++i];
            if (c->config[0] == '\0') {
                fprintf(stderr, "-c needs a path\n");
                return -1;
            }
            continue;
        }
        if ((r = opt_value(argc, argv, &i, a, "--log-level", &c->log_level)) == 0) continue;
        else if (r < 0) { fprintf(stderr, "--log-level needs a value\n"); return -1; }
        if (!strcmp(a, "-l")) {
            if (i + 1 >= argc) { fprintf(stderr, "-l needs a value\n"); return -1; }
            c->log_level = argv[++i]; continue;
        }
        if (!strcmp(a, "-f") || !strcmp(a, "--foreground")) { c->foreground = 1; continue; }
        if (!strcmp(a, "-1") || !strcmp(a, "--once")) { c->once = 1; continue; }
        if (!strcmp(a, "-n") || !strcmp(a, "--dry-run")) { c->dry_run = 1; c->once = 1; continue; }
        if (!strcmp(a, "--print-ip")) { c->print_ip = 1; continue; }
        if (!strcmp(a, "--check-config")) { c->check_config = 1; continue; }
        if (!strcmp(a, "--check-ca")) { c->check_ca = 1; continue; }
        if (!strcmp(a, "--allow-non-root-owner")) { c->allow_non_root_owner = 1; continue; }
        fprintf(stderr, "miniddns: unknown option: %s\n", a);
        return -1;
    }
    /* §11 rule 2: diagnostics and one-shot are mutually exclusive. */
    if ((c->print_ip || c->check_config || c->check_ca) && (c->once || c->dry_run)) {
        fprintf(stderr, "miniddns: --print-ip/--check-* cannot be combined with --once/--dry-run\n");
        return -1;
    }
    if (c->log_level) {
        int lv;
        if (mn_log_level_parse(c->log_level, &lv) != 0) {
            fprintf(stderr, "miniddns: invalid --log-level %s\n", c->log_level);
            return -1;
        }
    }
    return 0;
}

/* returns 0 ok, 1 no-config (diagnostics), 2 unreadable, 3 validation error */
static int load_config(const struct cli *cli, int diagnostic, struct mn_cfg *cfg,
                       char *err, size_t errlen)
{
    char root[MN_PATH_MAX], path[MN_PATH_MAX], perr[512];
    int io_err = 0;

    mn_find_artifact_root(root, sizeof(root));
    if (mn_resolve_conf_path(cli->config, root, path, sizeof(path), perr, sizeof(perr)) != 0) {
        int explicit_conf = cli->config != NULL && cli->config[0] != '\0';

        if (!explicit_conf && (cli->check_ca || cli->print_ip)) {
            /* §09.6: diagnostics must work outside systemd and without a config. */
            mn_cfg_defaults(cfg, root);
            snprintf(err, errlen, "%s", perr);
            return 1;
        }
        snprintf(err, errlen, "%s", perr);
        return 2;
    }
    if (mn_cfg_load_ex(cli->config, diagnostic, cli->allow_non_root_owner,
                       cfg, &io_err, err, errlen) != 0)
        return io_err ? 2 : 3;
    return 0;
}

static int acquire_lock(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        mn_log(MN_LOG_ERROR, "lock_open_failed path=%s errno=%d", path, errno);
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            mn_log(MN_LOG_INFO, "lock held path=%s exiting=0", path);
            close(fd);
            return -2;
        }
        mn_log(MN_LOG_ERROR, "lock_failed path=%s errno=%d", path, errno);
        close(fd);
        return -1;
    }
    return fd;
}

static void set_timer(int tfd, int64_t due_ms)
{
    struct itimerspec its;
    int64_t now = mn_now_ms(), delta;
    memset(&its, 0, sizeof(its));
    if (due_ms == INT64_MAX) {
        timerfd_settime(tfd, 0, &its, NULL);
        return;
    }
    delta = due_ms - now;
    if (delta < 1) delta = 1;
    its.it_value.tv_sec = (time_t)(delta / 1000);
    its.it_value.tv_nsec = (long)((delta % 1000) * 1000000L);
    timerfd_settime(tfd, 0, &its, NULL);
}

static int64_t min_due(int64_t a, int64_t b, int64_t c)
{
    int64_t m = a;
    if (b < m) m = b;
    if (c < m) m = c;
    return m;
}

struct local_snap {
    int      valid;
    int      has_v4_iface;
    char     v4_iface_ip[MN_IP_STRLEN];
    int      has_v6;
    char     v6_ip[MN_IP_STRLEN];
    uint64_t v4_if_sig;
};

struct app {
    struct mn_cfg      cfg;
    struct mn_ca       ca;
    struct mn_nl       nl;
    struct mn_provider provs[MN_MAX_PROVIDERS];
    struct mn_memo     memos[MN_MAX_RECORDS];
    struct mn_cycle_ctx ctx;
    struct local_snap  last_local_snap;
    int pending_carrier;
    int have_ca, have_nl, have_provs, lock_fd, allow_nonroot;
};

static void app_capture_local_snap(const struct app *a,
                                   const struct mn_addr_set *addrs,
                                   struct local_snap *out)
{
    struct mn_detect_result r4, r6;
    uint64_t sig = 0;

    memset(out, 0, sizeof(*out));
    memset(&r4, 0, sizeof(r4));
    memset(&r6, 0, sizeof(r6));
    if (mn_detect_ipv4_iface_only(&a->cfg, addrs, &r4, &sig) == MN_OK) {
        out->has_v4_iface = 1;
        (void)mn_strlcpy(out->v4_iface_ip, sizeof(out->v4_iface_ip), r4.ip);
    }
    out->v4_if_sig = sig;
    if (mn_detect_ipv6_quiet(&a->cfg, addrs, &r6) == MN_OK) {
        out->has_v6 = 1;
        (void)mn_strlcpy(out->v6_ip, sizeof(out->v6_ip), r6.ip);
    }
    out->valid = 1;
}

static int local_snap_equal(const struct local_snap *a, const struct local_snap *b)
{
    if (!a->valid || !b->valid)
        return 0;
    return a->has_v4_iface == b->has_v4_iface &&
           a->has_v6 == b->has_v6 &&
           a->v4_if_sig == b->v4_if_sig &&
           strcmp(a->v4_iface_ip, b->v4_iface_ip) == 0 &&
           strcmp(a->v6_ip, b->v6_ip) == 0;
}

static void app_cleanup(struct app *a)
{
    if (a->have_provs) mn_provider_fini_all(a->provs, a->cfg.n_providers);
    if (a->have_nl) mn_nl_close(&a->nl);
    if (a->have_ca) mn_ca_free(&a->ca);
    mn_cfg_wipe_secrets(&a->cfg);
    if (a->lock_fd >= 0) close(a->lock_fd);
    mn_log_close();
}

static int app_cycle_run(struct app *a, const char *reason,
                         struct mn_addr_set *pre_addrs, int *fails)
{
    char err[512];
    struct mn_addr_set *tmp_addrs = NULL;
    struct mn_addr_set *addrs = pre_addrs;
    int ok = 0, fail = 0;
    int64_t dur = 0;
    int rc;

    if (addrs == NULL) {
        tmp_addrs = (struct mn_addr_set *)calloc(1, sizeof(*tmp_addrs));
        if (tmp_addrs == NULL) {
            mn_log(MN_LOG_ERROR, "netlink rescan_failed err=E_CFG detail=\"out of memory\"");
            if (fails) *fails = 1;
            a->ctx.last_errcode = E_CFG;
            a->ctx.last_http_status = -1;
            a->ctx.last_retry_after = -1;
            return -1;
        }
        if (mn_nl_rescan(&a->nl, tmp_addrs, err, sizeof(err)) != 0) {
            free(tmp_addrs);
            mn_log(MN_LOG_ERROR, "netlink rescan_failed err=E_CFG detail=\"%s\"", err);
            if (fails) *fails = 1;
            a->ctx.last_errcode = E_CFG;
            a->ctx.last_http_status = -1;
            a->ctx.last_retry_after = -1;
            return -1;
        }
        addrs = tmp_addrs;
    }
    app_capture_local_snap(a, addrs, &a->last_local_snap);
    a->ctx.addrs = addrs;
    a->ctx.clock_guard = mn_clock_unsynced(mn_wall(), a->cfg.core.clock_guard_epoch);
    a->ctx.last_errcode = MN_OK;
    a->ctx.last_http_status = -1;
    a->ctx.last_retry_after = -1;
    rc = mn_cycle(&a->ctx, reason, &ok, &fail, &dur);
    a->ctx.addrs = NULL;
    free(tmp_addrs);
    maybe_trim_heap();
    if (fails) *fails = fail;
    (void)ok; (void)dur;
    return rc;
}

static int app_cycle(struct app *a, const char *reason, int *fails)
{
    return app_cycle_run(a, reason, NULL, fails);
}

static int do_print_ip(struct app *a)
{
    char err[512];
    char ip4[MN_IP_STRLEN] = "none", ip6[MN_IP_STRLEN] = "none";
    struct mn_addr_set *addrs;
    struct mn_detect_result r4, r6;
    int rc4 = E_NO_IP, rc6 = E_NO_IP;
    memset(&r4, 0, sizeof(r4)); memset(&r6, 0, sizeof(r6));
    if (mn_nl_open(&a->nl, err, sizeof(err)) != 0) {
        fprintf(stderr, "miniddns: netlink: %s\n", err); return 1;
    }
    a->have_nl = 1;
    addrs = (struct mn_addr_set *)calloc(1, sizeof(*addrs));
    if (addrs == NULL) {
        fprintf(stderr, "miniddns: out of memory\n"); return 1;
    }
    if (mn_nl_rescan(&a->nl, addrs, err, sizeof(err)) != 0) {
        free(addrs);
        fprintf(stderr, "miniddns: netlink dump: %s\n", err); return 1;
    }
    rc4 = mn_detect_ipv4(&a->cfg, addrs, a->have_ca ? &a->ca : NULL, &r4, err, sizeof(err));
    rc6 = mn_detect_ipv6(&a->cfg, addrs, &r6, err, sizeof(err));
    free(addrs);
    if (rc4 == MN_OK) snprintf(ip4, sizeof(ip4), "%s", r4.ip);
    if (rc6 == MN_OK) snprintf(ip6, sizeof(ip6), "%s", r6.ip);
    printf("ipv4=%s ipv6=%s\n", ip4, ip6);
    return (rc4 == MN_OK || rc6 == MN_OK) ? 0 : 1;
}

#if defined(__GNUC__)
__attribute__((noinline))
#endif
static int do_check_ca(struct app *a, int no_config)
{
    char capath[MN_PATH_MAX], err[512], cipher[64];
    char hosts[16][128], urlbuf[1024], host[128], path[512];
    int n_hosts = 0, port, i, failures = 0;
    char *p;
    if (mn_resolve_ca_path(&a->cfg, capath, sizeof(capath), err, sizeof(err)) != 0) {
        printf("check-ca: FAIL err=E_CA_LOAD detail=\"%s\"\n", err);
        return 1;
    }
    if (mn_ca_init(&a->ca, capath, a->allow_nonroot, err, sizeof(err)) != 0) {
        printf("check-ca: FAIL err=E_CA_LOAD path=%s detail=\"%s\"\n", capath, err);
        return 1;
    }
    a->have_ca = 1;
    if (no_config) mn_log(MN_LOG_WARN, "no_config hint=using_default_endpoints");
    {
        size_t n = 0;
        char earliest[16] = "(unknown)";
        mn_ca_current(&a->ca, &n);
        if (a->ca.info.earliest_valid)
            mn_ca_format_date(a->ca.info.earliest_days, earliest, sizeof(earliest));
        printf("check-ca: ca path=%s anchors=%zu earliest_notAfter=%s\n",
               capath, n, earliest);
    }
    snprintf(hosts[n_hosts++], 128, "%s", MN_CF_API_HOST);
    snprintf(urlbuf, sizeof(urlbuf), "%s", a->cfg.detect.ipv4_echo_url);
    p = urlbuf;
    while (*p) {
        char *comma = strchr(p, ',');
        int seen = 0;
        if (comma) *comma = '\0';
        if (mn_parse_https_url(mn_trim(p), host, sizeof(host), &port, path, sizeof(path),
                               err, sizeof(err)) == 0) {
            for (i = 0; i < n_hosts; i++) if (!strcasecmp(hosts[i], host)) seen = 1;
            if (!seen && n_hosts < 16) snprintf(hosts[n_hosts++], 128, "%s", host);
        }
        if (!comma) break;
        p = comma + 1;
    }
    for (i = 0; i < n_hosts; i++) {
        int ec = 0, tls_version = 0;
        cipher[0] = '\0';
        if (mn_tls_handshake(&a->cfg, &a->ca, hosts[i], 443, cipher, sizeof(cipher),
                             &tls_version, &ec, err, sizeof(err)) == 0) {
            printf("check-ca: OK tls=%s cipher=%s host=%s\n",
                   mn_tls_version_name(tls_version),
                   cipher[0] ? cipher : "unknown", hosts[i]);
        } else {
            printf("check-ca: FAIL host=%s err=%s detail=\"%s\"\n", hosts[i], mn_err_name(ec), err);
            failures++;
        }
    }
    return failures ? 1 : 0;
}

static void schedule_next(struct app *a, int fail, int64_t now,
                          size_t *backoff_idx, int64_t *retry_due,
                          int *retry_active)
{
    if (a->ctx.clock_guard) {
        /* §05.6: fixed 30 s, no backoff consumption, no writes. */
        *retry_due = now + 30000;
        *retry_active = 1;
        mn_log(MN_LOG_INFO, "retry scheduled delay_ms=30000 reason=clock");
        return;
    }
    if (fail > 0) {
        int status = a->ctx.last_http_status;
        int ra = a->ctx.last_retry_after;
        int ec = a->ctx.last_errcode;
        int64_t delay;

        if (status < 0 || ra < 0) {
            int s2, r2;
            mn_http_last_meta(&s2, &r2);
            if (status < 0) status = s2;
            if (ra < 0) ra = r2;
        }
        /* Use the current backoff step, then advance for the next failure. */
        delay = mn_backoff_take(a->cfg.core.retry_backoff,
                                a->cfg.core.n_backoff, backoff_idx,
                                a->cfg.core.interval_fallback, ec, status, ra);
        *retry_due = now + delay;
        *retry_active = 1;
        mn_log(MN_LOG_INFO, "retry scheduled delay_ms=%lld status=%d retry_after=%d",
               (long long)delay, status, ra);
        return;
    }
    *backoff_idx = 0;
    *retry_active = 0;
    *retry_due = INT64_MAX;
}

static int do_daemon(struct app *a, int once, int dry_run)
{
    char err[512];
    sigset_t mask;
    int sigfd = -1, tfd = -1;
    struct pollfd fds[3];
    struct mn_debounce deb;
    size_t backoff_idx = 0;
    int64_t fallback_due = INT64_MAX, retry_due = INT64_MAX, due;
    int retry_active = 0, rc = 0, fail = 0;
    int exit_code = 0;

    (void)dry_run;
    memset(&deb, 0, sizeof(deb));
    if (mn_nl_open(&a->nl, err, sizeof(err)) != 0) {
        mn_log(MN_LOG_ERROR, "netlink_open_failed err=E_CFG detail=\"%s\"", err);
        return 1;
    }
    a->have_nl = 1;
    /* mn_nl_open() already performed initial dump and logged initial_addrs=N. */

    if (once) {
        rc = app_cycle(a, "boot", &fail);
        if (rc < 0) return 1;
        return fail > 0 ? 1 : 0;
    }

    /* §05.1: install signals before the boot cycle so startup is not
       terminated by the default SIGTERM/SIGINT actions. */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);   /* drained and ignored, never exits */
    if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0) {
        mn_log(MN_LOG_ERROR, "sigprocmask_failed errno=%d", errno);
        return 1;
    }
    sigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (sigfd < 0 || tfd < 0) {
        mn_log(MN_LOG_ERROR, "event_setup_failed errno=%d", errno);
        if (sigfd >= 0) close(sigfd);
        if (tfd >= 0) close(tfd);
        return 1;
    }
    if (a->cfg.core.interval_fallback > 0)
        fallback_due = mn_now_ms() + (int64_t)a->cfg.core.interval_fallback * 1000;

    rc = app_cycle(a, "boot", &fail);
    if (rc < 0) {
        close(sigfd);
        close(tfd);
        return 1;
    }
    schedule_next(a, fail, mn_now_ms(), &backoff_idx, &retry_due, &retry_active);

    fds[0].fd = mn_nl_fd(&a->nl); fds[0].events = POLLIN;
    fds[1].fd = tfd;             fds[1].events = POLLIN;
    fds[2].fd = sigfd;           fds[2].events = POLLIN;

    for (;;) {
        int64_t now;
        fds[0].revents = fds[1].revents = fds[2].revents = 0;
        now = mn_now_ms();
        due = min_due(deb.active ? deb.deadline_ms : INT64_MAX,
                      retry_active ? retry_due : INT64_MAX,
                      fallback_due);
        set_timer(tfd, due);
        rc = ppoll(fds, 3, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR) continue;
            mn_log(MN_LOG_ERROR, "ppoll_failed errno=%d", errno);
            exit_code = 1;
            break;
        }
        if (rc == 0) continue;

        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            mn_log(MN_LOG_ERROR, "netlink_poll_failed revents=0x%x", fds[0].revents);
            exit_code = 1;
            break;
        }
        if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            mn_log(MN_LOG_ERROR, "timerfd_poll_failed revents=0x%x", fds[1].revents);
            exit_code = 1;
            break;
        }
        if (fds[2].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            mn_log(MN_LOG_ERROR, "signalfd_poll_failed revents=0x%x", fds[2].revents);
            exit_code = 1;
            break;
        }

        if (fds[2].revents & POLLIN) {
            struct signalfd_siginfo si;
            ssize_t n;

            do {
                n = read(sigfd, &si, sizeof(si));
            } while (n < 0 && errno == EINTR);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                mn_log(MN_LOG_ERROR, "signalfd_read_failed errno=%d", errno);
                exit_code = 1;
                break;
            }
            if (n != (ssize_t)sizeof(si)) {
                mn_log(MN_LOG_ERROR, "signalfd_short_read bytes=%ld", (long)n);
                exit_code = 1;
                break;
            }
            if (si.ssi_signo == SIGHUP) {
                /* §05.1 only defines SIGTERM/SIGINT as exit signals. */
                mn_log(MN_LOG_WARN, "sighup_ignored hint=no_reload");
                continue;
            }
            mn_log(MN_LOG_INFO, "stop signal=%d exiting=0", (int)si.ssi_signo);
            break;
        }

        if (fds[0].revents & POLLIN) {
            int overflow = 0, carrier = 0, drained;

            drained = mn_nl_drain_filtered(&a->nl, &a->cfg.detect, &overflow,
                                           &carrier, err, sizeof(err));
            if (drained < 0) {
                mn_log(MN_LOG_ERROR, "netlink_drain_failed err=E_CFG detail=\"%s\"", err);
                exit_code = 1;
                break;
            }
            if (overflow) {
                mn_debounce_clear(&deb);
                a->pending_carrier = 0;
                rc = app_cycle(a, "event", &fail);
            } else if (drained > 0) {
                if (carrier) a->pending_carrier = 1;
                mn_debounce_event(&deb, mn_now_ms(), a->cfg.core.debounce_ms,
                                  10 * a->cfg.core.debounce_ms);
                continue;
            } else {
                continue;
            }
        }
        if (fds[1].revents & POLLIN) {
            uint64_t expiries;
            ssize_t n;
            const char *reason = NULL;
            struct mn_addr_set *ev_addrs = NULL;

            do {
                n = read(tfd, &expiries, sizeof(expiries));
            } while (n < 0 && errno == EINTR);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                mn_log(MN_LOG_ERROR, "timerfd_read_failed errno=%d", errno);
                exit_code = 1;
                break;
            }
            now = mn_now_ms();
            if (mn_debounce_due(&deb, now)) {
                int had_carrier = a->pending_carrier;
                a->pending_carrier = 0;
                mn_debounce_clear(&deb);
                reason = "event";
                /* v1.3 REQ-07 layer 2: skip spurious event cycles when no local
                   effective address changed and no carrier flip occurred; keep
                   backoff/retry/fallback scheduling untouched. */
                if (!had_carrier && a->last_local_snap.valid) {
                    ev_addrs = (struct mn_addr_set *)calloc(1, sizeof(*ev_addrs));
                    if (ev_addrs != NULL &&
                        mn_nl_rescan(&a->nl, ev_addrs, err, sizeof(err)) == 0) {
                        struct local_snap cur_snap;
                        app_capture_local_snap(a, ev_addrs, &cur_snap);
                        if (local_snap_equal(&a->last_local_snap, &cur_snap)) {
                            free(ev_addrs);
                            mn_log(MN_LOG_DEBUG, "cycle skip reason=no_local_addr_change");
                            continue;
                        }
                    } else {
                        free(ev_addrs);
                        ev_addrs = NULL;
                    }
                }
            } else if (retry_active && now >= retry_due) {
                reason = "retry";
                retry_active = 0;
            } else if (now >= fallback_due) {
                reason = "timer";
                if (deb.active) mn_debounce_clear(&deb);   /* §05.3 */
                a->pending_carrier = 0;
                fallback_due = (a->cfg.core.interval_fallback > 0)
                             ? now + (int64_t)a->cfg.core.interval_fallback * 1000 : INT64_MAX;
            }
            if (!reason) {
                free(ev_addrs);
                continue;
            }
            rc = app_cycle_run(a, reason, ev_addrs, &fail);
            free(ev_addrs);
        }

        if (rc < 0) rc = 1;
        schedule_next(a, fail, mn_now_ms(), &backoff_idx, &retry_due, &retry_active);
    }
    close(sigfd);
    close(tfd);
    return exit_code;
}

int main(int argc, char **argv)
{
    struct cli cli;
    struct app *a = NULL;
    char err[512];
    int rc = 1, diagnostic, mode;

#if defined(__GLIBC__)
    /* v1.3 REQ-06: disable dynamic mmap threshold inflation so transient >=16 KiB
       buffers (TLS, netlink, CA arena) unmap cleanly back to the OS on free(). */
    (void)mallopt(M_MMAP_THRESHOLD, 16 * 1024);
    (void)mallopt(M_TRIM_THRESHOLD, 32 * 1024);
#endif

    if (parse_cli(argc, argv, &cli) != 0) return 2;
    if (cli.version) { version_info(); return 0; }
    if (cli.help) { usage(stdout); return 0; }

    /* v1.3 REQ-04: allocate struct app on heap to keep main() stack RSS <= 32 KiB. */
    a = (struct app *)calloc(1, sizeof(*a));
    if (a == NULL) {
        fprintf(stderr, "miniddns: out of memory\n");
        return 1;
    }
    a->lock_fd = -1;
    a->allow_nonroot = cli.allow_non_root_owner;

    /* log with defaults first so load failures are visible */
    mn_log_init(MN_LOG_INFO, MN_LOG_JOURNALD, NULL);
    if (cli.allow_non_root_owner)
        mn_log(MN_LOG_WARN, "allow_non_root_owner=1 hint=test_only");

    diagnostic = cli.print_ip || cli.check_config || cli.check_ca || cli.dry_run;
    mode = load_config(&cli, diagnostic, &a->cfg, err, sizeof(err));
    if (mode == 2) {
        fprintf(stderr, "miniddns: E_CFG %s\n", err);
        mn_log(MN_LOG_ERROR, "config_failed err=E_CFG detail=\"%s\"", err);
        rc = 2;
        goto out;
    }
    if (mode == 3) {
        fprintf(stderr, "miniddns: E_CFG %s\n", err);
        mn_log(MN_LOG_ERROR, "config_failed err=E_CFG detail=\"%s\"", err);
        /* §11: --check-config validation failure = 1; --once config error = 2;
           daemon startup failure = 1 (§05.1). */
        rc = cli.check_config ? 1
           : (cli.once || cli.dry_run || cli.print_ip || cli.check_ca) ? 2
           : 1;
        goto out;
    }
    a->cfg.allow_non_root_owner = cli.allow_non_root_owner;
    mn_log_init(a->cfg.core.log_level, a->cfg.core.log_target,
                a->cfg.core.log_target == MN_LOG_FILE ? a->cfg.core.log_file : NULL);
    if (cli.log_level) {
        int lv;
        mn_log_level_parse(cli.log_level, &lv);
        mn_log_set_level(lv);                     /* §11 rule 3: CLI > config > default */
    }
    mn_log(MN_LOG_INFO, "start version=%s instance=%s config=%s",
           MN_VERSION, a->cfg.core.instance,
           a->cfg.conf_path[0] ? a->cfg.conf_path : "(none)");
    if (mode == 1)
        mn_log(MN_LOG_WARN, "no_config hint=using_defaults");

    if (cli.check_config) {
        mn_cfg_print(&a->cfg);
        rc = 0;
        goto out;
    }

    /* --check-ca owns its CA lifecycle (it must also work without a config file). */
    if (cli.check_ca) {
        rc = do_check_ca(a, mode == 1);
        goto out;
    }

    /* CA loading is required for every TLS-using path; --print-ip degrades to iface. */
    {
        char capath[MN_PATH_MAX];
        if (mn_resolve_ca_path(&a->cfg, capath, sizeof(capath), err, sizeof(err)) == 0) {
            if (mn_ca_init(&a->ca, capath, a->allow_nonroot, err, sizeof(err)) == 0) {
                a->have_ca = 1;
            } else {
                mn_log(MN_LOG_ERROR, "ca_load_failed err=E_CA_LOAD detail=\"%s\"", err);
                if (!cli.print_ip) { rc = 1; goto out; }
            }
        } else if (!cli.print_ip) {
            mn_log(MN_LOG_ERROR, "ca_path_failed err=E_CA_LOAD detail=\"%s\"", err);
            rc = 1;
            goto out;
        }
    }

    if (cli.print_ip) {
        if (!a->have_ca && (a->cfg.detect.ipv4_mode == MN_IP4_EXTERNAL ||
                            a->cfg.detect.ipv4_mode == MN_IP4_AUTO)) {
            mn_log(MN_LOG_WARN, "ca_unavailable external_disabled=1");
            a->cfg.detect.ipv4_mode = MN_IP4_IFACE;
        }
        rc = do_print_ip(a);
        goto out;
    }

    /* --once and the daemon take flock; --dry-run does not (§11). */
    if (!cli.dry_run) {
        int fd = acquire_lock(a->cfg.core.lock_file);
        if (fd == -2) { rc = 0; goto out; }
        if (fd < 0) { rc = 1; goto out; }
        a->lock_fd = fd;
    }

    if (mn_provider_init_all(&a->cfg, a->provs, MN_MAX_PROVIDERS, cli.dry_run,
                             err, sizeof(err)) != 0) {
        mn_log(MN_LOG_ERROR, "provider_init_failed err=E_CFG detail=\"%s\"", err);
        rc = 1;
        goto out;
    }
    a->have_provs = 1;
    a->ctx.cfg = &a->cfg;
    a->ctx.provs = a->provs;
    a->ctx.n_provs = a->cfg.n_providers;
    a->ctx.ca = &a->ca;
    a->ctx.memos = a->memos;
    a->ctx.dry_run = cli.dry_run;

    rc = do_daemon(a, cli.once, cli.dry_run);
out:
    app_cleanup(a);
    free(a);
    return rc;
}

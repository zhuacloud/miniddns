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
#ifdef MN_STATIC_BUILD
    printf("build=static\n");
#else
    printf("build=dynamic (use `make static` for the static artifact)\n");
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
    char *probe;
    size_t plen;
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
    /* Separate "unreadable" (exit 2) from "invalid" (check-config exit 1). */
    probe = (char *)malloc(MN_LIMIT_CONF_FILE + 1);
    if (!probe) { snprintf(err, errlen, "out of memory"); return 2; }
    if (mn_checked_read(path, MN_FILE_CONF, probe, MN_LIMIT_CONF_FILE + 1, &plen,
                        cli->allow_non_root_owner, perr, sizeof(perr)) != 0) {
        free(probe);
        snprintf(err, errlen, "%s", perr);
        return 2;
    }
    free(probe);
    if (mn_cfg_load(cli->config, diagnostic, cli->allow_non_root_owner, cfg, err, errlen) != 0)
        return 3;
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

struct app {
    struct mn_cfg      cfg;
    struct mn_ca       ca;
    struct mn_nl       nl;
    struct mn_addr_set addrs;
    struct mn_provider provs[MN_MAX_PROVIDERS];
    struct mn_memo     memos[MN_MAX_RECORDS];
    struct mn_cycle_ctx ctx;
    int have_ca, have_nl, have_provs, lock_fd, allow_nonroot;
};

static void app_cleanup(struct app *a)
{
    if (a->have_provs) mn_provider_fini_all(a->provs, a->cfg.n_providers);
    if (a->have_nl) mn_nl_close(&a->nl);
    if (a->have_ca) mn_ca_free(&a->ca);
    mn_cfg_wipe_secrets(&a->cfg);
    if (a->lock_fd >= 0) close(a->lock_fd);
    mn_log_close();
}

static int app_cycle(struct app *a, const char *reason, int *fails)
{
    char err[512];
    int ok = 0, fail = 0;
    int64_t dur = 0;
    int rc;
    if (mn_nl_rescan(&a->nl, &a->addrs, err, sizeof(err)) != 0) {
        mn_log(MN_LOG_ERROR, "netlink rescan_failed err=E_CFG detail=\"%s\"", err);
        if (fails) *fails = 1;
        a->ctx.last_errcode = E_CFG;
        a->ctx.last_http_status = -1;
        a->ctx.last_retry_after = -1;
        return -1;
    }
    a->ctx.addrs = &a->addrs;
    a->ctx.clock_guard = mn_clock_unsynced(mn_wall(), a->cfg.core.clock_guard_epoch);
    a->ctx.last_errcode = MN_OK;
    a->ctx.last_http_status = -1;
    a->ctx.last_retry_after = -1;
    rc = mn_cycle(&a->ctx, reason, &ok, &fail, &dur);
    if (fails) *fails = fail;
    (void)ok; (void)dur;
    return rc;
}

static int do_print_ip(struct app *a)
{
    char err[512];
    char ip4[MN_IP_STRLEN] = "none", ip6[MN_IP_STRLEN] = "none";
    struct mn_detect_result r4, r6;
    int rc4 = E_NO_IP, rc6 = E_NO_IP;
    memset(&r4, 0, sizeof(r4)); memset(&r6, 0, sizeof(r6));
    if (mn_nl_open(&a->nl, err, sizeof(err)) != 0) {
        fprintf(stderr, "miniddns: netlink: %s\n", err); return 1;
    }
    a->have_nl = 1;
    if (mn_nl_rescan(&a->nl, &a->addrs, err, sizeof(err)) != 0) {
        fprintf(stderr, "miniddns: netlink dump: %s\n", err); return 1;
    }
    rc4 = mn_detect_ipv4(&a->cfg, &a->addrs, a->have_ca ? &a->ca : NULL, &r4, err, sizeof(err));
    rc6 = mn_detect_ipv6(&a->cfg, &a->addrs, &r6, err, sizeof(err));
    if (rc4 == MN_OK) snprintf(ip4, sizeof(ip4), "%s", r4.ip);
    if (rc6 == MN_OK) snprintf(ip6, sizeof(ip6), "%s", r6.ip);
    printf("ipv4=%s ipv6=%s\n", ip4, ip6);
    return (rc4 == MN_OK || rc6 == MN_OK) ? 0 : 1;
}

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
    if (mn_nl_rescan(&a->nl, &a->addrs, err, sizeof(err)) != 0) {
        mn_log(MN_LOG_ERROR, "netlink_dump_failed err=E_CFG detail=\"%s\"", err);
        return 1;
    }
    /* mn_nl_open() already logs `netlink subscribed ... initial_addrs=N`. */

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
            int overflow = 0, drained;

            drained = mn_nl_drain(&a->nl, &overflow, err, sizeof(err));
            if (drained < 0) {
                mn_log(MN_LOG_ERROR, "netlink_drain_failed err=E_CFG detail=\"%s\"", err);
                exit_code = 1;
                break;
            }
            if (overflow) {
                mn_debounce_clear(&deb);
                rc = app_cycle(a, "event", &fail);
            } else if (drained > 0) {
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
            if (mn_debounce_due(&deb, now)) { reason = "event"; mn_debounce_clear(&deb); }
            else if (retry_active && now >= retry_due) { reason = "retry"; retry_active = 0; }
            else if (now >= fallback_due) {
                reason = "timer";
                if (deb.active) mn_debounce_clear(&deb);   /* §05.3 */
                fallback_due = (a->cfg.core.interval_fallback > 0)
                             ? now + (int64_t)a->cfg.core.interval_fallback * 1000 : INT64_MAX;
            }
            if (!reason) continue;
            rc = app_cycle(a, reason, &fail);
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
    struct app a;
    char err[512];
    int rc, diagnostic, mode;

    memset(&a, 0, sizeof(a));
    a.lock_fd = -1;
    a.allow_nonroot = 0;
    if (parse_cli(argc, argv, &cli) != 0) return 2;
    if (cli.version) { version_info(); return 0; }
    if (cli.help) { usage(stdout); return 0; }
    a.allow_nonroot = cli.allow_non_root_owner;

    /* log with defaults first so load failures are visible */
    mn_log_init(MN_LOG_INFO, MN_LOG_JOURNALD, NULL);
    if (cli.allow_non_root_owner)
        mn_log(MN_LOG_WARN, "allow_non_root_owner=1 hint=test_only");

    diagnostic = cli.print_ip || cli.check_config || cli.check_ca || cli.dry_run;
    mode = load_config(&cli, diagnostic, &a.cfg, err, sizeof(err));
    if (mode == 2) {
        fprintf(stderr, "miniddns: E_CFG %s\n", err);
        mn_log(MN_LOG_ERROR, "config_failed err=E_CFG detail=\"%s\"", err);
        return 2;
    }
    if (mode == 3) {
        fprintf(stderr, "miniddns: E_CFG %s\n", err);
        mn_log(MN_LOG_ERROR, "config_failed err=E_CFG detail=\"%s\"", err);
        /* §11: --check-config validation failure = 1; --once config error = 2;
           daemon startup failure = 1 (§05.1). */
        return cli.check_config ? 1
             : (cli.once || cli.dry_run || cli.print_ip || cli.check_ca) ? 2
             : 1;
    }
    a.cfg.allow_non_root_owner = cli.allow_non_root_owner;
    mn_log_init(a.cfg.core.log_level, a.cfg.core.log_target,
                a.cfg.core.log_target == MN_LOG_FILE ? a.cfg.core.log_file : NULL);
    if (cli.log_level) {
        int lv;
        mn_log_level_parse(cli.log_level, &lv);
        mn_log_set_level(lv);                     /* §11 rule 3: CLI > config > default */
    }
    mn_log(MN_LOG_INFO, "start version=%s instance=%s config=%s",
           MN_VERSION, a.cfg.core.instance,
           a.cfg.conf_path[0] ? a.cfg.conf_path : "(none)");
    if (mode == 1)
        mn_log(MN_LOG_WARN, "no_config hint=using_defaults");

    if (cli.check_config) {
        mn_cfg_print(&a.cfg);
        return 0;
    }

    /* --check-ca owns its CA lifecycle (it must also work without a config file). */
    if (cli.check_ca) {
        rc = do_check_ca(&a, mode == 1);
        app_cleanup(&a);
        return rc;
    }

    /* CA loading is required for every TLS-using path; --print-ip degrades to iface. */
    {
        char capath[MN_PATH_MAX];
        if (mn_resolve_ca_path(&a.cfg, capath, sizeof(capath), err, sizeof(err)) == 0) {
            if (mn_ca_init(&a.ca, capath, a.allow_nonroot, err, sizeof(err)) == 0) {
                a.have_ca = 1;
            } else {
                mn_log(MN_LOG_ERROR, "ca_load_failed err=E_CA_LOAD detail=\"%s\"", err);
                if (!cli.print_ip) return 1;
            }
        } else if (!cli.print_ip) {
            mn_log(MN_LOG_ERROR, "ca_path_failed err=E_CA_LOAD detail=\"%s\"", err);
            return 1;
        }
    }

    if (cli.print_ip) {
        if (!a.have_ca && (a.cfg.detect.ipv4_mode == MN_IP4_EXTERNAL ||
                           a.cfg.detect.ipv4_mode == MN_IP4_AUTO)) {
            mn_log(MN_LOG_WARN, "ca_unavailable external_disabled=1");
            a.cfg.detect.ipv4_mode = MN_IP4_IFACE;
        }
        rc = do_print_ip(&a);
        app_cleanup(&a);
        return rc;
    }

    /* --once and the daemon take flock; --dry-run does not (§11). */
    if (!cli.dry_run) {
        int fd = acquire_lock(a.cfg.core.lock_file);
        if (fd == -2) { app_cleanup(&a); return 0; }
        if (fd < 0) { app_cleanup(&a); return 1; }
        a.lock_fd = fd;
    }

    if (mn_provider_init_all(&a.cfg, a.provs, MN_MAX_PROVIDERS, cli.dry_run,
                             err, sizeof(err)) != 0) {
        mn_log(MN_LOG_ERROR, "provider_init_failed err=E_CFG detail=\"%s\"", err);
        app_cleanup(&a);
        return 1;
    }
    a.have_provs = 1;
    a.ctx.cfg = &a.cfg;
    a.ctx.provs = a.provs;
    a.ctx.n_provs = a.cfg.n_providers;
    a.ctx.ca = &a.ca;
    a.ctx.memos = a.memos;
    a.ctx.dry_run = cli.dry_run;

    rc = do_daemon(&a, cli.once, cli.dry_run);
    app_cleanup(&a);
    return rc;
}

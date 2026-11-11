/* provider.c — vtable registry, credential loading and generic diff/apply cycle */
#include "provider.h"
#include "detect.h"
#include "log.h"
#include "tls_http.h"
#include "util.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

extern const struct mn_provider_ops mn_cloudflare_ops;

#define MN_PROV_ESC_CAP     (MN_LOG_FIELD_MAX + 1)
#define MN_PROV_DETAIL_CAP  MN_LOG_LINE_MAX
#define MN_PROV_LOCAL_ERR   512

static int prov_lower(int c)
{
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static int prov_ci_equal(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        if (prov_lower((unsigned char)*a) != prov_lower((unsigned char)*b)) {
            return 0;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

static const char *prov_escape(char *buf, size_t cap, const char *value)
{
    int r;

    if (buf == NULL || cap == 0) {
        return "-";
    }
    buf[0] = '\0';
    if (value == NULL) {
        return buf;
    }
    r = mn_log_escape(buf, cap, value);
    if (r < 0) {
        buf[0] = '\0';
    }
    buf[cap - 1] = '\0';
    return buf;
}

static void prov_single_line(char *out, size_t cap, const char *in)
{
    size_t i = 0;

    if (out == NULL || cap == 0) {
        return;
    }
    out[0] = '\0';
    if (in == NULL) {
        return;
    }
    for (; in[i] != '\0' && i + 1u < cap; ++i) {
        unsigned char c = (unsigned char)in[i];
        out[i] = (c < 0x20u || c == 0x7fu) ? ' ' : (char)c;
    }
    out[i] = '\0';
}

static void prov_set_err(char *err, size_t errlen, const char *fmt, ...)
{
    static const char fallback[] = "reason=err_truncated";
    va_list ap;
    int n;

    if (err == NULL || errlen == 0) {
        return;
    }
    if (fmt == NULL) {
        fmt = fallback;
    }
    err[0] = '\0';
    va_start(ap, fmt);
    n = vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= errlen) {
        if (errlen < sizeof(fallback)) {
            memcpy(err, fallback, errlen - 1u);
            err[errlen - 1u] = '\0';
        } else {
            memcpy(err, fallback, sizeof(fallback));
        }
    }
}

static void prov_sanitize_err(char *err, size_t errlen)
{
    char tmp[MN_PROV_DETAIL_CAP];
    size_t n;

    if (err == NULL || errlen == 0) {
        return;
    }
    prov_single_line(tmp, sizeof(tmp), err);
    n = strlen(tmp);
    if (n >= errlen) {
        n = errlen - 1u;
    }
    memcpy(err, tmp, n);
    err[n] = '\0';
}

static const char *prov_fold_key(char *buf, size_t cap, size_t idx, const char *tag)
{
    int n;

    if (buf == NULL || cap == 0) {
        return "record";
    }
    n = snprintf(buf, cap, "record:%zu:%s", idx, tag != NULL ? tag : "record");
    if (n < 0 || (size_t)n >= cap) {
        return "record";
    }
    return buf;
}

static const char *prov_record_type(int family)
{
    if (family == AF_INET) {
        return "A";
    }
    if (family == AF_INET6) {
        return "AAAA";
    }
    return "unknown";
}

static void prov_log_error(const struct mn_record_cfg *rec, int rc, const char *detail)
{
    char name[MN_PROV_ESC_CAP];
    char errname[MN_PROV_ESC_CAP];
    char one_line[MN_PROV_DETAIL_CAP];
    const char *ename = mn_err_name(rc);

    prov_escape(name, sizeof(name), rec != NULL ? rec->name : "");
    prov_escape(errname, sizeof(errname), ename != NULL ? ename : "E_CFG");
    prov_single_line(one_line, sizeof(one_line), detail);
    if (one_line[0] != '\0') {
        mn_log(MN_LOG_ERROR, "record name=%s type=%s action=error err=%s %s",
               name, prov_record_type(rec != NULL ? rec->family : 0),
               errname, one_line);
    } else {
        mn_log(MN_LOG_ERROR, "record name=%s type=%s action=error err=%s",
               name, prov_record_type(rec != NULL ? rec->family : 0), errname);
    }
}

static void prov_cycle_failure(struct mn_cycle_ctx *ctx, int rc, int errcode)
{
    int status = -1;
    int retry_after = -1;
    int code = errcode < 0 ? errcode : rc;

    if (code >= 0) {
        code = E_PARSE;
    }
    ctx->last_errcode = code;
    mn_http_last_meta(&status, &retry_after);
    ctx->last_http_status = status;
    ctx->last_retry_after = retry_after;
}

static int64_t prov_elapsed_ms(int64_t start)
{
    int64_t now = mn_now_ms();

    return now >= start ? now - start : 0;
}

static const char *prov_next_reason(const char *reason)
{
    if (reason == NULL) {
        return "event";
    }
    if (strcmp(reason, "boot") == 0 || strcmp(reason, "event") == 0) {
        return "event";
    }
    if (strcmp(reason, "timer") == 0) {
        return "timer";
    }
    if (strcmp(reason, "retry") == 0) {
        return "retry";
    }
    if (strcmp(reason, "once") == 0 || strcmp(reason, "dry-run") == 0 ||
        strcmp(reason, "dry_run") == 0) {
        return "exit";
    }
    if (strcmp(reason, "clock") == 0) {
        return "clock";
    }
    return "event";
}

static void prov_log_cycle_end(int ok, int fail, int64_t duration, const char *next)
{
    char next_esc[MN_PROV_ESC_CAP];

    mn_log(MN_LOG_INFO, "cycle end ok=%d fail=%d duration_ms=%" PRId64 " next=%s",
           ok, fail, duration, prov_escape(next_esc, sizeof(next_esc), next));
}

const struct mn_provider_ops *mn_provider_lookup(const char *kind)
{
    if (prov_ci_equal(kind, "cloudflare")) {
        return &mn_cloudflare_ops;
    }
    return NULL;
}

void mn_provider_fini_all(struct mn_provider *provs, size_t n)
{
    size_t i;

    if (provs == NULL) {
        return;
    }
    for (i = 0; i < n; ++i) {
        if (provs[i].ops != NULL && provs[i].ops->fini != NULL) {
            provs[i].ops->fini(&provs[i]);
        }
        mn_secure_zero(provs[i].token, sizeof(provs[i].token));
        provs[i].ca = NULL;
    }
}

struct mn_provider *mn_provider_find(struct mn_provider *provs, size_t n,
                                     const char *id)
{
    size_t i;

    if (provs == NULL || id == NULL) {
        return NULL;
    }
    for (i = 0; i < n; ++i) {
        if (provs[i].id != NULL && strcmp(provs[i].id, id) == 0) {
            return &provs[i];
        }
    }
    return NULL;
}

static int prov_wrapper_precheck(struct mn_provider *p, unsigned cap,
                                 const char *cap_name, char *ebuf, size_t ecap,
                                 int *errcode)
{
    char kind[MN_PROV_ESC_CAP];
    char cap_esc[MN_PROV_ESC_CAP];

    if (p == NULL || p->ops == NULL) {
        prov_set_err(ebuf, ecap, "reason=provider_unavailable");
        if (errcode != NULL) {
            *errcode = E_CFG;
        }
        return E_CFG;
    }
    if ((p->ops->caps & cap) == 0u) {
        prov_set_err(ebuf, ecap, "reason=unsupported_cap cap=%s provider=%s",
                     prov_escape(cap_esc, sizeof(cap_esc), cap_name),
                     prov_escape(kind, sizeof(kind), p->ops->kind));
        if (errcode != NULL) {
            *errcode = E_CFG;
        }
        return E_CFG;
    }
    return MN_OK;
}

int mn_provider_discover(struct mn_provider *p, const struct mn_record_cfg *rc,
                         struct mn_remote *out, int *errcode, char *err, size_t errlen)
{
    char dummy[1] = { 0 };
    char *ebuf = (err != NULL && errlen > 0) ? err : dummy;
    size_t ecap = (err != NULL && errlen > 0) ? errlen : sizeof(dummy);
    char errname[MN_PROV_ESC_CAP];
    int status;

    if (errcode != NULL) {
        *errcode = MN_OK;
    }
    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
    if (out == NULL || rc == NULL) {
        prov_set_err(ebuf, ecap, "reason=invalid_argument");
        if (errcode != NULL) {
            *errcode = E_CFG;
        }
        return E_CFG;
    }
    memset(out, 0, sizeof(*out));
    status = prov_wrapper_precheck(p, MN_CAP_DISCOVER, "discover", ebuf, ecap, errcode);
    if (status != MN_OK) {
        return status;
    }
    if (p->ops->discover == NULL) {
        prov_set_err(ebuf, ecap, "reason=provider_unavailable");
        if (errcode != NULL) {
            *errcode = E_CFG;
        }
        return E_CFG;
    }
    status = p->ops->discover(p, rc, out, ebuf, ecap);
    prov_sanitize_err(ebuf, ecap);
    if (status != MN_OK) {
        if (status > 0) {
            status = E_PARSE;
        }
        if (errcode != NULL) {
            *errcode = status;
        }
        if (ebuf[0] == '\0') {
            prov_set_err(ebuf, ecap, "reason=operation_failed err=%s",
                         prov_escape(errname, sizeof(errname), mn_err_name(status)));
        }
        return status;
    }
    if (errcode != NULL) {
        *errcode = MN_OK;
    }
    return MN_OK;
}

int mn_provider_update(struct mn_provider *p, const struct mn_record_cfg *rc,
                       const struct mn_remote *cur, const char *ip,
                       int *errcode, char *err, size_t errlen)
{
    char dummy[1] = { 0 };
    char *ebuf = (err != NULL && errlen > 0) ? err : dummy;
    size_t ecap = (err != NULL && errlen > 0) ? errlen : sizeof(dummy);
    char errname[MN_PROV_ESC_CAP];
    int status;

    (void)cur;
    if (errcode != NULL) {
        *errcode = MN_OK;
    }
    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
    if (rc == NULL || ip == NULL) {
        prov_set_err(ebuf, ecap, "reason=invalid_argument");
        if (errcode != NULL) {
            *errcode = E_CFG;
        }
        return E_CFG;
    }
    status = prov_wrapper_precheck(p, MN_CAP_PATCH_CONTENT, "patch_content",
                                   ebuf, ecap, errcode);
    if (status != MN_OK) {
        return status;
    }
    if (p->ops->update == NULL) {
        prov_set_err(ebuf, ecap, "reason=provider_unavailable");
        if (errcode != NULL) {
            *errcode = E_CFG;
        }
        return E_CFG;
    }
    status = p->ops->update(p, rc, cur, ip, ebuf, ecap);
    prov_sanitize_err(ebuf, ecap);
    if (status != MN_OK) {
        if (status > 0) {
            status = E_PARSE;
        }
        if (errcode != NULL) {
            *errcode = status;
        }
        if (ebuf[0] == '\0') {
            prov_set_err(ebuf, ecap, "reason=operation_failed err=%s",
                         prov_escape(errname, sizeof(errname), mn_err_name(status)));
        }
        return status;
    }
    if (errcode != NULL) {
        *errcode = MN_OK;
    }
    return MN_OK;
}

int mn_provider_create(struct mn_provider *p, const struct mn_record_cfg *rc,
                       const char *ip, struct mn_remote *out,
                       int *errcode, char *err, size_t errlen)
{
    char dummy[1] = { 0 };
    char *ebuf = (err != NULL && errlen > 0) ? err : dummy;
    size_t ecap = (err != NULL && errlen > 0) ? errlen : sizeof(dummy);
    char errname[MN_PROV_ESC_CAP];
    int status;

    if (errcode != NULL) {
        *errcode = MN_OK;
    }
    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
    if (out == NULL || rc == NULL || ip == NULL) {
        prov_set_err(ebuf, ecap, "reason=invalid_argument");
        if (errcode != NULL) {
            *errcode = E_CFG;
        }
        return E_CFG;
    }
    memset(out, 0, sizeof(*out));
    status = prov_wrapper_precheck(p, MN_CAP_CREATE, "create", ebuf, ecap, errcode);
    if (status != MN_OK) {
        return status;
    }
    if (p->ops->create == NULL) {
        prov_set_err(ebuf, ecap, "reason=provider_unavailable");
        if (errcode != NULL) {
            *errcode = E_CFG;
        }
        return E_CFG;
    }
    status = p->ops->create(p, rc, ip, out, ebuf, ecap);
    prov_sanitize_err(ebuf, ecap);
    if (status != MN_OK) {
        if (status > 0) {
            status = E_PARSE;
        }
        if (errcode != NULL) {
            *errcode = status;
        }
        if (ebuf[0] == '\0') {
            prov_set_err(ebuf, ecap, "reason=operation_failed err=%s",
                         prov_escape(errname, sizeof(errname), mn_err_name(status)));
        }
        return status;
    }
    if (errcode != NULL) {
        *errcode = MN_OK;
    }
    return MN_OK;
}

static int prov_resolve_token(struct mn_cfg *cfg, struct mn_provider *p,
                              const struct mn_provider_cfg *pc,
                              int diagnostic, int *skipped,
                              char *err, size_t errlen)
{
    char id[MN_PROV_ESC_CAP];
    char path[MN_PATH_MAX];
    char suberr[MN_PROV_DETAIL_CAP];
    char detail[MN_PROV_DETAIL_CAP];
    char *raw = NULL;
    size_t raw_cap = (size_t)MN_LIMIT_TOKEN_FILE + 1u;
    size_t raw_len = 0;
    size_t i;
    int local_skipped = 0;
    int has_file;
    int has_inline;
    int rc;

    if (skipped == NULL) {
        skipped = &local_skipped;
    }
    *skipped = 0;
    p->token[0] = '\0';
    has_file = pc->token_file[0] != '\0';
    has_inline = pc->has_token_inline != 0;
    prov_escape(id, sizeof(id), pc->id);
    if (has_inline) {
        if (has_file) {
            mn_log(MN_LOG_WARN,
                   "provider id=%s line=%d inline_token=1 token_file_precedence=1",
                   id, pc->line);
        } else {
            mn_log(MN_LOG_WARN, "provider id=%s line=%d inline_token=1",
                   id, pc->line);
        }
    }
    if (has_file) {
        suberr[0] = '\0';
        rc = mn_expand_creds_dir(pc->token_file, path, sizeof(path),
                                 diagnostic, skipped, suberr, sizeof(suberr));
        if (rc < 0) {
            prov_single_line(detail, sizeof(detail), suberr);
            prov_set_err(err, errlen,
                         "reason=token_file_expand provider_id=%s line=%d %s",
                         id, pc->line, detail);
            return E_CFG;
        }
        if (*skipped) {
            mn_log(MN_LOG_WARN,
                   "provider id=%s line=%d token_file_skipped=1 reason=credentials_directory_missing diagnostic=%d",
                   id, pc->line, diagnostic);
        } else {
            raw = (char *)malloc(raw_cap);
            if (raw == NULL) {
                prov_set_err(err, errlen,
                             "reason=out_of_memory provider_id=%s line=%d",
                             id, pc->line);
                return E_CFG;
            }
            memset(raw, 0, raw_cap);
            suberr[0] = '\0';
            rc = mn_checked_read(path, MN_FILE_TOKEN, raw, raw_cap, &raw_len,
                                 cfg->allow_non_root_owner, suberr, sizeof(suberr));
            if (rc < 0) {
                prov_single_line(detail, sizeof(detail), suberr);
                prov_set_err(err, errlen,
                             "reason=token_file_read provider_id=%s line=%d %s",
                             id, pc->line, detail);
                mn_secure_zero(raw, raw_cap);
                free(raw);
                return E_CFG;
            }
            if (raw_len >= raw_cap) {
                prov_set_err(err, errlen,
                             "reason=token_file_too_large provider_id=%s line=%d",
                             id, pc->line);
                mn_secure_zero(raw, raw_cap);
                free(raw);
                return E_CFG;
            }
            raw[raw_len] = '\0';
            for (i = 0; i < raw_len; ++i) {
                if (raw[i] == '\n' || raw[i] == '\r') {
                    raw[i] = '\0';
                    break;
                }
            }
            if (mn_strlcpy(p->token, sizeof(p->token), mn_trim(raw)) < 0) {
                prov_set_err(err, errlen,
                             "reason=token_too_long provider_id=%s line=%d",
                             id, pc->line);
                mn_secure_zero(raw, raw_cap);
                free(raw);
                return E_CFG;
            }
            mn_secure_zero(raw, raw_cap);
            free(raw);
        }
    } else if (has_inline) {
        if (mn_strlcpy(p->token, sizeof(p->token), pc->token_inline) < 0) {
            prov_set_err(err, errlen,
                         "reason=token_too_long provider_id=%s line=%d",
                         id, pc->line);
            return E_CFG;
        }
    }
    if (p->token[0] == '\0') {
        if (!diagnostic && !*skipped) {
            prov_set_err(err, errlen,
                         "reason=empty_token provider_id=%s line=%d",
                         id, pc->line);
            return E_CFG;
        }
        mn_log(MN_LOG_WARN,
               "provider id=%s line=%d token_empty=1 diagnostic=%d skipped=%d",
               id, pc->line, diagnostic, *skipped);
    }
    return MN_OK;
}

int mn_provider_init_all(struct mn_cfg *cfg, struct mn_provider *provs,
                         size_t cap, int diagnostic, char *err, size_t errlen)
{
    size_t i, j;

    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
    if (cfg == NULL || provs == NULL) {
        prov_set_err(err, errlen, "reason=invalid_argument");
        return E_CFG;
    }
    if (cfg->n_providers > MN_MAX_PROVIDERS || cfg->n_records > MN_MAX_RECORDS) {
        prov_set_err(err, errlen,
                     "reason=config_limit providers=%zu records=%zu",
                     cfg->n_providers, cfg->n_records);
        return E_CFG;
    }
    if (cfg->n_providers > cap) {
        prov_set_err(err, errlen,
                     "reason=provider_capacity cap=%zu count=%zu",
                     cap, cfg->n_providers);
        return E_CFG;
    }
    for (i = 0; i < cfg->n_providers; ++i) {
        const struct mn_provider_cfg *pc = &cfg->providers[i];
        const struct mn_provider_ops *ops = mn_provider_lookup(pc->kind);
        char id[MN_PROV_ESC_CAP];
        char kind[MN_PROV_ESC_CAP];
        char operr[MN_PROV_DETAIL_CAP];
        char detail[MN_PROV_DETAIL_CAP];
        int skipped = 0;
        int rc;

        memset(&provs[i], 0, sizeof(provs[i]));
        prov_escape(id, sizeof(id), pc->id);
        prov_escape(kind, sizeof(kind), pc->kind);
        if (ops == NULL) {
            prov_set_err(err, errlen,
                         "reason=unknown_provider_kind provider_id=%s kind=%s line=%d",
                         id, kind, pc->line);
            mn_provider_fini_all(provs, i + 1u);
            return E_CFG;
        }
        provs[i].ops = ops;
        provs[i].cfg = cfg;
        provs[i].id = pc->id;
        if (mn_strlcpy(provs[i].zone_id, sizeof(provs[i].zone_id), pc->zone_id) < 0) {
            prov_set_err(err, errlen,
                         "reason=zone_id_truncated provider_id=%s line=%d",
                         id, pc->line);
            mn_provider_fini_all(provs, i + 1u);
            return E_CFG;
        }
        rc = prov_resolve_token(cfg, &provs[i], pc, diagnostic, &skipped,
                                err, errlen);
        if (rc < 0) {
            mn_provider_fini_all(provs, i + 1u);
            return E_CFG;
        }
        operr[0] = '\0';
        rc = ops->init(&provs[i], cfg, provs[i].id, operr, sizeof(operr));
        if (rc < 0 || rc > 0) {
            prov_single_line(detail, sizeof(detail), operr);
            prov_set_err(err, errlen,
                         "reason=provider_init provider_id=%s line=%d %s",
                         id, pc->line, detail);
            mn_provider_fini_all(provs, i + 1u);
            return E_CFG;
        }
    }
    for (j = 0; j < cfg->n_records; ++j) {
        struct mn_record_cfg *rec = &cfg->records[j];
        char provider_id[MN_PROV_ESC_CAP];
        char name[MN_PROV_ESC_CAP];
        struct mn_provider *p;

        rec->prov = NULL;
        p = mn_provider_find(provs, cfg->n_providers, rec->provider_id);
        if (p == NULL) {
            prov_set_err(err, errlen,
                         "reason=unknown_provider provider_id=%s record=%s line=%d",
                         prov_escape(provider_id, sizeof(provider_id), rec->provider_id),
                         prov_escape(name, sizeof(name), rec->name), rec->line);
            mn_provider_fini_all(provs, cfg->n_providers);
            return E_CFG;
        }
        rec->prov = p;
    }
    return MN_OK;
}

int mn_cycle(struct mn_cycle_ctx *ctx, const char *reason,
             int *ok_count, int *fail_count, int64_t *duration_ms)
{
    char reason_esc[MN_PROV_ESC_CAP];
    const char *reason_value = reason != NULL ? reason : "event";
    const char *next;
    int ok = 0;
    int fail = 0;
    int64_t t0;
    int64_t duration;
    size_t n_records;
    size_t i;

    mn_log(MN_LOG_INFO, "cycle start reason=%s",
           prov_escape(reason_esc, sizeof(reason_esc), reason_value));
    if (ok_count != NULL) {
        *ok_count = 0;
    }
    if (fail_count != NULL) {
        *fail_count = 0;
    }
    if (duration_ms != NULL) {
        *duration_ms = 0;
    }
    if (ctx == NULL || ctx->cfg == NULL) {
        prov_log_cycle_end(0, 1, 0, "event");
        mn_log_repeat_flush();
        return 1;
    }
    ctx->last_errcode = MN_OK;
    ctx->last_http_status = -1;
    ctx->last_retry_after = -1;
    t0 = mn_now_ms();
    next = prov_next_reason(reason_value);
    if (ctx->clock_guard) {
        mn_log(MN_LOG_WARN, "clock_unsynced epoch=%lld retry_in=30s",
               (long long)time(NULL));
        duration = prov_elapsed_ms(t0);
        if (duration_ms != NULL) {
            *duration_ms = duration;
        }
        prov_log_cycle_end(0, 0, duration, "clock");
        mn_log_repeat_flush();
        return 0;
    }

    n_records = ctx->cfg->n_records;
    if (n_records > MN_MAX_RECORDS) {
        n_records = MN_MAX_RECORDS;
    }
    for (i = 0; i < n_records; ++i) {
        struct mn_record_cfg *rec = &ctx->cfg->records[i];
        struct mn_provider *prov;
        struct mn_detect_result det;
        struct mn_remote remote;
        char errbuf[MN_PROV_LOCAL_ERR];
        char name[MN_PROV_ESC_CAP];
        char want[MN_PROV_ESC_CAP];
        char old[MN_PROV_ESC_CAP];
        char id[MN_PROV_ESC_CAP];
        char kind[MN_PROV_ESC_CAP];
        char fold_key[64];
        char normalized[MN_IP_STRLEN];
        const char *type;
        int drc;
        int prc;
        int errcode = MN_OK;
        int same = 0;
        int64_t op_t0;
        int64_t op_ms;

        if (!rec->enabled) {
            continue;
        }
        type = prov_record_type(rec->family);
        prov_escape(name, sizeof(name), rec->name);
        errbuf[0] = '\0';
        memset(&det, 0, sizeof(det));
        if (rec->family != AF_INET && rec->family != AF_INET6) {
            prov_log_error(rec, E_CFG, "reason=bad_family");
            ++fail;
            prov_cycle_failure(ctx, E_CFG, E_CFG);
            continue;
        }
        if (rec->family == AF_INET) {
            drc = mn_detect_ipv4(ctx->cfg, ctx->addrs, ctx->ca, &det,
                                 errbuf, sizeof(errbuf));
        } else {
            drc = mn_detect_ipv6(ctx->cfg, ctx->addrs, &det,
                                 errbuf, sizeof(errbuf));
        }
        if (drc == E_NO_IP) {
            const char *key;
            if (rec->family == AF_INET && ctx->cfg->detect.ipv4_mode == MN_IP4_OFF) {
                key = prov_fold_key(fold_key, sizeof(fold_key), i, "skip-ipv4-off");
                mn_log_repeat(MN_LOG_INFO, key,
                              "record name=%s type=A action=skip reason=ipv4-off",
                              name);
            } else if (rec->family == AF_INET6) {
                key = prov_fold_key(fold_key, sizeof(fold_key), i, "skip-ipv6");
                mn_log_repeat(MN_LOG_INFO, key,
                              "record name=%s type=AAAA action=skip reason=no-publishable-ipv6 "
                              "candidates=%d filtered_temporary=%d filtered_dadfailed=%d "
                              "filtered_deprecated=%d filtered_tentative=%d filtered_optimistic=%d "
                              "filtered_lifetime=%d filtered_private=%d filtered_scope=%d "
                              "filtered_iface_down=%d filtered_iface_name=%d",
                              name, det.candidates, det.filtered_temporary,
                              det.filtered_dadfailed, det.filtered_deprecated,
                              det.filtered_tentative, det.filtered_optimistic,
                              det.filtered_lifetime, det.filtered_private,
                              det.filtered_scope, det.filtered_iface_down,
                              det.filtered_iface_name);
            } else {
                key = prov_fold_key(fold_key, sizeof(fold_key), i, "skip-no-ip");
                mn_log_repeat(MN_LOG_INFO, key,
                              "record name=%s type=A action=skip reason=no-ip",
                              name);
            }
            ++ok;
            continue;
        }
        if (drc != MN_OK) {
            prov_log_error(rec, drc, errbuf);
            ++fail;
            prov_cycle_failure(ctx, drc, drc);
            continue;
        }
        if (ctx->memos != NULL &&
            mn_memo_hit(&ctx->memos[i], det.ip, mn_now_ms(),
                        ctx->cfg->core.write_memo_ms)) {
            prov_escape(want, sizeof(want), det.ip);
            mn_log_repeat(MN_LOG_DEBUG,
                          prov_fold_key(fold_key, sizeof(fold_key), i, "unchanged-memo"),
                          "record name=%s type=%s action=unchanged reason=write_memo ip=%s",
                          name, type, want);
            ++ok;
            continue;
        }

        prov = rec->prov;
        if (prov == NULL) {
            prov_log_error(rec, E_CFG, "reason=provider_unresolved");
            ++fail;
            prov_cycle_failure(ctx, E_CFG, E_CFG);
            continue;
        }
        prov->ca = ctx->ca;
        memset(&remote, 0, sizeof(remote));
        errbuf[0] = '\0';
        errcode = MN_OK;
        prc = mn_provider_discover(prov, rec, &remote, &errcode,
                                   errbuf, sizeof(errbuf));
        if (prc != MN_OK) {
            prov_log_error(rec, prc, errbuf);
            ++fail;
            prov_cycle_failure(ctx, prc, errcode);
            continue;
        }
        if (!remote.found) {
            if (!rec->create_if_missing) {
                mn_log_repeat(MN_LOG_INFO,
                              prov_fold_key(fold_key, sizeof(fold_key), i, "skip-absent"),
                              "record name=%s type=%s action=skip reason=absent",
                              name, type);
                ++ok;
                continue;
            }
            prov_escape(want, sizeof(want), det.ip);
            if (ctx->dry_run) {
                mn_log(MN_LOG_INFO,
                       "record name=%s type=%s action=would-create ip=%s",
                       name, type, want);
                ++ok;
                continue;
            }
            op_t0 = mn_now_ms();
            errbuf[0] = '\0';
            errcode = MN_OK;
            prc = mn_provider_create(prov, rec, det.ip, &remote, &errcode,
                                     errbuf, sizeof(errbuf));
            if (prc != MN_OK) {
                prov_log_error(rec, prc, errbuf);
                ++fail;
                prov_cycle_failure(ctx, prc, errcode);
                continue;
            }
            op_ms = prov_elapsed_ms(op_t0);
            if (ctx->memos != NULL) {
                mn_memo_set(&ctx->memos[i], det.ip, mn_now_ms());
            }
            prov_escape(id, sizeof(id), remote.id[0] != '\0' ? remote.id : "-");
            mn_log(MN_LOG_INFO,
                   "record name=%s type=%s action=create ip=%s id=%s duration_ms=%" PRId64,
                   name, type, want, id, op_ms);
            ++ok;
            continue;
        }

        memset(normalized, 0, sizeof(normalized));
        if (mn_ip_normalize(rec->family, remote.content, normalized) != 0) {
            prov_escape(old, sizeof(old), remote.content);
            mn_log(MN_LOG_WARN,
                   "record name=%s type=%s reason=remote_content_invalid old=%s",
                   name, type, old);
        } else {
            same = mn_ip_equal(rec->family, remote.content, det.ip) > 0;
        }
        if (same) {
            prov_escape(want, sizeof(want), det.ip);
            mn_log_repeat(MN_LOG_DEBUG,
                          prov_fold_key(fold_key, sizeof(fold_key), i, "unchanged"),
                          "record name=%s type=%s action=unchanged ip=%s",
                          name, type, want);
            ++ok;
            continue;
        }

        prov_escape(want, sizeof(want), det.ip);
        prov_escape(old, sizeof(old), remote.content);
        if (ctx->dry_run) {
            mn_log(MN_LOG_INFO,
                   "record name=%s type=%s action=would-update old=%s new=%s",
                   name, type, old, want);
            ++ok;
            continue;
        }
        op_t0 = mn_now_ms();
        errbuf[0] = '\0';
        errcode = MN_OK;
        prc = mn_provider_update(prov, rec, &remote, det.ip, &errcode,
                                 errbuf, sizeof(errbuf));
        if (prc != MN_OK) {
            prov_log_error(rec, prc, errbuf);
            ++fail;
            prov_cycle_failure(ctx, prc, errcode);
            continue;
        }
        op_ms = prov_elapsed_ms(op_t0);
        if (ctx->memos != NULL) {
            mn_memo_set(&ctx->memos[i], det.ip, mn_now_ms());
        }
        prov_escape(kind, sizeof(kind),
                    (prov->ops != NULL && prov->ops->kind != NULL) ? prov->ops->kind : "cloudflare");
        mn_log(MN_LOG_INFO,
               "record name=%s type=%s action=update old=%s new=%s provider=%s duration_ms=%" PRId64,
               name, type, old, want, kind, op_ms);
        ++ok;
    }

    duration = prov_elapsed_ms(t0);
    if (ok_count != NULL) {
        *ok_count = ok;
    }
    if (fail_count != NULL) {
        *fail_count = fail;
    }
    if (duration_ms != NULL) {
        *duration_ms = duration;
    }
    prov_log_cycle_end(ok, fail, duration, next);
    mn_log_repeat_flush();
    return fail == 0 ? 0 : 1;
}

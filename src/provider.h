/* provider.h — §07 vtable registry + §05.4 generic diff/apply cycle */
#ifndef MN_PROVIDER_H
#define MN_PROVIDER_H

#include "miniddns.h"
#include "sched.h"
#include "nl_addr.h"
#include "ca.h"

#define MN_CF_API_HOST "api.cloudflare.com"
#define MN_CF_API_PORT 443

/* Runtime instance array, one per [provider] section. */
int mn_provider_init_all(struct mn_cfg *cfg, struct mn_provider *provs,
                         size_t cap, int diagnostic, char *err, size_t errlen);
void mn_provider_fini_all(struct mn_provider *provs, size_t n);
struct mn_provider *mn_provider_find(struct mn_provider *provs, size_t n,
                                     const char *id);

int mn_provider_discover(struct mn_provider *p, const struct mn_record_cfg *rc,
                         struct mn_remote *out, int *errcode, char *err, size_t errlen);
int mn_provider_update(struct mn_provider *p, const struct mn_record_cfg *rc,
                       const struct mn_remote *cur, const char *ip,
                       int *errcode, char *err, size_t errlen);
int mn_provider_create(struct mn_provider *p, const struct mn_record_cfg *rc,
                       const char *ip, struct mn_remote *out,
                       int *errcode, char *err, size_t errlen);

struct mn_cycle_ctx {
    struct mn_cfg      *cfg;
    struct mn_provider *provs;
    size_t              n_provs;
    struct mn_addr_set *addrs;
    struct mn_ca *ca;
    struct mn_memo     *memos;       /* one per record */
    int                 dry_run;
    int                 clock_guard; /* 1 = clock unsynced, no requests at all */
    /* output of the last failed record; used by main for backoff (§05.5) */
    int                 last_errcode;
    int                 last_http_status;
    int                 last_retry_after;
};

/* One complete cycle (§05.4). Returns 0 when fail==0, 1 when any record failed. */
int mn_cycle(struct mn_cycle_ctx *ctx, const char *reason,
             int *ok_count, int *fail_count, int64_t *duration_ms);

#endif /* MN_PROVIDER_H */

/* sched.h — pure scheduling helpers (§05.3–§05.5), usable by unit tests */
#ifndef MN_SCHED_H
#define MN_SCHED_H

#include "miniddns.h"

/* write memo (§05.4.1) */
struct mn_memo {
    char    ip[MN_IP_STRLEN];
    int64_t mono_ms;
    int     valid;
};
int  mn_memo_hit(const struct mn_memo *m, const char *ip, int64_t now_ms, int window_ms);
void mn_memo_set(struct mn_memo *m, const char *ip, int64_t now_ms);

/* backoff (§05.5). Returns delay in ms; never 0 (interval_fallback=0 must still retry). */
int64_t mn_backoff_delay_ms(const int *seq, size_t n, size_t idx,
                            int interval_fallback_s, int errcode, int http_status,
                            int retry_after_s);
size_t  mn_backoff_next(size_t idx, size_t n);

/* Return the delay for the current step, then advance *idx for the next
   failure.  This keeps the first failure on seq[0] (5s by default). */
int64_t mn_backoff_take(const int *seq, size_t n, size_t *idx,
                        int interval_fallback_s, int errcode, int http_status,
                        int retry_after_s);

/* Retry-After: delta-seconds or HTTP-date; clamp [1,86400]; -1 = absent/invalid */
int mn_retry_after_seconds(const char *value, time_t now);

/* debounce sliding window with hard cap (§05.3) */
struct mn_debounce {
    int64_t deadline_ms;
    int64_t first_ms;
    int     active;
};
void mn_debounce_event(struct mn_debounce *d, int64_t now_ms, int debounce_ms,
                       int max_defer_ms);
int  mn_debounce_due(const struct mn_debounce *d, int64_t now_ms);
void mn_debounce_clear(struct mn_debounce *d);

/* clock guard (§05.6) */
int mn_clock_unsynced(time_t now, time_t guard_epoch);

#endif /* MN_SCHED_H */

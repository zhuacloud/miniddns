/* sched.c — pure scheduling helpers (§05.3–§05.6), unit-testable */
#include "sched.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int mn_memo_hit(const struct mn_memo *m, const char *ip, int64_t now_ms, int window_ms)
{
    if (!m || !m->valid || window_ms <= 0 || !ip) return 0;
    if (strcmp(m->ip, ip) != 0) return 0;
    if (now_ms < m->mono_ms) return 0;
    return (now_ms - m->mono_ms) < (int64_t)window_ms;
}

void mn_memo_set(struct mn_memo *m, const char *ip, int64_t now_ms)
{
    if (!m || !ip) return;
    snprintf(m->ip, sizeof(m->ip), "%s", ip);
    m->mono_ms = now_ms;
    m->valid = 1;
}

static int clamp_s(int v) { return v < 1 ? 1 : (v > 86400 ? 86400 : v); }

int64_t mn_backoff_delay_ms(const int *seq, size_t n, size_t idx,
                            int interval_fallback_s, int errcode, int http_status,
                            int retry_after_s)
{
    int base;
    int64_t ms;
    if (!seq || n == 0) return 1000;
    if (idx >= n) idx = n - 1;
    base = clamp_s(seq[idx]);
    /* §05.5: non-self-healing errors jump to the largest step. */
    if (errcode == E_TLS_CERT ||
        (errcode == E_HTTP_STATUS && http_status >= 400 && http_status < 500 && http_status != 429) ||
        errcode == E_PARSE ||
        errcode == E_API) {
        size_t i;
        for (i = 0; i < n; i++) if (seq[i] > base) base = clamp_s(seq[i]);
    }
    if (errcode == E_TLS_TIME) return 30000;     /* clock guard: fixed 30 s, no backoff consumption */
    if (retry_after_s > 0) {
        ms = (int64_t)clamp_s(retry_after_s) * 1000;   /* Retry-After overrides backoff */
    } else if (interval_fallback_s > 0) {
        int f = clamp_s(interval_fallback_s);
        ms = (int64_t)(base < f ? base : f) * 1000;
    } else {
        /* interval_fallback=0 must NOT produce delay=0 (would disarm timerfd) */
        ms = (int64_t)base * 1000;
    }
    if (ms < 1000) ms = 1000;
    return ms;
}

size_t mn_backoff_next(size_t idx, size_t n)
{
    if (n == 0) return 0;
    return (idx + 1 < n) ? idx + 1 : n - 1;
}

int64_t mn_backoff_take(const int *seq, size_t n, size_t *idx,
                        int interval_fallback_s, int errcode, int http_status,
                        int retry_after_s)
{
    size_t current = idx != NULL ? *idx : 0;
    int64_t delay = mn_backoff_delay_ms(seq, n, current, interval_fallback_s,
                                        errcode, http_status, retry_after_s);

    if (idx != NULL)
        *idx = mn_backoff_next(current, n);
    return delay;
}

/* civil date -> days since 1970-01-01 (Hinnant); no timezone dependence */
static int64_t days_from_civil(int y, unsigned m, unsigned d)
{
    int64_t yy = y;
    yy -= m <= 2;
    const int64_t era = (yy >= 0 ? yy : yy - 399) / 400;
    const unsigned yoe = (unsigned)(yy - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static int month_index(const char *s)
{
    static const char *names[] = { "Jan","Feb","Mar","Apr","May","Jun",
                                   "Jul","Aug","Sep","Oct","Nov","Dec" };
    int i;
    for (i = 0; i < 12; i++) if (strncmp(s, names[i], 3) == 0) return i + 1;
    return 0;
}

int mn_retry_after_seconds(const char *value, time_t now)
{
    char *end;
    long v;
    if (!value || !value[0]) return -1;
    while (*value == ' ' || *value == '\t') value++;
    v = strtol(value, &end, 10);
    if (end != value && *end == '\0') {
        if (v < 1) v = 1;
        if (v > 86400) v = 86400;
        return (int)v;
    }
    /* HTTP-date, e.g. "Sun, 06 Nov 1994 08:49:37 GMT" (also RFC850/RFC1123) */
    {
        char wday[8] = {0}, mon[8] = {0}, tz[8] = {0};
        int day = 0, year = 0, hh = 0, mm = 0, ss = 0, mi;
        if (sscanf(value, "%3[A-Za-z], %d %3[A-Za-z] %d %d:%d:%d %3[A-Za-z]",
                   wday, &day, mon, &year, &hh, &mm, &ss, tz) == 8) {
            int64_t target;
            mi = month_index(mon);
            if (!mi || day < 1 || day > 31 || year < 1970) return -1;
            if (year < 100) year += (year < 70 ? 2000 : 1900);
            target = days_from_civil(year, (unsigned)mi, (unsigned)day) * 86400
                   + hh * 3600 + mm * 60 + ss;
            v = (long)(target - (int64_t)now);
            if (v < 1) v = 1;
            if (v > 86400) v = 86400;
            return (int)v;
        }
    }
    return -1;
}

void mn_debounce_event(struct mn_debounce *d, int64_t now_ms, int debounce_ms,
                       int max_defer_ms)
{
    if (!d->active) {
        d->active = 1;
        d->first_ms = now_ms;
    }
    d->deadline_ms = now_ms + debounce_ms;
    if (max_defer_ms > 0 && d->deadline_ms - d->first_ms > max_defer_ms)
        d->deadline_ms = d->first_ms + max_defer_ms;
}

int mn_debounce_due(const struct mn_debounce *d, int64_t now_ms)
{
    return d->active && now_ms >= d->deadline_ms;
}

void mn_debounce_clear(struct mn_debounce *d)
{
    d->active = 0; d->deadline_ms = 0; d->first_ms = 0;
}

int mn_clock_unsynced(time_t now, time_t guard_epoch)
{
    return now < guard_epoch;
}

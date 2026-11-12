/* ca.h — §09 CA bundle loader: PEM -> br_x509_trust_anchor[], two-stage arena */
#ifndef MN_CA_H
#define MN_CA_H

#include "miniddns.h"
#include "bearssl.h"
#include <sys/types.h>  /* off_t, ino_t — needed by musl too */

struct mn_ca_info {
    size_t   n_total;          /* PEM CERTIFICATE objects seen */
    size_t   n_skipped;        /* decode failures / oversized DER / bad time */
    size_t   n_expired;        /* notAfter already past */
    uint32_t earliest_days;    /* days since 1970 of earliest notAfter */
    int      earliest_valid;
    char     earliest_subject[128]; /* best-effort CN, for warnings */
};

struct mn_ca {
    char path[MN_PATH_MAX];              /* resolved path */
    br_x509_trust_anchor *anchors;       /* points into arena */
    size_t n_anchors;
    void  *arena;                        /* single allocation, replaced atomically */
    struct mn_ca_info info;
    struct { time_t mtime; off_t size; ino_t ino; } sig;
    int allow_non_root_owner;
};

/* load + validate path (§03/§09). 0 ok, E_CA_LOAD(-12) on failure. */
int mn_ca_init(struct mn_ca *ca, const char *path, int allow_non_root_owner,
               char *err, size_t errlen);

/* stat() the resolved target before each request; reload on change.
   On reload failure the OLD anchors are kept and an error is logged.
   Returns 0 (ok or kept-old), -1 when the file itself vanished. */
int mn_ca_refresh(struct mn_ca *ca);

const br_x509_trust_anchor *mn_ca_current(struct mn_ca *ca, size_t *n);
void mn_ca_free(struct mn_ca *ca);

/* Format days-since-1970 as YYYY-MM-DD (UTC). */
int  mn_ca_format_date(uint32_t days, char *out, size_t cap);

/* Exposed for unit tests: parse a PEM buffer. Caller frees *arena. */
int mn_ca_parse_bundle(const char *buf, size_t len,
                       br_x509_trust_anchor **anchors, size_t *n_anchors,
                       void **arena, struct mn_ca_info *info,
                       char *err, size_t errlen);

#endif /* MN_CA_H */

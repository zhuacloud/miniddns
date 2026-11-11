/* util.h — small, dependency-free helpers (§03 paths/permissions, §06 compare) */
#ifndef MN_UTIL_H
#define MN_UTIL_H

#include "miniddns.h"

int64_t  mn_now_ms(void);                       /* CLOCK_MONOTONIC */
time_t   mn_wall(void);                         /* CLOCK_REALTIME */

char    *mn_trim(char *s);                      /* in-place, returns s */
int      mn_strlcpy(char *dst, size_t cap, const char *src); /* 0 ok, -1 truncated */
int      mn_strlcat(char *dst, size_t cap, const char *src);
void     mn_secure_zero(void *p, size_t n);

/* §03: token = O_NOFOLLOW; conf/ca = realpath + fstat(target); size/owner/mode checks */
int      mn_checked_read(const char *path, int cls, char *buf, size_t cap,
                         size_t *len, int allow_non_root_owner,
                         char *err, size_t errlen);

/* readlink("/proc/self/exe") based artifact root detection */
int      mn_find_artifact_root(char *out, size_t cap);
int      mn_resolve_conf_path(const char *cli_path, const char *root,
                              char *out, size_t cap, char *err, size_t errlen);
int      mn_resolve_ca_path(const struct mn_cfg *cfg, char *out, size_t cap,
                            char *err, size_t errlen);

/* '$CREDENTIALS_DIRECTORY/' expansion: diagnostic => warn + *skipped=1 */
int      mn_expand_creds_dir(const char *value, char *out, size_t cap,
                             int diagnostic, int *skipped, char *err, size_t errlen);

/* https://host[:port]/path parser; rejects anything else */
int      mn_parse_https_url(const char *url, char *host, size_t hostcap,
                            int *port, char *path, size_t pathcap,
                            char *err, size_t errlen);

/* iface_include/exclude: exact match or trailing '*' only */
int      mn_iface_match(const char *pattern, const char *name);

/* check-config masking (never print a full token / zone id) */
const char *mn_mask(const char *s, char *out, size_t cap);

#endif /* MN_UTIL_H */

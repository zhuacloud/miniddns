/* miniddns — shared types, constants and error codes (design.md §07.1 / A.0 / A.3) */
#ifndef MINIDDNS_H
#define MINIDDNS_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

#define MN_VERSION        "1.2.0"

/* ---- A.0 internal constants ------------------------------------------------ */
#define MN_IP_STRLEN        46      /* INET6_ADDRSTRLEN, incl NUL */
#define MN_FQDN_MAX         254     /* incl NUL */
#define MN_ID_MAX           64
#define MN_TOKEN_MAX        512
#define MN_MAX_PROVIDERS    8
#define MN_MAX_RECORDS      32
#define MN_CA_MAX_ANCHORS   512
#define MN_LIMIT_CA_FILE    (2 * 1024 * 1024)
#define MN_LIMIT_CONF_FILE  (256 * 1024)
#define MN_LIMIT_TOKEN_FILE (256 * 1024)
#define MN_LIMIT_DER        (16 * 1024)
#define MN_LIMIT_HEADER     (16 * 1024)
#define MN_LIMIT_BODY       (256 * 1024)
#define MN_TLS_IOBUF        16384
#define MN_MAX_REDIRECT     3
#define MN_BACKOFF_MAX      8
#define MN_LOG_LINE_MAX     1024
#define MN_LOG_FIELD_MAX    200

/* project-internal bounds (implementation detail, not part of the INI schema) */
#define MN_PATH_MAX         512
#define MN_MAX_ADDRS        128
#define MN_IFNAME_MAX       16
#define MN_MAX_ECHO_URLS    8
#define MN_ZONE_ID_MAX      40

/* ---- A.3 error codes ------------------------------------------------------- */
#define MN_OK               0
#define E_CFG              (-1)
#define E_DNS              (-2)
#define E_CONNECT          (-3)
#define E_TIMEOUT          (-4)
#define E_TLS_HANDSHAKE    (-5)
#define E_TLS_CERT         (-6)
#define E_TLS_TIME         (-7)
#define E_HTTP_STATUS      (-8)
#define E_RATELIMIT        (-9)
#define E_PARSE            (-10)
#define E_API              (-11)
#define E_CA_LOAD          (-12)
#define E_NO_IP            (-13)
#define E_BUSY             (-14)

const char *mn_err_name(int rc);

/* ---- enum values ----------------------------------------------------------- */
enum mn_log_level {
    MN_LOG_ERROR = 3,
    MN_LOG_WARN  = 4,
    MN_LOG_INFO  = 6,
    MN_LOG_DEBUG = 7
};

enum mn_log_target { MN_LOG_JOURNALD = 0, MN_LOG_FILE = 1 };

enum mn_ip4_mode {
    MN_IP4_OFF = 0, MN_IP4_IFACE = 1, MN_IP4_EXTERNAL = 2, MN_IP4_AUTO = 3
};
enum mn_ip6_mode { MN_IP6_OFF = 0, MN_IP6_IFACE = 1 };

/* file classes for checked reads (§03) */
enum mn_file_class {
    MN_FILE_CONF = 0,
    MN_FILE_TOKEN = 1,
    MN_FILE_CA = 2
};

/* ---- configuration --------------------------------------------------------- */
struct mn_core_cfg {
    char    instance[33];
    int     interval_fallback;      /* seconds; 0 disables fallback timer */
    int     debounce_ms;
    int     write_memo_ms;
    char    ca_bundle[MN_PATH_MAX]; /* empty = auto-detect */
    int     http_timeout_ms;
    int     connect_timeout_ms;
    int     retry_backoff[MN_BACKOFF_MAX];
    size_t  n_backoff;
    int     log_level;              /* enum mn_log_level */
    int     log_target;             /* enum mn_log_target */
    char    log_file[MN_PATH_MAX];
    char    lock_file[MN_PATH_MAX];
    time_t  clock_guard_epoch;
};

struct mn_detect_cfg {
    int  ipv4_mode;                 /* enum mn_ip4_mode */
    int  ipv6_mode;                 /* enum mn_ip6_mode */
    char iface_include[MN_PATH_MAX];
    char iface_exclude[MN_PATH_MAX];
    char ipv4_echo_url[1024];
    int  allow_private_ipv4;
    int  allow_temporary_ipv6;
};

struct mn_provider_cfg {
    char id[64];
    char kind[32];
    char zone_id[MN_ZONE_ID_MAX];
    char token_file[MN_PATH_MAX];
    char token_inline[MN_TOKEN_MAX];
    int  has_token_inline;
    int  line;                      /* line of the [provider] header */
};

struct mn_record_cfg {
    char name[MN_FQDN_MAX];
    int  family;                    /* AF_INET | AF_INET6 */
    int  ttl;
    int  proxied;
    int  create_if_missing;
    int  enabled;
    char provider_id[64];
    int  line;                      /* line of the [record] header */
    struct mn_provider *prov;       /* resolved runtime instance */
};

struct mn_cfg {
    struct mn_core_cfg     core;
    int allow_non_root_owner;   /* runtime-only, set from --allow-non-root-owner */
    struct mn_detect_cfg   detect;
    struct mn_provider_cfg providers[MN_MAX_PROVIDERS];
    struct mn_record_cfg   records[MN_MAX_RECORDS];
    size_t n_providers, n_records;
    char   conf_path[MN_PATH_MAX];  /* actually used config path (startup log) */
    char   root[MN_PATH_MAX];       /* artifact root, empty when system install */
    int    has_root;
};

/* ---- provider model (§07.1 / §07.2) --------------------------------------- */
struct mn_remote {
    int  found;
    char id[MN_ID_MAX];
    char content[MN_IP_STRLEN];     /* normalised */
};

#define MN_CAP_PATCH_CONTENT (1u << 0)
#define MN_CAP_CREATE        (1u << 1)
#define MN_CAP_TTL           (1u << 2)
#define MN_CAP_PROXY         (1u << 3)
#define MN_CAP_DISCOVER      (1u << 4)

struct mn_provider;
struct mn_ca;                   /* ca.h — forward declared to avoid a cycle */
struct mn_provider_ops {
    const char *kind;
    unsigned    caps;
    int  (*init)(struct mn_provider *p, const struct mn_cfg *cfg,
                 const char *prov_id, char *err, size_t errlen);
    int  (*discover)(struct mn_provider *p, const struct mn_record_cfg *rc,
                     struct mn_remote *out, char *err, size_t errlen);
    int  (*update)(struct mn_provider *p, const struct mn_record_cfg *rc,
                   const struct mn_remote *cur, const char *ip,
                   char *err, size_t errlen);
    int  (*create)(struct mn_provider *p, const struct mn_record_cfg *rc,
                   const char *ip, struct mn_remote *out,
                   char *err, size_t errlen);
    void (*fini)(struct mn_provider *p);
};

struct mn_provider {
    const struct mn_provider_ops *ops;
    const struct mn_cfg *cfg;
    const char *id;                 /* points into cfg */
    char  token[MN_TOKEN_MAX];
    char  zone_id[MN_ZONE_ID_MAX];
    void *priv;
    struct mn_ca *ca;               /* borrowed TLS trust context, set by mn_cycle */
};

const struct mn_provider_ops *mn_provider_lookup(const char *kind);

#endif /* MINIDDNS_H */

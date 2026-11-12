/* tls_http.h — §08 BearSSL + minimal HTTP/1.1 client (fail closed) */
#ifndef MN_TLS_HTTP_H
#define MN_TLS_HTTP_H

#include "miniddns.h"
#include "ca.h"

struct mn_http_req {
    const char *method;         /* GET / PATCH / POST — never hard-coded */
    const char *host;           /* SNI + Host header */
    const char *path;           /* request target, incl. query */
    const char *body;           /* NULL/"" for GET */
    const char *extra_headers;  /* e.g. "Authorization: Bearer ...\r\n"; NEVER logged */
    int         port;           /* 443 */
    int         want_json;      /* validate Content-Type contains "json" */
    int         allow_redirect; /* echo endpoints only, §06.2 */
};

struct mn_http_result {
    int    status;
    char  *body;                /* heap, NUL-terminated; free with mn_http_result_free */
    size_t body_len;
    int    retry_after_secs;    /* -1 when absent */
    char   content_type[64];
};

void mn_http_result_free(struct mn_http_result *r);

/* Metadata of the last completed request (single-threaded process).
   Used by the core to pick backoff for E_HTTP_STATUS / E_RATELIMIT (§05.5).
   -1 means "not present". */
void mn_http_last_meta(int *http_status, int *retry_after_secs);

/* Full request with socket + TLS. Returns 0 on HTTP-level completion (check status),
   negative error code otherwise; *errcode carries the same code. */
int mn_http_request(const struct mn_cfg *cfg, struct mn_ca *ca,
                    const struct mn_http_req *req, struct mn_http_result *out,
                    int *errcode, char *err, size_t errlen);

/* TLS handshake only, zero application bytes (§09.6 --check-ca) */
int mn_tls_handshake(const struct mn_cfg *cfg, struct mn_ca *ca,
                     const char *host, int port, char *cipher, size_t ciphercap,
                     int *tls_version, int *errcode, char *err, size_t errlen);

/* Human-readable name for a BearSSL protocol version (e.g. "1.2"). */
const char *mn_tls_version_name(int version);

/* Pure response parser for unit tests: status line, headers, Content-Length,
   chunked, limits, Retry-After. Returns 0 or E_PARSE with reason in err. */
int mn_http_parse_raw(const char *buf, size_t len, struct mn_http_result *out,
                      int *errcode, char *err, size_t errlen);

#endif /* MN_TLS_HTTP_H */

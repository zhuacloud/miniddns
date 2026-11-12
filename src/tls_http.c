/* tls_http.c — §08 BearSSL client + minimal HTTP/1.1, fail closed */
#include "tls_http.h"
#include "log.h"
#include "sched.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MN_TLS_DAYS_TO_EPOCH          719528u
#define MN_TLS_DEFAULT_HTTP_MS        8000
#define MN_TLS_DEFAULT_CONNECT_MS     5000
#define MN_TLS_RESP_CAP               ((size_t)MN_LIMIT_HEADER + (size_t)MN_LIMIT_BODY + 8192u)
#define MN_TLS_REQ_HEADER_CAP         8192u
#define MN_TLS_EXTRA_CAP              4096u
#define MN_TLS_PATH_CAP               1024u
#define MN_TLS_REASON_CAP             64u
#define MN_TLS_LOG_VALUE_CAP          (MN_LOG_FIELD_MAX + 1)

static int g_last_http_status = -1;
static int g_last_retry_after = -1;

void mn_http_result_free(struct mn_http_result *r)
{
    if (r == NULL) {
        return;
    }
    free(r->body);
    r->body = NULL;
    r->body_len = 0;
    r->status = 0;
    r->retry_after_secs = -1;
    r->content_type[0] = '\0';
}

static void tls_result_init(struct mn_http_result *r)
{
    if (r == NULL) {
        return;
    }
    memset(r, 0, sizeof *r);
    r->retry_after_secs = -1;
}

static void tls_copy_literal(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (cap == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    n = strlen(src);
    if (n >= cap) {
        n = cap - 1;
    }
    if (n > 0) {
        memcpy(dst, src, n);
    }
    dst[n] = '\0';
}

static int tls_copy_cstr(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (dst == NULL || cap == 0 || src == NULL) {
        return -1;
    }
    n = strlen(src);
    if (n >= cap) {
        dst[0] = '\0';
        return -1;
    }
    if (n > 0) {
        memcpy(dst, src, n);
    }
    dst[n] = '\0';
    return 0;
}

static int tls_copy_slice(char *dst, size_t cap, const char *src, size_t len,
                          int *truncated)
{
    size_t n;

    if (truncated != NULL) {
        *truncated = 0;
    }
    if (dst == NULL || cap == 0) {
        if (truncated != NULL) {
            *truncated = 1;
        }
        return -1;
    }
    if (len >= cap) {
        n = cap - 1;
        if (truncated != NULL) {
            *truncated = 1;
        }
    } else {
        n = len;
    }
    if (n > 0 && src != NULL) {
        memcpy(dst, src, n);
    }
    dst[n] = '\0';
    return (truncated != NULL && *truncated) ? -1 : 0;
}

static void tls_set_err(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;
    int r;

    if (err == NULL || errlen == 0) {
        return;
    }
    va_start(ap, fmt);
    r = vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
    if (r < 0) {
        err[0] = '\0';
    }
}

static void tls_err_clear(char *err, size_t errlen)
{
    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
}

static int tls_snprintf_ok(int r, size_t cap)
{
    return r >= 0 && (size_t)r < cap;
}

static void tls_set_meta(int status, int retry_after)
{
    g_last_http_status = status;
    g_last_retry_after = retry_after;
}

void mn_http_last_meta(int *http_status, int *retry_after_secs)
{
    if (http_status != NULL) {
        *http_status = g_last_http_status;
    }
    if (retry_after_secs != NULL) {
        *retry_after_secs = g_last_retry_after;
    }
}

static void tls_sanitize_log(const char *in, size_t len,
                             char *out, size_t cap)
{
    size_t i, o;

    if (cap == 0) {
        return;
    }
    for (i = 0, o = 0; i < len && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)in[i];

        if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') {
            c = '_';
        }
        out[o++] = (char)c;
    }
    out[o] = '\0';
}

static int tls_error_level(int rc, int status)
{
    if (rc == E_TLS_CERT || rc == E_PARSE || rc == E_CA_LOAD ||
        (rc == E_HTTP_STATUS && status >= 400 && status < 500)) {
        return MN_LOG_ERROR;
    }
    return MN_LOG_WARN;
}

static void tls_log_error(int rc, int status, const char *host,
                          const char *why)
{
    char safehost[MN_TLS_LOG_VALUE_CAP];
    char safewhy[MN_TLS_REASON_CAP];
    const char *h = host != NULL ? host : "-";
    const char *w = why != NULL && why[0] != '\0' ? why : "unknown";
    int level = tls_error_level(rc, status);

    tls_sanitize_log(h, strlen(h), safehost, sizeof safehost);
    tls_sanitize_log(w, strlen(w), safewhy, sizeof safewhy);
    if (rc == E_PARSE) {
        mn_log(level, "http parse err=%s reason=%s",
               mn_err_name(rc), safewhy);
    } else {
        mn_log(level, "http error err=%s http_status=%d url_host=%s reason=%s",
               mn_err_name(rc), status, safehost, safewhy);
    }
}

static int tls_error_return(int rc, int status, const char *host,
                            const char *why, char *err, size_t errlen,
                            int *errcode)
{
    if (errcode != NULL) {
        *errcode = rc;
    }
    if (err != NULL && errlen > 0 &&
        (err[0] == '\0' || strstr(err, "reason=") == NULL)) {
        tls_set_err(err, errlen, "reason=%s", why != NULL ? why : "unknown");
    }
    tls_log_error(rc, status, host, why);
    return rc;
}

static const char *tls_reason_for_rc(int rc)
{
    switch (rc) {
    case E_DNS:           return "dns";
    case E_CONNECT:       return "connect";
    case E_TIMEOUT:       return "timeout";
    case E_TLS_HANDSHAKE: return "tls_handshake";
    case E_TLS_CERT:      return "tls_cert";
    case E_TLS_TIME:      return "tls_time";
    case E_CA_LOAD:       return "ca_load";
    case E_PARSE:         return "parse";
    case E_HTTP_STATUS:   return "status";
    case E_RATELIMIT:     return "ratelimit";
    default:              return "unknown";
    }
}

static void tls_extract_reason(const char *err, char *out, size_t cap)
{
    const char *p;
    size_t i, o;

    if (cap == 0) {
        return;
    }
    p = err != NULL ? strstr(err, "reason=") : NULL;
    if (p == NULL) {
        tls_copy_literal(out, cap, "unknown");
        return;
    }
    p += 7;
    for (i = 0, o = 0; p[i] != '\0' && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)p[i];

        if (c <= 0x20 || c > 0x7e || c == '"' || c == '\\') {
            break;
        }
        out[o++] = (char)c;
    }
    out[o] = '\0';
}

static int tls_line(const char *p, size_t len, size_t *line_len,
                    size_t *advance)
{
    const char *nl;

    if (p == NULL || len == 0) {
        return -1;
    }
    nl = (const char *)memchr(p, '\n', len);
    if (nl == NULL) {
        return -1;
    }
    *line_len = (size_t)(nl - p);
    if (*line_len > 0 && p[*line_len - 1] == '\r') {
        (*line_len)--;
    }
    *advance = (size_t)(nl - p) + 1;
    return 0;
}

static void tls_trim(const char **p, size_t *len)
{
    while (*len > 0 && isspace((unsigned char)**p)) {
        (*p)++;
        (*len)--;
    }
    while (*len > 0 && isspace((unsigned char)(*p)[*len - 1])) {
        (*len)--;
    }
}

static int tls_iascii_eq(const char *a, size_t alen, const char *b)
{
    size_t i;

    for (i = 0; i < alen; i++) {
        if (b[i] == '\0' ||
            tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) {
            return 0;
        }
    }
    return b[alen] == '\0';
}

static int tls_strieq(const char *a, const char *b)
{
    size_t i;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (i = 0; a[i] != '\0' && b[i] != '\0'; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) {
            return 0;
        }
    }
    return a[i] == '\0' && b[i] == '\0';
}

static int tls_iprefix(const char *s, const char *prefix)
{
    size_t i;

    if (s == NULL || prefix == NULL) {
        return 0;
    }
    for (i = 0; prefix[i] != '\0'; i++) {
        if (s[i] == '\0' ||
            tolower((unsigned char)s[i]) !=
            tolower((unsigned char)prefix[i])) {
            return 0;
        }
    }
    return 1;
}

static int tls_contains_nocase(const char *hay, size_t haylen,
                               const char *needle)
{
    size_t i, j, nlen;

    if (hay == NULL || needle == NULL) {
        return 0;
    }
    nlen = strlen(needle);
    if (nlen == 0 || nlen > haylen) {
        return 0;
    }
    for (i = 0; i + nlen <= haylen; i++) {
        for (j = 0; j < nlen; j++) {
            if (tolower((unsigned char)hay[i + j]) !=
                tolower((unsigned char)needle[j])) {
                break;
            }
        }
        if (j == nlen) {
            return 1;
        }
    }
    return 0;
}

static int tls_token_char(unsigned char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) {
        return 1;
    }
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'':
    case '*': case '+': case '-': case '.': case '^': case '_':
    case '`': case '|': case '~':
        return 1;
    default:
        return 0;
    }
}

static int tls_validate_method(const char *s)
{
    size_t i;

    if (s == NULL || s[0] == '\0') {
        return -1;
    }
    for (i = 0; s[i] != '\0'; i++) {
        if (i >= 32 || !tls_token_char((unsigned char)s[i])) {
            return -1;
        }
    }
    return 0;
}

static int tls_validate_host(const char *s)
{
    size_t i;

    if (s == NULL || s[0] == '\0' || strlen(s) >= MN_FQDN_MAX) {
        return -1;
    }
    if (s[0] == '[') {
        const char *close = strchr(s, ']');
        const char *p;

        if (close == NULL || close[1] != '\0' || close == s + 1) {
            return -1;
        }
        for (p = s + 1; p < close; p++) {
            unsigned char c = (unsigned char)*p;

            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F') || c == ':' || c == '.')) {
                return -1;
            }
        }
        return 0;
    }
    for (i = 0; s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_')) {
            return -1;
        }
    }
    return 0;
}

static int tls_validate_path(const char *s)
{
    size_t i;

    if (s == NULL || s[0] != '/') {
        return -1;
    }
    for (i = 0; s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c <= 0x20 || c >= 0x7f || c == '\\' || c == '"' || c == '#') {
            return -1;
        }
    }
    return 0;
}

/* Normalize caller-supplied CRLF/LF header lines; reject Accept-Encoding. */
static int tls_normalize_extra(const char *extra, char *out, size_t cap,
                               size_t *out_len)
{
    size_t i, j, k, o, src_len, line_len, name_len, line_end;
    const char *line, *colon;

    if (out == NULL || cap == 0) {
        return -1;
    }
    out[0] = '\0';
    *out_len = 0;
    if (extra == NULL) {
        return 0;
    }
    src_len = strlen(extra);
    o = 0;
    i = 0;
    while (i < src_len) {
        j = i;
        while (j < src_len && extra[j] != '\r' && extra[j] != '\n') {
            j++;
        }
        line_end = j;
        line = extra + i;
        line_len = line_end - i;
        if (line_len == 0) {
            return -1;
        }
        colon = (const char *)memchr(line, ':', line_len);
        if (colon == NULL) {
            return -1;
        }
        name_len = (size_t)(colon - line);
        if (name_len == 0 || name_len > 128) {
            return -1;
        }
        for (k = 0; k < line_len; k++) {
            unsigned char c = (unsigned char)line[k];

            if (c < 0x20 && c != '\t') {
                return -1;
            }
            if (c > 0x7e) {
                return -1;
            }
        }
        for (k = 0; k < name_len; k++) {
            if (!tls_token_char((unsigned char)line[k])) {
                return -1;
            }
        }
        if (tls_iascii_eq(line, name_len, "Accept-Encoding") ||
            tls_iascii_eq(line, name_len, "Content-Encoding") ||
            tls_iascii_eq(line, name_len, "Host") ||
            tls_iascii_eq(line, name_len, "Content-Length") ||
            tls_iascii_eq(line, name_len, "Transfer-Encoding") ||
            tls_iascii_eq(line, name_len, "Connection") ||
            tls_iascii_eq(line, name_len, "Proxy-Connection") ||
            tls_iascii_eq(line, name_len, "Trailer") ||
            tls_iascii_eq(line, name_len, "Upgrade") ||
            tls_iascii_eq(line, name_len, "TE")) {
            return -1;
        }
        if (o + line_len + 2 >= cap) {
            return -1;
        }
        memcpy(out + o, line, line_len);
        o += line_len;
        out[o++] = '\r';
        out[o++] = '\n';
        if (line_end < src_len && extra[line_end] == '\r') {
            if (line_end + 1 >= src_len ||
                extra[line_end + 1] != '\n') {
                return -1;
            }
            i = line_end + 2;
        } else if (line_end < src_len) {
            i = line_end + 1;
        } else {
            i = line_end;
        }
    }
    out[o] = '\0';
    *out_len = o;
    return 0;
}

/* Returns 1 found, 0 absent, -1 malformed/duplicate/truncated. */
static int tls_find_header(const char *buf, size_t len, const char *name,
                           char *out, size_t cap)
{
    size_t pos, line_len, advance, header_bytes, name_len, vlen;
    const char *line, *colon, *value;
    int found, trunc;

    if (buf == NULL || len == 0 || name == NULL || out == NULL || cap == 0) {
        return -1;
    }
    if (tls_line(buf, len, &line_len, &advance) < 0) {
        return -1;
    }
    pos = advance;
    header_bytes = advance;
    if (header_bytes > (size_t)MN_LIMIT_HEADER) {
        return -1;
    }
    found = 0;
    while (pos < len) {
        if (tls_line(buf + pos, len - pos, &line_len, &advance) < 0) {
            return -1;
        }
        if (header_bytes + advance > (size_t)MN_LIMIT_HEADER) {
            return -1;
        }
        header_bytes += advance;
        line = buf + pos;
        pos += advance;
        if (line_len == 0) {
            break;
        }
        colon = (const char *)memchr(line, ':', line_len);
        if (colon == NULL) {
            continue;
        }
        name_len = (size_t)(colon - line);
        value = colon + 1;
        vlen = line_len - name_len - 1;
        tls_trim(&value, &vlen);
        if (!tls_iascii_eq(line, name_len, name)) {
            continue;
        }
        if (found) {
            return -1;
        }
        found = 1;
        if (tls_copy_slice(out, cap, value, vlen, &trunc) < 0 || trunc) {
            return -1;
        }
    }
    return found ? 1 : 0;
}

static void tls_debug_dump_headers(const char *direction, const char *host,
                                   const char *buf, size_t len)
{
    size_t pos, line_len, advance, header_bytes, name_len, vlen, hlen;
    const char *line, *colon, *value;
    char safehost[MN_TLS_LOG_VALUE_CAP];
    char safe_a[MN_TLS_LOG_VALUE_CAP];
    char safe_b[MN_TLS_LOG_VALUE_CAP];

    if (mn_log_get_level() < MN_LOG_DEBUG || buf == NULL || len == 0) {
        return;
    }
    hlen = host != NULL ? strlen(host) : 0;
    tls_sanitize_log(host != NULL ? host : "-", hlen,
                     safehost, sizeof safehost);
    pos = 0;
    header_bytes = 0;
    while (pos < len && header_bytes < (size_t)MN_LIMIT_HEADER) {
        if (tls_line(buf + pos, len - pos, &line_len, &advance) < 0) {
            break;
        }
        header_bytes += advance;
        line = buf + pos;
        pos += advance;
        if (line_len == 0) {
            break;
        }
        colon = (const char *)memchr(line, ':', line_len);
        if (colon == NULL) {
            tls_sanitize_log(line, line_len, safe_a, sizeof safe_a);
            mn_log(MN_LOG_DEBUG,
                   "http headers direction=%s url_host=%s header=\"%s\"",
                   direction, safehost, safe_a);
            continue;
        }
        name_len = (size_t)(colon - line);
        value = colon + 1;
        vlen = line_len - name_len - 1;
        tls_trim(&value, &vlen);
        if (tls_iascii_eq(line, name_len, "Cookie") ||
            tls_iascii_eq(line, name_len, "Set-Cookie")) {
            continue;
        }
        if (tls_iascii_eq(line, name_len, "Authorization")) {
            mn_log(MN_LOG_DEBUG,
                   "http headers direction=%s url_host=%s "
                   "header=\"Authorization: Bearer ****\"",
                   direction, safehost);
            continue;
        }
        if (tls_contains_nocase(line, name_len, "auth") ||
            tls_contains_nocase(line, name_len, "token") ||
            tls_contains_nocase(line, name_len, "cookie")) {
            tls_sanitize_log(line, name_len, safe_a, sizeof safe_a);
            mn_log(MN_LOG_DEBUG,
                   "http headers direction=%s url_host=%s header=\"%s: ****\"",
                   direction, safehost, safe_a);
            continue;
        }
        tls_sanitize_log(line, name_len, safe_a, sizeof safe_a);
        tls_sanitize_log(value, vlen, safe_b, sizeof safe_b);
        mn_log(MN_LOG_DEBUG,
               "http headers direction=%s url_host=%s header=\"%s: %s\"",
               direction, safehost, safe_a, safe_b);
    }
}

/* ---- pure HTTP response parser -------------------------------------------- */

static int tls_parse_fail(struct mn_http_result *out, int *errcode,
                          char *err, size_t errlen, const char *why)
{
    int saved_status = out != NULL ? out->status : 0;

    if (out != NULL) {
        mn_http_result_free(out);
        out->status = saved_status;
        out->retry_after_secs = -1;
    }
    if (errcode != NULL) {
        *errcode = E_PARSE;
    }
    tls_set_err(err, errlen, "reason=%s", why);
    return E_PARSE;
}

static int tls_parse_content_length(const char *p, size_t len, uint64_t *out)
{
    uint64_t v;
    size_t i;
    unsigned d;

    if (len == 0) {
        return -1;
    }
    v = 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)p[i];

        if (c < '0' || c > '9') {
            return -1;
        }
        d = (unsigned)(c - '0');
        if (v > (UINT64_MAX - d) / 10u) {
            return -1;
        }
        v = v * 10u + d;
    }
    *out = v;
    return 0;
}

static int tls_body_reserve(struct mn_http_result *out, size_t *cap,
                            size_t need, const char **why)
{
    char *p;
    size_t ncap;
    const size_t maxcap = (size_t)MN_LIMIT_BODY + 1;

    if (need > maxcap) {
        *why = "body_too_large";
        return -1;
    }
    if (need <= *cap) {
        return 0;
    }
    ncap = *cap != 0 ? *cap : 4096;
    while (ncap < need) {
        if (ncap > maxcap / 2) {
            ncap = maxcap;
            break;
        }
        ncap *= 2;
    }
    if (ncap > maxcap) {
        ncap = maxcap;
    }
    p = (char *)realloc(out->body, ncap);
    if (p == NULL) {
        *why = "out_of_memory";
        return -1;
    }
    out->body = p;
    *cap = ncap;
    return 0;
}

static int tls_body_append(struct mn_http_result *out, size_t *cap,
                           const char *src, size_t len, const char **why)
{
    size_t need;

    if (len > (size_t)MN_LIMIT_BODY - out->body_len) {
        *why = "body_too_large";
        return -1;
    }
    need = out->body_len + len + 1;
    if (tls_body_reserve(out, cap, need, why) < 0) {
        return -1;
    }
    if (len > 0) {
        memcpy(out->body + out->body_len, src, len);
    }
    out->body_len += len;
    out->body[out->body_len] = '\0';
    return 0;
}

static int tls_parse_chunk_size(const char *line, size_t len, size_t *size,
                                const char **why)
{
    uint64_t v;
    size_t i;
    unsigned d;

    if (len == 0 || len > 1024) {
        *why = "bad_chunk";
        return -1;
    }
    v = 0;
    i = 0;
    while (i < len && isxdigit((unsigned char)line[i])) {
        unsigned char c = (unsigned char)line[i];

        if (c >= '0' && c <= '9') {
            d = (unsigned)(c - '0');
        } else {
            d = (unsigned)(tolower(c) - 'a' + 10);
        }
        if (v > (UINT64_MAX - d) / 16u) {
            *why = "bad_chunk";
            return -1;
        }
        v = v * 16u + d;
        i++;
    }
    if (i == 0 || (i < len && line[i] != ';')) {
        *why = "bad_chunk";
        return -1;
    }
    for (; i < len; i++) {
        unsigned char c = (unsigned char)line[i];

        if (c < 0x20 || c > 0x7e) {
            *why = "bad_chunk";
            return -1;
        }
    }
    if (v > (size_t)MN_LIMIT_BODY) {
        *why = "body_too_large";
        return -1;
    }
    *size = (size_t)v;
    return 0;
}

static int tls_decode_chunked(const char *p, size_t len,
                              struct mn_http_result *out, const char **why)
{
    size_t pos, line_len, advance, chunk, after, sep, cap;

    out->body = (char *)malloc(1);
    if (out->body == NULL) {
        *why = "out_of_memory";
        return -1;
    }
    out->body[0] = '\0';
    out->body_len = 0;
    cap = 1;
    pos = 0;
    for (;;) {
        if (pos >= len) {
            *why = "incomplete_body";
            return -1;
        }
        if (tls_line(p + pos, len - pos, &line_len, &advance) < 0) {
            *why = "incomplete_body";
            return -1;
        }
        if (tls_parse_chunk_size(p + pos, line_len, &chunk, why) < 0) {
            return -1;
        }
        pos += advance;
        if (chunk == 0) {
            for (;;) {
                if (pos >= len) {
                    *why = "incomplete_body";
                    return -1;
                }
                if (tls_line(p + pos, len - pos,
                             &line_len, &advance) < 0) {
                    *why = "incomplete_body";
                    return -1;
                }
                pos += advance;
                if (line_len == 0) {
                    out->body[out->body_len] = '\0';
                    return 0;
                }
            }
        }
        if (chunk > (size_t)MN_LIMIT_BODY - out->body_len) {
            *why = "body_too_large";
            return -1;
        }
        if (len - pos < chunk) {
            *why = "incomplete_body";
            return -1;
        }
        after = pos + chunk;
        if (after >= len) {
            *why = "incomplete_body";
            return -1;
        }
        if (p[after] == '\r') {
            if (after + 1 >= len) {
                *why = "incomplete_body";
                return -1;
            }
            if (p[after + 1] != '\n') {
                *why = "bad_chunk";
                return -1;
            }
            sep = 2;
        } else if (p[after] == '\n') {
            sep = 1;
        } else {
            *why = "bad_chunk";
            return -1;
        }
        if (tls_body_append(out, &cap, p + pos, chunk, why) < 0) {
            return -1;
        }
        pos = after + sep;
    }
}

int mn_http_parse_raw(const char *buf, size_t len,
                      struct mn_http_result *out, int *errcode,
                      char *err, size_t errlen)
{
    size_t pos, line_len, advance, header_bytes, body_start, available, n;
    size_t name_len, vlen;
    const char *line, *colon, *value;
    uint64_t cl, cl_first;
    int has_cl, cl_bad, chunked, te_seen;
    int status;
    const char *why = "unknown";
    char tmp[256];
    int trunc;

    if (errcode != NULL) {
        *errcode = MN_OK;
    }
    tls_err_clear(err, errlen);
    tls_result_init(out);
    if (out == NULL) {
        return tls_parse_fail(out, errcode, err, errlen, "bad_status_line");
    }
    if (buf == NULL || len == 0) {
        return tls_parse_fail(out, errcode, err, errlen, "bad_status_line");
    }
    if (tls_line(buf, len, &line_len, &advance) < 0) {
        if (len >= (size_t)MN_LIMIT_HEADER) {
            return tls_parse_fail(out, errcode, err, errlen,
                                  "header_too_large");
        }
        if (len < 7 || memcmp(buf, "HTTP/1.", 7) != 0) {
            return tls_parse_fail(out, errcode, err, errlen,
                                  "bad_status_line");
        }
        return tls_parse_fail(out, errcode, err, errlen,
                              "incomplete_headers");
    }
    if (line_len >= (size_t)MN_LIMIT_HEADER) {
        return tls_parse_fail(out, errcode, err, errlen, "header_too_large");
    }
    line = buf;
    if (line_len < 12 || memcmp(line, "HTTP/1.", 7) != 0 ||
        !isdigit((unsigned char)line[7]) || line[8] != ' ' ||
        !isdigit((unsigned char)line[9]) ||
        !isdigit((unsigned char)line[10]) ||
        !isdigit((unsigned char)line[11]) ||
        (line_len > 12 && line[12] != ' ')) {
        return tls_parse_fail(out, errcode, err, errlen, "bad_status_line");
    }
    status = (line[9] - '0') * 100 + (line[10] - '0') * 10 +
             (line[11] - '0');
    out->status = status;
    pos = advance;
    header_bytes = advance;

    has_cl = 0;
    cl_bad = 0;
    cl = 0;
    cl_first = 0;
    chunked = 0;
    te_seen = 0;
    for (;;) {
        if (pos >= len) {
            return tls_parse_fail(out, errcode, err, errlen,
                                  "incomplete_headers");
        }
        if (tls_line(buf + pos, len - pos, &line_len, &advance) < 0) {
            if (header_bytes + (len - pos) > (size_t)MN_LIMIT_HEADER) {
                return tls_parse_fail(out, errcode, err, errlen,
                                      "header_too_large");
            }
            return tls_parse_fail(out, errcode, err, errlen,
                                  "incomplete_headers");
        }
        if (header_bytes + advance > (size_t)MN_LIMIT_HEADER) {
            return tls_parse_fail(out, errcode, err, errlen,
                                  "header_too_large");
        }
        header_bytes += advance;
        line = buf + pos;
        pos += advance;
        if (line_len == 0) {
            body_start = pos;
            break;
        }
        colon = (const char *)memchr(line, ':', line_len);
        if (colon == NULL) {
            continue;
        }
        name_len = (size_t)(colon - line);
        value = colon + 1;
        vlen = line_len - name_len - 1;
        tls_trim(&value, &vlen);
        if (tls_iascii_eq(line, name_len, "Content-Length")) {
            uint64_t parsed;

            if (tls_parse_content_length(value, vlen, &parsed) < 0) {
                cl_bad = 1;
            } else {
                if (!has_cl) {
                    cl_first = parsed;
                    cl = parsed;
                    has_cl = 1;
                } else if (parsed != cl_first) {
                    cl_bad = 1;
                }
            }
        } else if (tls_iascii_eq(line, name_len, "Transfer-Encoding")) {
            if (te_seen || !tls_iascii_eq(value, vlen, "chunked")) {
                return tls_parse_fail(out, errcode, err, errlen,
                                      "transfer_encoding");
            }
            te_seen = 1;
            chunked = 1;
        } else if (tls_iascii_eq(line, name_len, "Content-Encoding")) {
            if (!tls_iascii_eq(value, vlen, "identity")) {
                return tls_parse_fail(out, errcode, err, errlen,
                                      "encoded_body");
            }
        } else if (tls_iascii_eq(line, name_len, "Retry-After")) {
            if (tls_copy_slice(tmp, sizeof tmp, value, vlen, &trunc) < 0 ||
                trunc) {
                out->retry_after_secs = -1;
            } else {
                out->retry_after_secs =
                    mn_retry_after_seconds(tmp, mn_wall());
            }
        } else if (tls_iascii_eq(line, name_len, "Content-Type")) {
            (void)tls_copy_slice(out->content_type,
                                 sizeof out->content_type,
                                 value, vlen, &trunc);
        }
    }
    if (cl_bad && !chunked) {
        return tls_parse_fail(out, errcode, err, errlen,
                              "bad_content_length");
    }
    available = len - body_start;
    if (chunked) {
        if (tls_decode_chunked(buf + body_start, available, out, &why) < 0) {
            return tls_parse_fail(out, errcode, err, errlen, why);
        }
    } else if (has_cl) {
        if (cl > (size_t)MN_LIMIT_BODY) {
            return tls_parse_fail(out, errcode, err, errlen,
                                  "body_too_large");
        }
        n = (size_t)cl;
        if (available < n) {
            return tls_parse_fail(out, errcode, err, errlen,
                                  "incomplete_body");
        }
        out->body = (char *)malloc(n + 1);
        if (out->body == NULL) {
            return tls_parse_fail(out, errcode, err, errlen,
                                  "out_of_memory");
        }
        if (n > 0) {
            memcpy(out->body, buf + body_start, n);
        }
        out->body[n] = '\0';
        out->body_len = n;
    } else {
        if (available > (size_t)MN_LIMIT_BODY) {
            return tls_parse_fail(out, errcode, err, errlen,
                                  "body_too_large");
        }
        out->body = (char *)malloc(available + 1);
        if (out->body == NULL) {
            return tls_parse_fail(out, errcode, err, errlen,
                                  "out_of_memory");
        }
        if (available > 0) {
            memcpy(out->body, buf + body_start, available);
        }
        out->body[available] = '\0';
        out->body_len = available;
    }
    if (errcode != NULL) {
        *errcode = MN_OK;
    }
    tls_err_clear(err, errlen);
    return MN_OK;
}

/* ---- URL/redirect whitelist (§06.2) --------------------------------------- */

static int tls_parse_port(const char *s, int *port)
{
    unsigned v;
    size_t i;

    if (s == NULL || s[0] == '\0') {
        return -1;
    }
    v = 0;
    for (i = 0; s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c < '0' || c > '9') {
            return -1;
        }
        v = v * 10u + (unsigned)(c - '0');
        if (v > 65535u) {
            return -1;
        }
    }
    *port = (int)v;
    return 0;
}

static int tls_parse_https_url(const char *url, char *host, size_t hostcap,
                               char *path, size_t pathcap, int *port,
                               int allow_non443)
{
    char authority[MN_FQDN_MAX + 16];
    const char *auth, *end, *path_str;
    const char *colon;
    size_t auth_len;
    int p, trunc;

    if (url == NULL || host == NULL || hostcap == 0 ||
        !tls_iprefix(url, "https://")) {
        return -1;
    }
    auth = url + 8;
    end = auth;
    while (*end != '\0' && *end != '/' && *end != '?' && *end != '#') {
        end++;
    }
    if (*end == '?' || *end == '#') {
        return -1;
    }
    auth_len = (size_t)(end - auth);
    if (auth_len == 0 || auth_len >= sizeof authority) {
        return -1;
    }
    if (tls_copy_slice(authority, sizeof authority, auth, auth_len,
                       &trunc) < 0 || trunc) {
        return -1;
    }
    if (authority[0] == '[' || strchr(authority, '@') != NULL) {
        return -1;
    }
    colon = strchr(authority, ':');
    p = 443;
    if (colon != NULL) {
        char *first_colon = (char *)colon;
        const char *port_str = colon + 1;

        if (strchr(port_str, ':') != NULL ||
            tls_parse_port(port_str, &p) < 0) {
            return -1;
        }
        *first_colon = '\0';
    }
    if (!allow_non443 && p != 443) {
        return -1;
    }
    if (tls_validate_host(authority) < 0 ||
        tls_copy_cstr(host, hostcap, authority) < 0) {
        return -1;
    }
    path_str = *end == '/' ? end : "/";
    if (tls_validate_path(path_str) < 0) {
        return -1;
    }
    if (path != NULL && pathcap > 0 &&
        tls_copy_cstr(path, pathcap, path_str) < 0) {
        return -1;
    }
    if (port != NULL) {
        *port = p;
    }
    return 0;
}

static int tls_host_in_echo_urls(const struct mn_cfg *cfg, const char *host)
{
    const char *p;
    char url[1024 + 1];
    char whost[MN_FQDN_MAX];
    int port, trunc;

    if (cfg == NULL || host == NULL) {
        return 0;
    }
    p = cfg->detect.ipv4_echo_url;
    while (*p != '\0') {
        const char *start;
        size_t len;

        while (*p == ',' || isspace((unsigned char)*p)) {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        len = (size_t)(p - start);
        tls_trim(&start, &len);
        if (len > 0) {
            if (tls_copy_slice(url, sizeof url, start, len, &trunc) == 0 &&
                !trunc &&
                tls_parse_https_url(url, whost, sizeof whost,
                                    NULL, 0, &port, 1) == 0 &&
                tls_strieq(whost, host)) {
                return 1;
            }
        }
        if (*p == ',') {
            p++;
        }
    }
    return 0;
}

static int tls_redirect_allowed(const struct mn_cfg *cfg,
                                const char *location,
                                char *host, size_t hostcap,
                                char *path, size_t pathcap)
{
    char loc_host[MN_FQDN_MAX];
    char loc_path[MN_TLS_PATH_CAP];
    int port;

    if (cfg == NULL || location == NULL || host == NULL || path == NULL) {
        return -1;
    }
    if (tls_parse_https_url(location, loc_host, sizeof loc_host,
                            loc_path, sizeof loc_path, &port, 0) < 0 ||
        port != 443) {
        return -1;
    }
    if (!tls_host_in_echo_urls(cfg, loc_host)) {
        return -1;
    }
    if (tls_copy_cstr(host, hostcap, loc_host) < 0 ||
        tls_copy_cstr(path, pathcap, loc_path) < 0) {
        return -1;
    }
    return 0;
}

/* ---- sockets and BearSSL --------------------------------------------------- */

struct mn_tls {
    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    br_sslio_context ioc;
    unsigned char iobuf[MN_TLS_IOBUF];
    int fd;
    int64_t deadline;
    int timeout;
    int io_error;
    int eof;
};

static int tls_http_timeout_ms(const struct mn_cfg *cfg)
{
    if (cfg != NULL && cfg->core.http_timeout_ms > 0) {
        return cfg->core.http_timeout_ms;
    }
    return MN_TLS_DEFAULT_HTTP_MS;
}

static int tls_connect_timeout_ms(const struct mn_cfg *cfg)
{
    if (cfg != NULL && cfg->core.connect_timeout_ms > 0) {
        return cfg->core.connect_timeout_ms;
    }
    return MN_TLS_DEFAULT_CONNECT_MS;
}

static int tls_clamp_ms(int64_t ms)
{
    if (ms <= 0) {
        return 0;
    }
    if (ms > (int64_t)INT_MAX) {
        return INT_MAX;
    }
    return (int)ms;
}

static void tls_set_socket_timeouts(int fd, int64_t deadline)
{
    struct timeval tv;
    int64_t left = deadline - mn_now_ms();

    if (left < 1) {
        left = 1;
    }
    tv.tv_sec = (time_t)(left / 1000);
    tv.tv_usec = (suseconds_t)((left % 1000) * 1000);
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

static int tls_remaining_ms(struct mn_tls *t)
{
    int64_t left = t->deadline - mn_now_ms();

    if (left <= 0) {
        t->timeout = 1;
        return 0;
    }
    return tls_clamp_ms(left);
}

static int tls_wait_socket(struct mn_tls *t, short events)
{
    struct pollfd pfd;
    int ms, pr;

    for (;;) {
        ms = tls_remaining_ms(t);
        if (ms <= 0) {
            return -1;
        }
        tls_set_socket_timeouts(t->fd, t->deadline);
        pfd.fd = t->fd;
        pfd.events = events;
        pfd.revents = 0;
        pr = poll(&pfd, 1, ms);
        if (pr > 0) {
            return 0;
        }
        if (pr == 0) {
            t->timeout = 1;
            return -1;
        }
        if (errno == EINTR) {
            continue;
        }
        t->io_error = 1;
        return -1;
    }
}

static int tls_raw_read(struct mn_tls *t, unsigned char *dst, size_t len)
{
    ssize_t n;

    if (tls_wait_socket(t, POLLIN) < 0) {
        return -1;
    }
    for (;;) {
        n = recv(t->fd, dst, len, 0);
        if (n > 0) {
            return (int)n;
        }
        if (n == 0) {
            t->eof = 1;
            return -1;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (tls_wait_socket(t, POLLIN) < 0) {
                return -1;
            }
            continue;
        }
        t->io_error = 1;
        return -1;
    }
}

static int tls_raw_write(struct mn_tls *t, const unsigned char *src, size_t len)
{
    ssize_t n;
    int flags;

#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#else
    flags = 0;
#endif
    if (tls_wait_socket(t, POLLOUT) < 0) {
        return -1;
    }
    for (;;) {
        n = send(t->fd, src, len, flags);
        if (n > 0) {
            return (int)n;
        }
        if (n == 0) {
            t->io_error = 1;
            return -1;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (tls_wait_socket(t, POLLOUT) < 0) {
                return -1;
            }
            continue;
        }
        t->io_error = 1;
        return -1;
    }
}

static int tls_low_read(void *ctx, unsigned char *dst, size_t len)
{
    return tls_raw_read((struct mn_tls *)ctx, dst, len);
}

static int tls_low_write(void *ctx, const unsigned char *src, size_t len)
{
    return tls_raw_write((struct mn_tls *)ctx, src, len);
}

static int tls_connect(const struct mn_cfg *cfg, const char *host, int port,
                       int64_t deadline, int *fd_out, int64_t *deadline_out,
                       char *err, size_t errlen,
                       char *reason, size_t reasoncap)
{
    struct addrinfo hints, *res, *ai;
    char portstr[16], detail[160];
    const char *why = "connect";
    int rc, r, ga, last_rc, successes, soerr = 0;
    int64_t connect_deadline, left;
    socklen_t slen;

    *fd_out = -1;
    if (deadline_out != NULL) *deadline_out = 0;
    if (port <= 0 || port > 65535) {
        tls_copy_literal(reason, reasoncap, "bad_port");
        tls_set_err(err, errlen, "reason=bad_port");
        return E_PARSE;
    }
    r = snprintf(portstr, sizeof portstr, "%d", port);
    if (!tls_snprintf_ok(r, sizeof portstr)) {
        tls_copy_literal(reason, reasoncap, "bad_port");
        tls_set_err(err, errlen, "reason=bad_port");
        return E_PARSE;
    }
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    ga = getaddrinfo(host, portstr, &hints, &res);
    if (ga != 0) {
        tls_copy_literal(reason, reasoncap, "dns");
        tls_set_err(err, errlen, "getaddrinfo host=%s: %s reason=dns",
                    host, gai_strerror(ga));
        return E_DNS;
    }
    tls_copy_literal(detail, sizeof detail, "no usable address");
    last_rc = E_CONNECT;
    successes = 0;
    for (ai = res; ai != NULL && successes < MN_MAX_ADDRS;
         ai = ai->ai_next, successes++) {
        int fd, fl, cr, pr, wait;
        int64_t connect_ms = tls_connect_timeout_ms(cfg);

        left = deadline - mn_now_ms();
        if (left <= 0) {
            last_rc = E_TIMEOUT;
            break;
        }
        connect_deadline = mn_now_ms() + connect_ms;
        if (connect_deadline > deadline) {
            connect_deadline = deadline;
        }
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            tls_copy_literal(detail, sizeof detail, strerror(errno));
            last_rc = E_CONNECT;
            continue;
        }
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
        fl = fcntl(fd, F_GETFL, 0);
        if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
            close(fd);
            tls_copy_literal(detail, sizeof detail, "O_NONBLOCK failed");
            last_rc = E_CONNECT;
            continue;
        }
        cr = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (cr == 0) {
            pr = 1;
            soerr = 0;
        } else if (errno == EINPROGRESS || errno == EALREADY ||
                   errno == EINTR) {
            pr = 0;
            for (;;) {
                left = connect_deadline - mn_now_ms();
                wait = tls_clamp_ms(left);
                if (wait <= 0) {
                    pr = 0;
                    last_rc = E_TIMEOUT;
                    break;
                }
                {
                    struct pollfd pfd;

                    pfd.fd = fd;
                    pfd.events = POLLOUT;
                    pfd.revents = 0;
                    pr = poll(&pfd, 1, wait);
                }
                if (pr > 0) {
                    soerr = 0;
                    slen = sizeof soerr;
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
                                   &soerr, &slen) < 0) {
                        soerr = errno;
                    }
                    break;
                }
                if (pr == 0) {
                    last_rc = E_TIMEOUT;
                    break;
                }
                if (errno == EINTR) {
                    continue;
                }
                soerr = errno;
                last_rc = E_CONNECT;
                break;
            }
        } else {
            soerr = errno;
            pr = -1;
            last_rc = E_CONNECT;
        }
        if (pr <= 0 || soerr != 0) {
            if (soerr != 0) {
                tls_copy_literal(detail, sizeof detail, strerror(soerr));
            } else if (last_rc == E_TIMEOUT) {
                tls_copy_literal(detail, sizeof detail, "connect timed out");
            }
            close(fd);
            if (last_rc == E_TIMEOUT && deadline - mn_now_ms() <= 0) {
                break;
            }
            continue;
        }
        fl = fcntl(fd, F_GETFL, 0);
        if (fl < 0 || fcntl(fd, F_SETFL, fl & ~O_NONBLOCK) < 0) {
            close(fd);
            tls_copy_literal(detail, sizeof detail, "blocking mode failed");
            last_rc = E_CONNECT;
            continue;
        }
        tls_set_socket_timeouts(fd, deadline);
        *fd_out = fd;
        if (deadline_out != NULL) *deadline_out = connect_deadline;
        freeaddrinfo(res);
        return MN_OK;
    }
    freeaddrinfo(res);
    why = last_rc == E_TIMEOUT ? "timeout" : "connect";
    tls_copy_literal(reason, reasoncap, why);
    rc = last_rc == E_TIMEOUT ? E_TIMEOUT : E_CONNECT;
    tls_set_err(err, errlen, "connect host=%s: %s reason=%s",
                host, detail, why);
    return rc;
}

static int tls_setup(struct mn_tls *t,
                     const br_x509_trust_anchor *anchors, size_t n,
                     const char *host)
{
    int64_t wall;
    uint32_t days, seconds;

    /*
     * BearSSL 0.6 has no br_x509_minimal_set_trust_anchors(); init_full()
     * installs the anchors through br_x509_minimal_init() before any reset.
     */
    br_ssl_client_init_full(&t->sc, &t->xc, anchors, n);
    /* §08.1: never negotiate TLS 1.0/1.1. */
    br_ssl_engine_set_versions(&t->sc.eng, BR_TLS12, BR_TLS12);
    br_x509_minimal_set_hash(&t->xc, br_sha1_ID, &br_sha1_vtable);
    br_x509_minimal_set_hash(&t->xc, br_sha256_ID, &br_sha256_vtable);
    br_x509_minimal_set_hash(&t->xc, br_sha384_ID, &br_sha384_vtable);
    br_x509_minimal_set_hash(&t->xc, br_sha512_ID, &br_sha512_vtable);
    br_x509_minimal_set_rsa(&t->xc, br_rsa_i31_pkcs1_vrfy);
    br_x509_minimal_set_ecdsa(&t->xc, br_ec_get_default(),
                              br_ecdsa_i31_vrfy_asn1);
    wall = (int64_t)mn_wall();
    if (wall < 0) {
        wall = 0;
    }
    days = (uint32_t)(wall / 86400) + MN_TLS_DAYS_TO_EPOCH;
    seconds = (uint32_t)(wall % 86400);
    br_x509_minimal_set_time(&t->xc, days, seconds);
    br_ssl_engine_set_buffer(&t->sc.eng, t->iobuf, sizeof t->iobuf, 1);
    return br_ssl_client_reset(&t->sc, host, 0) ? 0 : -1;
}

static int tls_map_br_error(int e)
{
    if (e == BR_ERR_X509_EXPIRED || e == BR_ERR_X509_TIME_UNKNOWN ||
        e == BR_ERR_X509_BAD_TIME) {
        return E_TLS_TIME;
    }
    if (e >= BR_ERR_X509_OK && e <= BR_ERR_X509_NOT_TRUSTED) {
        return E_TLS_CERT;
    }
    /* BR_ERR_IO and every non-X.509 engine failure stay handshake failures. */
    return E_TLS_HANDSHAKE;
}

static int tls_failure_rc(struct mn_tls *t)
{
    int e;

    if (t->timeout) {
        return E_TIMEOUT;
    }
    e = br_ssl_engine_last_error(&t->sc.eng);
    if (e != 0) {
        return tls_map_br_error(e);
    }
    return E_TLS_HANDSHAKE;
}

static void tls_zero_secret(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;

    while (n-- > 0) {
        *q++ = 0;
    }
}

static int tls_cipher_name(uint16_t suite, char *cipher, size_t cap)
{
    const char *name = NULL;
    int r;

    if (cipher == NULL || cap == 0) {
        return -1;
    }
    switch (suite) {
    case BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        name = "ECDHE_RSA_AES128_GCM";
        break;
    case BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        name = "ECDHE_RSA_AES256_GCM";
        break;
    case BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        name = "ECDHE_ECDSA_AES128_GCM";
        break;
    case BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        name = "ECDHE_ECDSA_AES256_GCM";
        break;
    case BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        name = "ECDHE_RSA_CHACHA20_POLY1305";
        break;
    case BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        name = "ECDHE_ECDSA_CHACHA20_POLY1305";
        break;
    case BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        name = "ECDHE_RSA_AES128_CBC_SHA256";
        break;
    case BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        name = "ECDHE_RSA_AES256_CBC_SHA384";
        break;
    case BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        name = "ECDHE_RSA_AES128_CBC_SHA";
        break;
    case BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        name = "ECDHE_RSA_AES256_CBC_SHA";
        break;
    case BR_TLS_RSA_WITH_AES_128_GCM_SHA256:
        name = "RSA_AES128_GCM";
        break;
    case BR_TLS_RSA_WITH_AES_256_GCM_SHA384:
        name = "RSA_AES256_GCM";
        break;
    default:
        break;
    }
    if (name != NULL) {
        r = snprintf(cipher, cap, "%s", name);
    } else {
        r = snprintf(cipher, cap, "0x%04x", (unsigned)suite);
    }
    if (!tls_snprintf_ok(r, cap)) {
        cipher[0] = '\0';
        return -1;
    }
    return 0;
}

static int tls_pump_handshake(struct mn_tls *t)
{
    unsigned loops = 0;

    for (;;) {
        unsigned state;
        unsigned char *buf;
        size_t len;
        int n;

        if (t->timeout) {
            return E_TIMEOUT;
        }
        if (++loops > 100000u) {
            return E_TLS_HANDSHAKE;
        }
        state = br_ssl_engine_current_state(&t->sc.eng);
        if (state & BR_SSL_CLOSED) {
            return tls_failure_rc(t);
        }
        if (state & BR_SSL_SENDREC) {
            buf = br_ssl_engine_sendrec_buf(&t->sc.eng, &len);
            if (buf == NULL || len == 0) {
                return E_TLS_HANDSHAKE;
            }
            n = tls_raw_write(t, buf, len);
            if (n <= 0) {
                return tls_failure_rc(t);
            }
            br_ssl_engine_sendrec_ack(&t->sc.eng, (size_t)n);
            continue;
        }
        /* BearSSL's SENDAPP|RECVAPP target matches either state flag. */
        if (state & (BR_SSL_SENDAPP | BR_SSL_RECVAPP)) {
            return MN_OK;
        }
        if (state & BR_SSL_RECVREC) {
            buf = br_ssl_engine_recvrec_buf(&t->sc.eng, &len);
            if (buf == NULL || len == 0) {
                return E_TLS_HANDSHAKE;
            }
            n = tls_raw_read(t, buf, len);
            if (n <= 0) {
                return tls_failure_rc(t);
            }
            br_ssl_engine_recvrec_ack(&t->sc.eng, (size_t)n);
            continue;
        }
        return E_TLS_HANDSHAKE;
    }
}

/* ---- one HTTP request ------------------------------------------------------ */

struct tls_req_args {
    const struct mn_cfg *cfg;
    const br_x509_trust_anchor *anchors;
    size_t n_anchors;
    int64_t deadline;
    const char *method;
    const char *host;
    const char *path;
    const char *body;
    const char *extra;
    int port;
    int want_json;
};

static int tls_resp_append(char **buf, size_t *len, size_t *cap,
                           const unsigned char *src, size_t n)
{
    size_t need, ncap, maxcap = MN_TLS_RESP_CAP + 1;
    char *p;

    if (n > MN_TLS_RESP_CAP - *len) {
        return -1;
    }
    need = *len + n + 1;
    if (need > maxcap) {
        return -1;
    }
    if (need > *cap) {
        ncap = *cap != 0 ? *cap : 4096;
        while (ncap < need) {
            if (ncap > maxcap / 2) {
                ncap = maxcap;
                break;
            }
            ncap *= 2;
        }
        if (ncap > maxcap) {
            ncap = maxcap;
        }
        p = (char *)realloc(*buf, ncap);
        if (p == NULL) {
            return -1;
        }
        *buf = p;
        *cap = ncap;
    }
    if (n > 0) {
        memcpy(*buf + *len, src, n);
    }
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

static int tls_one_fail(int rc, const char *why, char *reason,
                        size_t reasoncap, char *err, size_t errlen,
                        int *errcode)
{
    tls_copy_literal(reason, reasoncap, why);
    tls_set_err(err, errlen, "reason=%s", why);
    if (errcode != NULL) {
        *errcode = rc;
    }
    return rc;
}

/* Return 1 when the response is complete, 0 when more bytes are needed,
   -1 when the body is close-delimited (EOF required), and -2 for a framing
   error that the full parser should report.  Used to stop reading as soon as
   Content-Length/chunked framing is satisfied (§08.3). */
static int tls_response_complete(const char *buf, size_t len)
{
    size_t pos = 0, line_len, advance, header_bytes = 0, body_start = 0;
    int has_cl = 0, chunked = 0, te_seen = 0;
    uint64_t cl = 0;

    if (len == 0) return 0;
    if (tls_line(buf, len, &line_len, &advance) < 0)
        return len >= (size_t)MN_LIMIT_HEADER ? -2 : 0;
    header_bytes = advance;
    pos = advance;

    for (;;) {
        const char *line, *colon, *value;
        size_t name_len, vlen;

        if (pos >= len) return 0;
        if (tls_line(buf + pos, len - pos, &line_len, &advance) < 0) {
            if (header_bytes + (len - pos) > (size_t)MN_LIMIT_HEADER)
                return -2;
            return 0;
        }
        if (header_bytes + advance > (size_t)MN_LIMIT_HEADER)
            return -2;
        header_bytes += advance;
        line = buf + pos;
        pos += advance;
        if (line_len == 0) {
            body_start = pos;
            break;
        }
        colon = (const char *)memchr(line, ':', line_len);
        if (colon == NULL) continue;
        name_len = (size_t)(colon - line);
        value = colon + 1;
        vlen = line_len - name_len - 1;
        tls_trim(&value, &vlen);

        if (tls_iascii_eq(line, name_len, "Content-Length")) {
            uint64_t parsed;
            if (tls_parse_content_length(value, vlen, &parsed) < 0)
                return -2;
            if (!has_cl) {
                cl = parsed;
                has_cl = 1;
            } else if (parsed != cl) {
                return -2;
            }
        } else if (tls_iascii_eq(line, name_len, "Transfer-Encoding")) {
            if (te_seen || !tls_iascii_eq(value, vlen, "chunked"))
                return -2;
            te_seen = 1;
            chunked = 1;
        } else if (tls_iascii_eq(line, name_len, "Content-Encoding")) {
            if (!tls_iascii_eq(value, vlen, "identity"))
                return -2;
        }
    }

    if (chunked) {
        size_t p = body_start;
        for (;;) {
            const char *why = "bad_chunk";
            size_t chunk;

            if (p >= len) return 0;
            if (tls_line(buf + p, len - p, &line_len, &advance) < 0)
                return 0;
            if (tls_parse_chunk_size(buf + p, line_len, &chunk, &why) < 0)
                return -2;
            p += advance;
            if (chunk == 0) {
                for (;;) {
                    if (p >= len) return 0;
                    if (tls_line(buf + p, len - p, &line_len, &advance) < 0)
                        return 0;
                    p += advance;
                    if (line_len == 0) return 1;
                }
            }
            if (chunk > len - p) return 0;
            p += chunk;
            if (len - p < 2) return 0;
            if (buf[p] != '\r' || buf[p + 1] != '\n') return -2;
            p += 2;
        }
    }
    if (has_cl) {
        if (cl > (size_t)MN_LIMIT_BODY) return -2;
        if (len - body_start < (size_t)cl) return 0;
        return 1;
    }
    return -1;
}

static int tls_one_request(const struct tls_req_args *args,
                           char **raw_out, size_t *raw_len,
                           struct mn_http_result *out,
                           char *reason, size_t reasoncap,
                           char *err, size_t errlen, int *errcode)
{
    char headers[MN_TLS_REQ_HEADER_CAP];
    char extra_norm[MN_TLS_EXTRA_CAP];
    char creason[MN_TLS_REASON_CAP];
    char *wire, *resp;
    const char *body, *why;
    size_t body_len, extra_len, hlen, req_len, rlen, rcap;
    int r, fd, rc, parse_rc, nr;
    int64_t connect_deadline = 0;
    struct mn_tls t;
    unsigned char tmp[4096];

    *raw_out = NULL;
    *raw_len = 0;
    tls_result_init(out);
    tls_copy_literal(reason, reasoncap, "");
    tls_err_clear(err, errlen);
    body = args->body != NULL ? args->body : "";
    body_len = strlen(body);
    if (tls_validate_method(args->method) < 0 ||
        tls_validate_host(args->host) < 0 ||
        tls_validate_path(args->path) < 0 ||
        body_len > (size_t)MN_LIMIT_BODY) {
        return tls_one_fail(E_PARSE, "bad_request", reason, reasoncap,
                            err, errlen, errcode);
    }
    if (tls_normalize_extra(args->extra, extra_norm, sizeof extra_norm,
                            &extra_len) < 0) {
        return tls_one_fail(E_PARSE, "bad_request_headers", reason, reasoncap,
                            err, errlen, errcode);
    }
    r = snprintf(headers, sizeof headers,
                 "%s %s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "User-Agent: miniddns/%s\r\n"
                 "Accept: application/json\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "%s"
                 "\r\n",
                 args->method, args->path, args->host, MN_VERSION,
                 body_len, extra_norm);
    if (!tls_snprintf_ok(r, sizeof headers)) {
        return tls_one_fail(E_PARSE, "request_too_large", reason, reasoncap,
                            err, errlen, errcode);
    }
    hlen = (size_t)r;
    if (body_len > SIZE_MAX - hlen - 1) {
        return tls_one_fail(E_PARSE, "request_too_large", reason, reasoncap,
                            err, errlen, errcode);
    }
    req_len = hlen + body_len;
    wire = (char *)malloc(req_len + 1);
    if (wire == NULL) {
        return tls_one_fail(E_PARSE, "request_too_large", reason, reasoncap,
                            err, errlen, errcode);
    }
    memcpy(wire, headers, hlen);
    if (body_len > 0) {
        memcpy(wire + hlen, body, body_len);
    }
    wire[req_len] = '\0';
    tls_debug_dump_headers("request", args->host, wire, req_len);

    creason[0] = '\0';
    fd = -1;
    rc = tls_connect(args->cfg, args->host, args->port, args->deadline,
                     &fd, &connect_deadline, err, errlen,
                     creason, sizeof creason);
    if (rc != 0) {
        tls_copy_literal(reason, reasoncap, creason);
        free(wire);
        if (errcode != NULL) {
            *errcode = rc;
        }
        return rc;
    }
    memset(&t, 0, sizeof t);
    t.fd = fd;
    /* connect_timeout_ms covers TCP + the TLS handshake (§04.2). */
    t.deadline = connect_deadline != 0 ? connect_deadline : args->deadline;
    if (tls_setup(&t, args->anchors, args->n_anchors, args->host) != 0) {
        rc = tls_failure_rc(&t);
        why = tls_reason_for_rc(rc);
        tls_copy_literal(reason, reasoncap, why);
        tls_set_err(err, errlen, "reason=%s br_err=%d", why,
                    br_ssl_engine_last_error(&t.sc.eng));
        close(fd);
        free(wire);
        if (errcode != NULL) {
            *errcode = rc;
        }
        return rc;
    }
    br_sslio_init(&t.ioc, &t.sc.eng, tls_low_read, &t, tls_low_write, &t);
    if (br_sslio_write_all(&t.ioc, wire, req_len) != 0 ||
        br_sslio_flush(&t.ioc) != 0) {
        rc = tls_failure_rc(&t);
        why = tls_reason_for_rc(rc);
        tls_copy_literal(reason, reasoncap, why);
        tls_set_err(err, errlen, "reason=%s br_err=%d", why,
                    br_ssl_engine_last_error(&t.sc.eng));
        close(fd);
        free(wire);
        if (errcode != NULL) {
            *errcode = rc;
        }
        return rc;
    }
    free(wire);
    /* The handshake is complete; the remaining budget is http_timeout_ms. */
    t.deadline = args->deadline;

    resp = NULL;
    rlen = 0;
    rcap = 0;
    why = "timeout";
    for (;;) {
        int complete;

        if (t.timeout || mn_now_ms() >= args->deadline) {
            /* A full response may already be buffered even if the server
               keeps the connection open; do not discard it. */
            complete = rlen > 0 ? tls_response_complete(resp, rlen) : 0;
            if (complete != 0) break;
            rc = E_TIMEOUT;
            why = "timeout";
            goto read_fail;
        }
        nr = br_sslio_read(&t.ioc, tmp, sizeof tmp);
        if (nr > 0) {
            if (tls_resp_append(&resp, &rlen, &rcap, tmp,
                                (size_t)nr) < 0) {
                rc = E_PARSE;
                why = "body_too_large";
                goto read_fail;
            }
            complete = tls_response_complete(resp, rlen);
            if (complete > 0) break;
            if (complete == -2) break;   /* let the full parser report */
            continue;
        }
        if (t.timeout) {
            complete = rlen > 0 ? tls_response_complete(resp, rlen) : 0;
            if (complete != 0) break;
            rc = E_TIMEOUT;
            why = "timeout";
            goto read_fail;
        }
        if (t.eof) {
            /* A close-delimited body is only complete when the peer sent
               TLS close_notify; a bare TCP FIN is a truncation attack. */
            r = br_ssl_engine_last_error(&t.sc.eng);
            if (r != 0) {
                rc = tls_map_br_error(r);
                why = "tls_truncated";
                goto read_fail;
            }
            break;
        }
        r = br_ssl_engine_last_error(&t.sc.eng);
        if (r != 0) {
            rc = tls_map_br_error(r);
            why = tls_reason_for_rc(rc);
            goto read_fail;
        }
        if (t.io_error) {
            rc = E_TLS_HANDSHAKE;
            why = "tls_handshake";
            goto read_fail;
        }
        break;
    }
    close(fd);
    if (rlen == 0) {
        free(resp);
        return tls_one_fail(E_TIMEOUT, "incomplete_response", reason,
                            reasoncap, err, errlen, errcode);
    }
    tls_debug_dump_headers("response", args->host, resp, rlen);
    parse_rc = mn_http_parse_raw(resp, rlen, out, errcode, err, errlen);
    if (parse_rc != 0) {
        tls_extract_reason(err, creason, sizeof creason);
        if (strcmp(creason, "incomplete_headers") == 0 ||
            strcmp(creason, "incomplete_body") == 0) {
            rc = E_TIMEOUT;
        } else {
            rc = E_PARSE;
        }
        tls_copy_literal(reason, reasoncap, creason);
        if (out->status > 0) {
            tls_set_meta(out->status, -1);
        }
        free(resp);
        mn_http_result_free(out);
        if (errcode != NULL) {
            *errcode = rc;
        }
        return rc;
    }
    tls_set_meta(out->status, out->retry_after_secs);
    if (args->want_json &&
        !tls_contains_nocase(out->content_type, strlen(out->content_type),
                             "json")) {
        free(resp);
        mn_http_result_free(out);
        return tls_one_fail(E_PARSE, "content_type", reason, reasoncap,
                            err, errlen, errcode);
    }
    *raw_out = resp;
    *raw_len = rlen;
    if (errcode != NULL) {
        *errcode = MN_OK;
    }
    tls_err_clear(err, errlen);
    return MN_OK;

read_fail:
    close(fd);
    free(resp);
    tls_copy_literal(reason, reasoncap, why);
    tls_set_err(err, errlen, "reason=%s", why);
    if (errcode != NULL) {
        *errcode = rc;
    }
    return rc;
}

static void tls_move_result(struct mn_http_result *dst,
                            struct mn_http_result *src)
{
    mn_http_result_free(dst);
    *dst = *src;
    src->body = NULL;
    src->body_len = 0;
}

/* ---- public request + handshake diagnostics -------------------------------- */

int mn_http_request(const struct mn_cfg *cfg, struct mn_ca *ca,
                    const struct mn_http_req *req, struct mn_http_result *out,
                    int *errcode, char *err, size_t errlen)
{
    char cur_host[MN_FQDN_MAX], cur_path[MN_TLS_PATH_CAP];
    char new_host[MN_FQDN_MAX], new_path[MN_TLS_PATH_CAP];
    char location[MN_TLS_PATH_CAP + MN_FQDN_MAX + 16];
    char one_reason[MN_TLS_REASON_CAP], reason[MN_TLS_REASON_CAP];
    struct tls_req_args args;
    struct mn_http_result res;
    const br_x509_trust_anchor *anchors;
    char *raw;
    size_t n_anchors, raw_len;
    int64_t deadline;
    int rc, r, status, redirects, cur_port;

    if (errcode != NULL) {
        *errcode = MN_OK;
    }
    tls_err_clear(err, errlen);
    tls_result_init(out);
    tls_set_meta(-1, -1);
    tls_copy_literal(reason, sizeof reason, "unknown");
    if (cfg == NULL || ca == NULL || req == NULL || out == NULL ||
        req->method == NULL || req->host == NULL || req->path == NULL) {
        tls_copy_literal(reason, sizeof reason, "bad_request");
        return tls_error_return(E_PARSE, -1, req != NULL ? req->host : NULL,
                                reason, err, errlen, errcode);
    }
    if (mn_ca_refresh(ca) < 0) {
        tls_copy_literal(reason, sizeof reason, "ca_vanished");
        return tls_error_return(E_CA_LOAD, -1, req->host,
                                reason, err, errlen, errcode);
    }
    if (mn_clock_unsynced(mn_wall(), cfg->core.clock_guard_epoch)) {
        mn_log(MN_LOG_WARN, "clock_unsynced epoch=%lld retry_in=30s",
               (long long)mn_wall());
        tls_copy_literal(reason, sizeof reason, "clock_unsynced");
        return tls_error_return(E_TLS_TIME, -1, req->host,
                                reason, err, errlen, errcode);
    }
    anchors = mn_ca_current(ca, &n_anchors);
    if (anchors == NULL || n_anchors == 0) {
        tls_copy_literal(reason, sizeof reason, "no_trust_anchors");
        return tls_error_return(E_CA_LOAD, -1, req->host,
                                reason, err, errlen, errcode);
    }
    cur_port = req->port > 0 ? req->port : 443;
    r = snprintf(cur_host, sizeof cur_host, "%s", req->host);
    if (!tls_snprintf_ok(r, sizeof cur_host)) {
        tls_copy_literal(reason, sizeof reason, "request_too_large");
        return tls_error_return(E_PARSE, -1, req->host, reason,
                                err, errlen, errcode);
    }
    r = snprintf(cur_path, sizeof cur_path, "%s", req->path);
    if (!tls_snprintf_ok(r, sizeof cur_path)) {
        tls_copy_literal(reason, sizeof reason, "request_too_large");
        return tls_error_return(E_PARSE, -1, req->host, reason,
                                err, errlen, errcode);
    }
    deadline = mn_now_ms() + tls_http_timeout_ms(cfg);
    redirects = 0;
    status = -1;
    rc = MN_OK;
    for (;;) {
        args.cfg = cfg;
        args.anchors = anchors;
        args.n_anchors = n_anchors;
        args.deadline = deadline;
        args.method = req->method;
        args.host = cur_host;
        args.path = cur_path;
        args.body = req->body != NULL ? req->body : "";
        args.extra = req->extra_headers;
        args.port = cur_port;
        args.want_json = req->want_json;

        raw = NULL;
        raw_len = 0;
        tls_result_init(&res);
        one_reason[0] = '\0';
        rc = tls_one_request(&args, &raw, &raw_len, &res, one_reason,
                             sizeof one_reason, err, errlen, errcode);
        if (rc != 0) {
            status = res.status > 0 ? res.status : -1;
            tls_copy_literal(reason, sizeof reason,
                             one_reason[0] != '\0' ? one_reason :
                             tls_reason_for_rc(rc));
            if (res.status > 0) {
                tls_move_result(out, &res);
            }
            free(raw);
            mn_http_result_free(&res);
            goto done;
        }
        status = res.status;
        if (status >= 300 && status < 400 && req->allow_redirect) {
            if (redirects >= MN_MAX_REDIRECT) {
                tls_copy_literal(reason, sizeof reason, "redirect_limit");
                tls_set_err(err, errlen, "reason=redirect_limit http_status=%d",
                            status);
                rc = E_HTTP_STATUS;
                tls_move_result(out, &res);
                free(raw);
                mn_http_result_free(&res);
                goto done;
            }
            r = tls_find_header(raw, raw_len, "Location",
                                location, sizeof location);
            if (r <= 0 || tls_redirect_allowed(cfg, location,
                                               new_host, sizeof new_host,
                                               new_path, sizeof new_path) < 0) {
                tls_copy_literal(reason, sizeof reason, "redirect_rejected");
                tls_set_err(err, errlen, "reason=redirect_rejected");
                rc = E_PARSE;
                tls_move_result(out, &res);
                free(raw);
                mn_http_result_free(&res);
                goto done;
            }
            r = snprintf(cur_host, sizeof cur_host, "%s", new_host);
            if (!tls_snprintf_ok(r, sizeof cur_host)) {
                tls_copy_literal(reason, sizeof reason, "redirect_rejected");
                tls_set_err(err, errlen, "reason=redirect_rejected");
                rc = E_PARSE;
                tls_move_result(out, &res);
                free(raw);
                mn_http_result_free(&res);
                goto done;
            }
            r = snprintf(cur_path, sizeof cur_path, "%s", new_path);
            if (!tls_snprintf_ok(r, sizeof cur_path)) {
                tls_copy_literal(reason, sizeof reason, "redirect_rejected");
                tls_set_err(err, errlen, "reason=redirect_rejected");
                rc = E_PARSE;
                tls_move_result(out, &res);
                free(raw);
                mn_http_result_free(&res);
                goto done;
            }
            cur_port = 443;
            redirects++;
            free(raw);
            mn_http_result_free(&res);
            continue;
        }
        if (status >= 300 && status < 400) {
            tls_copy_literal(reason, sizeof reason, "redirect");
            tls_set_err(err, errlen, "reason=redirect http_status=%d", status);
            rc = E_HTTP_STATUS;
        } else if (status == 429) {
            tls_copy_literal(reason, sizeof reason, "ratelimit");
            tls_set_err(err, errlen, "reason=ratelimit http_status=%d", status);
            rc = E_RATELIMIT;
        } else if (status < 200 || status >= 300) {
            tls_copy_literal(reason, sizeof reason, "status");
            tls_set_err(err, errlen, "reason=status http_status=%d", status);
            rc = E_HTTP_STATUS;
        } else {
            rc = MN_OK;
        }
        tls_move_result(out, &res);
        free(raw);
        mn_http_result_free(&res);
        goto done;
    }

done:
    if (rc == MN_OK) {
        if (errcode != NULL) {
            *errcode = MN_OK;
        }
        tls_err_clear(err, errlen);
        return MN_OK;
    }
    return tls_error_return(rc, status, req != NULL ? req->host : NULL,
                            reason, err, errlen, errcode);
}

const char *mn_tls_version_name(int version)
{
    switch (version) {
    case BR_TLS12: return "1.2";
    case BR_TLS11: return "1.1";
    case BR_TLS10: return "1.0";
    case BR_SSL30: return "3.0";
    default:       return "unknown";
    }
}

int mn_tls_handshake(const struct mn_cfg *cfg, struct mn_ca *ca,
                     const char *host, int port, char *cipher, size_t ciphercap,
                     int *tls_version, int *errcode, char *err, size_t errlen)
{
    char reason[MN_TLS_REASON_CAP], creason[MN_TLS_REASON_CAP];
    const br_x509_trust_anchor *anchors;
    struct mn_tls t;
    br_ssl_session_parameters sp;
    size_t n_anchors;
    int64_t deadline, connect_deadline = 0;
    int rc, fd, status, r;
    const char *why;

    if (errcode != NULL) {
        *errcode = MN_OK;
    }
    if (tls_version != NULL) {
        *tls_version = 0;
    }
    tls_err_clear(err, errlen);
    tls_copy_literal(reason, sizeof reason, "unknown");
    if (cipher != NULL && ciphercap > 0) {
        tls_copy_literal(cipher, ciphercap, "");
    }
    if (cfg == NULL || ca == NULL || host == NULL || host[0] == '\0' ||
        cipher == NULL || ciphercap == 0 ||
        tls_validate_host(host) < 0) {
        tls_copy_literal(reason, sizeof reason, "bad_request");
        return tls_error_return(E_PARSE, -1, host, reason,
                                err, errlen, errcode);
    }
    if (mn_ca_refresh(ca) < 0) {
        tls_copy_literal(reason, sizeof reason, "ca_vanished");
        return tls_error_return(E_CA_LOAD, -1, host, reason,
                                err, errlen, errcode);
    }
    if (mn_clock_unsynced(mn_wall(), cfg->core.clock_guard_epoch)) {
        mn_log(MN_LOG_WARN, "clock_unsynced epoch=%lld retry_in=30s",
               (long long)mn_wall());
        tls_copy_literal(reason, sizeof reason, "clock_unsynced");
        return tls_error_return(E_TLS_TIME, -1, host, reason,
                                err, errlen, errcode);
    }
    anchors = mn_ca_current(ca, &n_anchors);
    if (anchors == NULL || n_anchors == 0) {
        tls_copy_literal(reason, sizeof reason, "no_trust_anchors");
        return tls_error_return(E_CA_LOAD, -1, host, reason,
                                err, errlen, errcode);
    }
    if (port <= 0) {
        port = 443;
    }
    deadline = mn_now_ms() + tls_http_timeout_ms(cfg);
    creason[0] = '\0';
    fd = -1;
    rc = tls_connect(cfg, host, port, deadline, &fd, &connect_deadline,
                     err, errlen, creason, sizeof creason);
    if (rc != 0) {
        tls_copy_literal(reason, sizeof reason, creason);
        status = -1;
        goto done;
    }
    memset(&t, 0, sizeof t);
    t.fd = fd;
    t.deadline = connect_deadline != 0 ? connect_deadline : deadline;
    if (tls_setup(&t, anchors, n_anchors, host) != 0) {
        rc = tls_failure_rc(&t);
        why = tls_reason_for_rc(rc);
        tls_copy_literal(reason, sizeof reason, why);
        tls_set_err(err, errlen, "reason=%s br_err=%d", why,
                    br_ssl_engine_last_error(&t.sc.eng));
        close(fd);
        status = -1;
        goto done;
    }
    rc = tls_pump_handshake(&t);
    if (rc == 0) {
        br_ssl_engine_get_session_parameters(&t.sc.eng, &sp);
        if (tls_version != NULL) {
            *tls_version = sp.version;
        }
        r = tls_cipher_name(sp.cipher_suite, cipher, ciphercap);
        tls_zero_secret(&sp, sizeof sp);
        if (r < 0) {
            rc = E_PARSE;
            tls_copy_literal(reason, sizeof reason, "cipher_too_long");
            tls_set_err(err, errlen, "reason=cipher_too_long");
        }
    } else {
        why = tls_reason_for_rc(rc);
        tls_copy_literal(reason, sizeof reason, why);
        tls_set_err(err, errlen, "reason=%s br_err=%d", why,
                    br_ssl_engine_last_error(&t.sc.eng));
    }
    close(fd);
    status = -1;

done:
    if (rc == MN_OK) {
        if (errcode != NULL) {
            *errcode = MN_OK;
        }
        tls_err_clear(err, errlen);
        return MN_OK;
    }
    return tls_error_return(rc, status, host, reason, err, errlen, errcode);
}

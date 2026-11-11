/* prov_cloudflare.c — Cloudflare v4 DNS provider (§07.3, §08.4) */
#include "provider.h"
#include "detect.h"
#include "json_util.h"
#include "log.h"
#include "tls_http.h"
#include "util.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define MN_CF_ESC_CAP       (MN_LOG_FIELD_MAX * 2 + 16)
#define MN_CF_DETAIL_CAP    MN_LOG_LINE_MAX
#define MN_CF_PATH_CAP      1024
#define MN_CF_BODY_CAP      1024
#define MN_CF_AUTH_CAP      (MN_TOKEN_MAX + 64)
#define MN_CF_API_CODE_CAP  64
#define MN_CF_API_MSG_CAP   (MN_LOG_FIELD_MAX + 1)

struct cf_envelope {
    int  success;
    int  n_results;
    char result_id[MN_ID_MAX];
    char result_content[MN_IP_STRLEN];
    char api_code[MN_CF_API_CODE_CAP];
    char api_msg[MN_CF_API_MSG_CAP];
};

static const char *cf_escape(char *buf, size_t cap, const char *value)
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

static void cf_single_line(char *out, size_t cap, const char *in)
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

static void cf_set_err(char *err, size_t errlen, const char *fmt, ...)
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

static int cf_fmt_checked(char *dst, size_t cap, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (dst == NULL || cap == 0 || fmt == NULL) {
        return -1;
    }
    dst[0] = '\0';
    va_start(ap, fmt);
    n = vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

static int cf_fail(char *err, size_t errlen, int code, const char *reason,
                   const char *value)
{
    char reason_esc[MN_CF_ESC_CAP];
    char value_esc[MN_CF_ESC_CAP];

    if (value != NULL) {
        cf_set_err(err, errlen, "reason=%s value=%s",
                   cf_escape(reason_esc, sizeof(reason_esc), reason),
                   cf_escape(value_esc, sizeof(value_esc), value));
    } else {
        cf_set_err(err, errlen, "reason=%s",
                   cf_escape(reason_esc, sizeof(reason_esc), reason));
    }
    return code;
}

static int cf_hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return (int)(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return (int)(c - 'a') + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return (int)(c - 'A') + 10;
    }
    return -1;
}

static int cf_zone_valid(const char *zone_id)
{
    size_t i;

    if (zone_id == NULL || strlen(zone_id) != 32u) {
        return 0;
    }
    for (i = 0; i < 32u; ++i) {
        if (cf_hex_digit((unsigned char)zone_id[i]) < 0) {
            return 0;
        }
    }
    return 1;
}

static const char *cf_type(int family)
{
    if (family == AF_INET) {
        return "A";
    }
    if (family == AF_INET6) {
        return "AAAA";
    }
    return NULL;
}

static int cf_ip_ok(const char *ip)
{
    size_t i;

    if (ip == NULL || ip[0] == '\0') {
        return 0;
    }
    for (i = 0; ip[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)ip[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F') || c == ':' || c == '.')) {
            return 0;
        }
    }
    return 1;
}

static int cf_url_component_ok(const char *s)
{
    size_t i;

    if (s == NULL) {
        return 0;
    }
    for (i = 0; s[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' ||
              c == '.' || c == '*')) {
            return 0;
        }
    }
    return 1;
}

static int cf_token_ok(const char *token)
{
    size_t i;

    if (token == NULL) {
        return 0;
    }
    for (i = 0; token[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)token[i];
        if (c < 0x21u || c > 0x7eu) {
            return 0;
        }
    }
    return 1;
}

static int cf_build_auth(const struct mn_provider *p, char *auth, size_t cap,
                         char *err, size_t errlen)
{
    if (p == NULL || !cf_token_ok(p->token)) {
        return cf_fail(err, errlen, E_CFG, "invalid_token", NULL);
    }
    if (cf_fmt_checked(auth, cap, "Authorization: Bearer %s\r\n", p->token) < 0) {
        mn_secure_zero(auth, cap);
        return cf_fail(err, errlen, E_PARSE, "request_truncated", NULL);
    }
    return MN_OK;
}

static void cf_log_headers(const struct mn_http_req *req)
{
    char method[MN_CF_ESC_CAP];
    char host[MN_CF_ESC_CAP];
    char path[MN_CF_ESC_CAP];

    mn_log(MN_LOG_DEBUG,
           "http headers method=%s url_host=%s path=%s authorization=\"Bearer ****\"",
           cf_escape(method, sizeof(method), req->method),
           cf_escape(host, sizeof(host), req->host),
           cf_escape(path, sizeof(path), req->path));
}

static int cf_http(const struct mn_provider *p, const struct mn_http_req *req,
                   struct mn_http_result *res, char *err, size_t errlen)
{
    char suberr[MN_CF_DETAIL_CAP];
    char detail[MN_CF_DETAIL_CAP];
    char errname[MN_CF_ESC_CAP];
    int request_errcode = MN_OK;
    int status;

    if (p == NULL || req == NULL || res == NULL) {
        return cf_fail(err, errlen, E_CFG, "invalid_argument", NULL);
    }
    memset(res, 0, sizeof(*res));
    res->retry_after_secs = -1;
    suberr[0] = '\0';
    cf_log_headers(req);
    status = mn_http_request(p->cfg, p->ca, req, res, &request_errcode,
                             suberr, sizeof(suberr));
    if (status != MN_OK) {
        if (status > 0) {
            status = E_PARSE;
        }
        cf_single_line(detail, sizeof(detail), suberr);
        if (detail[0] != '\0') {
            cf_set_err(err, errlen, "%s", detail);
        } else {
            cf_set_err(err, errlen, "reason=http_request err=%s",
                       cf_escape(errname, sizeof(errname), mn_err_name(status)));
        }
        return status;
    }
    return MN_OK;
}

static int cf_call(const struct mn_provider *p, const char *method,
                   const char *path, const char *body, const char *auth,
                   struct mn_http_result *res, char *err, size_t errlen)
{
    struct mn_http_req req;

    memset(&req, 0, sizeof(req));
    req.method = method;
    req.host = MN_CF_API_HOST;
    req.path = path;
    req.body = body != NULL ? body : "";
    req.extra_headers = auth;
    req.port = MN_CF_API_PORT;
    req.want_json = 1;
    req.allow_redirect = 0;
    return cf_http(p, &req, res, err, errlen);
}

static void cf_body_view(const struct mn_http_result *res, const char **body,
                         size_t *len)
{
    const char *b = res->body != NULL ? res->body : "";
    size_t n = res->body_len;
    size_t slen = strlen(b);

    if (res->body == NULL || n == 0) {
        n = slen;
    } else if (n > slen) {
        n = slen;
    }
    *body = b;
    *len = n;
}

static int cf_parse_envelope(const struct mn_http_result *res,
                             struct cf_envelope *env, char *err, size_t errlen)
{
    char parse_err[MN_CF_DETAIL_CAP];
    char detail[MN_CF_DETAIL_CAP];
    char errname[MN_CF_ESC_CAP];
    const char *body;
    size_t len;

    memset(env, 0, sizeof(*env));
    cf_body_view(res, &body, &len);
    parse_err[0] = '\0';
    if (mn_cf_parse(body, len, &env->success,
                    env->result_id, sizeof(env->result_id),
                    env->result_content, sizeof(env->result_content),
                    &env->n_results,
                    env->api_code, sizeof(env->api_code),
                    env->api_msg, sizeof(env->api_msg),
                    parse_err, sizeof(parse_err)) != MN_OK) {
        cf_single_line(detail, sizeof(detail), parse_err);
        cf_set_err(err, errlen, "%s",
                   detail[0] != '\0' ? detail : "reason=json");
        mn_log(MN_LOG_ERROR, "http parse err=%s reason=json",
               cf_escape(errname, sizeof(errname), mn_err_name(E_PARSE)));
        return E_PARSE;
    }
    return MN_OK;
}

static int cf_api_failure(const struct cf_envelope *env, char *err, size_t errlen)
{
    char code[MN_CF_ESC_CAP];
    char msg[MN_CF_ESC_CAP];
    char errname[MN_CF_ESC_CAP];

    cf_escape(code, sizeof(code), env->api_code);
    cf_escape(msg, sizeof(msg), env->api_msg);
    cf_escape(errname, sizeof(errname), mn_err_name(E_API));
    cf_set_err(err, errlen, "api_code=%s api_msg=\"%s\"", code, msg);
    mn_log(MN_LOG_ERROR, "http error err=%s api_code=%s api_msg=\"%s\"",
           errname, code, msg);
    return E_API;
}

static const char *cf_status_reason(int status)
{
    if (status >= 300 && status < 400) {
        return "redirect";
    }
    if (status >= 400 && status < 500) {
        return "client_error";
    }
    if (status >= 500 && status < 600) {
        return "server_error";
    }
    return "unexpected_status";
}

static int cf_status_level(int status)
{
    if (status == 429 || (status >= 300 && status < 400) ||
        (status >= 500 && status < 600)) {
        return MN_LOG_WARN;
    }
    return MN_LOG_ERROR;
}

static int cf_check_status(const struct mn_http_result *res,
                           char *err, size_t errlen)
{
    char host[MN_CF_ESC_CAP];
    char reason[MN_CF_ESC_CAP];
    char errname[MN_CF_ESC_CAP];
    int status = res->status;
    int code = E_HTTP_STATUS;
    int level;
    const char *h;
    const char *r;

    if (status >= 200 && status < 300) {
        return MN_OK;
    }
    h = cf_escape(host, sizeof(host), MN_CF_API_HOST);
    if (status == 429) {
        int retry = res->retry_after_secs < -1 ? -1 : res->retry_after_secs;

        cf_set_err(err, errlen, "http_status=429 url_host=%s retry_after=%d",
                   h, retry);
        mn_log(MN_LOG_WARN,
               "http error err=%s http_status=429 url_host=%s retry_after=%d",
               cf_escape(errname, sizeof(errname), mn_err_name(E_RATELIMIT)),
               h, retry);
        return E_RATELIMIT;
    }
    r = cf_escape(reason, sizeof(reason), cf_status_reason(status));
    level = cf_status_level(status);
    cf_set_err(err, errlen, "http_status=%d url_host=%s reason=%s",
               status, h, r);
    mn_log(level, "http error err=%s http_status=%d url_host=%s reason=%s",
           cf_escape(errname, sizeof(errname), mn_err_name(code)),
           status, h, r);
    return code;
}

static void cf_log_duplicate(const struct mn_record_cfg *rec, int n)
{
    char name[MN_CF_ESC_CAP];
    char type[MN_CF_ESC_CAP];

    mn_log(MN_LOG_WARN, "record name=%s type=%s duplicate_records=%d",
           cf_escape(name, sizeof(name), rec->name),
           cf_escape(type, sizeof(type), cf_type(rec->family)), n);
}

static int cf_discover_content(const struct mn_record_cfg *rec,
                               struct mn_remote *out, const char *raw,
                               char *err, size_t errlen)
{
    char normalized[MN_IP_STRLEN];
    char name[MN_CF_ESC_CAP];
    char type[MN_CF_ESC_CAP];
    char old[MN_CF_ESC_CAP];

    memset(normalized, 0, sizeof(normalized));
    if (mn_ip_normalize(rec->family, raw, normalized) == 0) {
        if (mn_strlcpy(out->content, sizeof(out->content), normalized) < 0) {
            return cf_fail(err, errlen, E_PARSE, "content_truncated", NULL);
        }
        return MN_OK;
    }
    mn_log(MN_LOG_WARN,
           "record name=%s type=%s reason=remote_content_invalid old=%s",
           cf_escape(name, sizeof(name), rec->name),
           cf_escape(type, sizeof(type), cf_type(rec->family)),
           cf_escape(old, sizeof(old), raw));
    if (mn_strlcpy(out->content, sizeof(out->content), raw) < 0) {
        return cf_fail(err, errlen, E_PARSE, "content_truncated", NULL);
    }
    return MN_OK;
}

static int cf_prepare_created(const struct cf_envelope *env, const char *ip,
                              struct mn_remote *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof(*out));
    out->found = 1;
    if (mn_strlcpy(out->id, sizeof(out->id), env->result_id) < 0) {
        return cf_fail(err, errlen, E_PARSE, "id_truncated", NULL);
    }
    if (mn_strlcpy(out->content, sizeof(out->content), ip) < 0) {
        return cf_fail(err, errlen, E_PARSE, "ip_truncated", NULL);
    }
    return MN_OK;
}

static int cf_init(struct mn_provider *p, const struct mn_cfg *cfg,
                   const char *prov_id, char *err, size_t errlen)
{
    char id[MN_CF_ESC_CAP];

    (void)cfg;
    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
    if (p == NULL || !cf_zone_valid(p->zone_id)) {
        cf_set_err(err, errlen, "reason=bad_zone_id provider_id=%s",
                   cf_escape(id, sizeof(id), prov_id));
        return E_CFG;
    }
    return MN_OK;
}

static int cf_discover(struct mn_provider *p, const struct mn_record_cfg *rec,
                       struct mn_remote *out, char *err, size_t errlen)
{
    char auth[MN_CF_AUTH_CAP];
    char path[MN_CF_PATH_CAP];
    struct mn_http_result res;
    struct cf_envelope env;
    const char *type;
    int status;
    int result = E_PARSE;

    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
    if (p == NULL || rec == NULL || out == NULL) {
        return cf_fail(err, errlen, E_CFG, "invalid_argument", NULL);
    }
    memset(auth, 0, sizeof(auth));
    memset(&res, 0, sizeof(res));
    res.retry_after_secs = -1;
    memset(out, 0, sizeof(*out));
    type = cf_type(rec->family);
    if (type == NULL) {
        return cf_fail(err, errlen, E_CFG, "bad_family", NULL);
    }
    if (!cf_url_component_ok(p->zone_id) || !cf_url_component_ok(rec->name)) {
        return cf_fail(err, errlen, E_PARSE, "invalid_request_value", NULL);
    }
    if (cf_fmt_checked(path, sizeof(path),
                       "/client/v4/zones/%s/dns_records?type=%s&name=%s",
                       p->zone_id, type, rec->name) < 0) {
        return cf_fail(err, errlen, E_PARSE, "request_truncated", NULL);
    }
    status = cf_build_auth(p, auth, sizeof(auth), err, errlen);
    if (status < 0) {
        result = status;
        goto done;
    }
    status = cf_call(p, "GET", path, "", auth, &res, err, errlen);
    if (status != MN_OK) {
        result = status;
        goto done;
    }
    status = cf_check_status(&res, err, errlen);
    if (status != MN_OK) {
        result = status;
        goto done;
    }
    status = cf_parse_envelope(&res, &env, err, errlen);
    if (status != MN_OK) {
        result = status;
        goto done;
    }
    if (!env.success) {
        result = cf_api_failure(&env, err, errlen);
        goto done;
    }
    if (env.n_results > 1) {
        cf_log_duplicate(rec, env.n_results);
    }
    if (env.n_results > 0) {
        out->found = 1;
        if (mn_strlcpy(out->id, sizeof(out->id), env.result_id) < 0) {
            result = cf_fail(err, errlen, E_PARSE, "id_truncated", NULL);
            goto done;
        }
        status = cf_discover_content(rec, out, env.result_content, err, errlen);
        if (status != MN_OK) {
            result = status;
            goto done;
        }
    }
    result = MN_OK;

done:
    mn_secure_zero(auth, sizeof(auth));
    mn_http_result_free(&res);
    return result;
}

static int cf_update(struct mn_provider *p, const struct mn_record_cfg *rec,
                     const struct mn_remote *cur, const char *ip,
                     char *err, size_t errlen)
{
    char auth[MN_CF_AUTH_CAP];
    char path[MN_CF_PATH_CAP];
    char body[MN_CF_BODY_CAP];
    struct mn_http_result res;
    struct cf_envelope env;
    const char *id;
    int status;
    int result = E_PARSE;

    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
    if (p == NULL || rec == NULL || ip == NULL) {
        return cf_fail(err, errlen, E_CFG, "invalid_argument", NULL);
    }
    memset(auth, 0, sizeof(auth));
    memset(&res, 0, sizeof(res));
    res.retry_after_secs = -1;
    (void)cur;
    id = cur != NULL ? cur->id : "";
    if (cf_type(rec->family) == NULL) {
        return cf_fail(err, errlen, E_CFG, "bad_family", NULL);
    }
    if (!cf_ip_ok(ip) || !cf_url_component_ok(p->zone_id) ||
        !cf_url_component_ok(id)) {
        return cf_fail(err, errlen, E_PARSE, "invalid_request_value", NULL);
    }
    if (cf_fmt_checked(path, sizeof(path),
                       "/client/v4/zones/%s/dns_records/%s",
                       p->zone_id, id) < 0 ||
        cf_fmt_checked(body, sizeof(body), "{\"content\":\"%s\"}", ip) < 0) {
        return cf_fail(err, errlen, E_PARSE, "request_truncated", NULL);
    }
    status = cf_build_auth(p, auth, sizeof(auth), err, errlen);
    if (status < 0) {
        result = status;
        goto done;
    }
    status = cf_call(p, "PATCH", path, body, auth, &res, err, errlen);
    if (status != MN_OK) {
        result = status;
        goto done;
    }
    status = cf_check_status(&res, err, errlen);
    if (status != MN_OK) {
        result = status;
        goto done;
    }
    status = cf_parse_envelope(&res, &env, err, errlen);
    if (status != MN_OK) {
        result = status;
        goto done;
    }
    if (!env.success) {
        result = cf_api_failure(&env, err, errlen);
        goto done;
    }
    result = MN_OK;

done:
    mn_secure_zero(auth, sizeof(auth));
    mn_http_result_free(&res);
    return result;
}

static int cf_create(struct mn_provider *p, const struct mn_record_cfg *rec,
                     const char *ip, struct mn_remote *out,
                     char *err, size_t errlen)
{
    char auth[MN_CF_AUTH_CAP];
    char path[MN_CF_PATH_CAP];
    char body[MN_CF_BODY_CAP];
    struct mn_http_result res;
    struct cf_envelope env;
    const char *type;
    const char *proxied;
    int status;
    int result = E_PARSE;

    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
    if (p == NULL || rec == NULL || ip == NULL || out == NULL) {
        return cf_fail(err, errlen, E_CFG, "invalid_argument", NULL);
    }
    memset(auth, 0, sizeof(auth));
    memset(&res, 0, sizeof(res));
    res.retry_after_secs = -1;
    memset(out, 0, sizeof(*out));
    type = cf_type(rec->family);
    if (type == NULL) {
        return cf_fail(err, errlen, E_CFG, "bad_family", NULL);
    }
    proxied = rec->proxied ? "true" : "false";
    if (!cf_ip_ok(ip) || !cf_url_component_ok(p->zone_id) ||
        !cf_url_component_ok(rec->name)) {
        return cf_fail(err, errlen, E_PARSE, "invalid_request_value", NULL);
    }
    if (cf_fmt_checked(path, sizeof(path),
                       "/client/v4/zones/%s/dns_records", p->zone_id) < 0 ||
        cf_fmt_checked(body, sizeof(body),
                       "{\"type\":\"%s\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":%d,\"proxied\":%s}",
                       type, rec->name, ip, rec->ttl, proxied) < 0) {
        return cf_fail(err, errlen, E_PARSE, "request_truncated", NULL);
    }
    status = cf_build_auth(p, auth, sizeof(auth), err, errlen);
    if (status < 0) {
        result = status;
        goto done;
    }
    status = cf_call(p, "POST", path, body, auth, &res, err, errlen);
    if (status != MN_OK) {
        result = status;
        goto done;
    }
    status = cf_check_status(&res, err, errlen);
    if (status != MN_OK) {
        result = status;
        goto done;
    }
    status = cf_parse_envelope(&res, &env, err, errlen);
    if (status != MN_OK) {
        result = status;
        goto done;
    }
    if (!env.success) {
        result = cf_api_failure(&env, err, errlen);
        goto done;
    }
    result = cf_prepare_created(&env, ip, out, err, errlen);

done:
    mn_secure_zero(auth, sizeof(auth));
    mn_http_result_free(&res);
    return result;
}

static void cf_fini(struct mn_provider *p)
{
    /* p->ca is borrowed; p->priv is unused. provider.c wipes p->token. */
    (void)p;
}

const struct mn_provider_ops mn_cloudflare_ops = {
    .kind = "cloudflare",
    .caps = MN_CAP_DISCOVER | MN_CAP_PATCH_CONTENT | MN_CAP_CREATE |
            MN_CAP_TTL | MN_CAP_PROXY,
    .init = cf_init,
    .discover = cf_discover,
    .update = cf_update,
    .create = cf_create,
    .fini = cf_fini
};

/* json_util.h — §07.3 jsmn wrapper (no generic tree) */
#ifndef MN_JSON_UTIL_H
#define MN_JSON_UTIL_H

#include "miniddns.h"

struct mn_json {
    const char  *buf;
    size_t       len;
    void        *tokens;   /* jsmntok_t* */
    int          ntok;
};

/* 0 ok, E_PARSE on malformed JSON. Tokens are heap allocated; mn_json_free() them. */
int mn_json_parse(struct mn_json *j, const char *buf, size_t len);
void mn_json_free(struct mn_json *j);

/* Find "key" inside an object token; return its value token index or -1. */
int mn_json_field(const struct mn_json *j, int obj, const char *key);
/* nth element of an array token, or -1 */
int mn_json_array_at(const struct mn_json *j, int arr, int n);
/* true/false primitive => *v, 0 ok */
int mn_json_bool(const struct mn_json *j, int tok, int *v);
/* string token => unescaped, truncated copy; 0 ok */
int mn_json_string(const struct mn_json *j, int tok, char *out, size_t cap);
/* numeric primitive => *v, 0 ok */
int mn_json_int(const struct mn_json *j, int tok, int *v);

/* Cloudflare-specific helpers; see §07.3. Returns 0 on a well-formed body.
   result_id/content are only filled when result[] is non-empty. */
int mn_cf_parse(const char *body, size_t len, int *success,
                char *result_id, size_t idcap,
                char *result_content, size_t contentcap,
                int *n_results,
                char *api_code, size_t codecap,
                char *api_msg, size_t msgcap,
                char *err, size_t errlen);

#endif /* MN_JSON_UTIL_H */

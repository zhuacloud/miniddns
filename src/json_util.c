/* json_util.c — jsmn wrapper and Cloudflare response envelope (§07.3) */
#define JSMN_STATIC
#include "jsmn.h"

#include "json_util.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MN_JSON_INITIAL_TOKENS 64u
#define MN_JSON_MAX_DEPTH     128

static const jsmntok_t *mn_json_tok(const struct mn_json *j, int idx)
{
    const jsmntok_t *toks;

    if (j == NULL || j->tokens == NULL || idx < 0 || idx >= j->ntok) {
        return NULL;
    }
    toks = (const jsmntok_t *)j->tokens;
    return &toks[idx];
}

static int mn_json_digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

static int mn_json_hex_digit(unsigned char c)
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

static int mn_json_hex4(const char *p, unsigned int *out)
{
    unsigned int value = 0;
    int i;

    for (i = 0; i < 4; ++i) {
        int d = mn_json_hex_digit((unsigned char)p[i]);
        if (d < 0) {
            return -1;
        }
        value = (value << 4) | (unsigned int)d;
    }
    *out = value;
    return 0;
}

static size_t mn_json_utf8_seq_len(const char *buf, int pos, int end)
{
    unsigned char c = (unsigned char)buf[pos];
    unsigned int cp;
    size_t need, i;

    if (c >= 0xc2u && c <= 0xdfu) {
        need = 2;
        cp = c & 0x1fu;
    } else if (c >= 0xe0u && c <= 0xefu) {
        need = 3;
        cp = c & 0x0fu;
    } else if (c >= 0xf0u && c <= 0xf4u) {
        need = 4;
        cp = c & 0x07u;
    } else {
        return 0;
    }
    if ((size_t)(end - pos) < need) {
        return 0;
    }
    for (i = 1; i < need; ++i) {
        unsigned char b = (unsigned char)buf[pos + (int)i];
        if ((b & 0xc0u) != 0x80u) {
            return 0;
        }
        cp = (cp << 6) | (unsigned int)(b & 0x3fu);
    }
    if ((need == 3 && cp < 0x800u) || (need == 4 && cp < 0x10000u) ||
        (cp >= 0xd800u && cp <= 0xdfffu) || cp > 0x10ffffu) {
        return 0;
    }
    return need;
}

static int mn_json_validate_string_raw(const struct mn_json *j, const jsmntok_t *t)
{
    int i = t->start;

    while (i < t->end) {
        unsigned char c = (unsigned char)j->buf[i];

        if (c < 0x20u || c == '"') {
            return -1;
        }
        if (c == '\\') {
            unsigned int cp = 0;
            unsigned char e;

            if (i + 1 >= t->end) {
                return -1;
            }
            e = (unsigned char)j->buf[i + 1];
            if (e == 'u') {
                if (i + 5 >= t->end || mn_json_hex4(j->buf + i + 2, &cp) < 0) {
                    return -1;
                }
                i += 6;
                continue;
            }
            if (e != '"' && e != '\\' && e != '/' && e != 'b' && e != 'f' &&
                e != 'n' && e != 'r' && e != 't') {
                return -1;
            }
            i += 2;
            continue;
        }
        if (c < 0x80u) {
            ++i;
            continue;
        }
        {
            size_t n = mn_json_utf8_seq_len(j->buf, i, t->end);
            if (n == 0) {
                return -1;
            }
            i += (int)n;
        }
    }
    return 0;
}

static int mn_json_number_valid(const char *s, size_t n)
{
    size_t p = 0;

    if (n == 0) {
        return 0;
    }
    if (s[p] == '-') {
        ++p;
        if (p == n) {
            return 0;
        }
    }
    if (s[p] == '0') {
        ++p;
    } else if (s[p] >= '1' && s[p] <= '9') {
        while (p < n && mn_json_digit((unsigned char)s[p])) {
            ++p;
        }
    } else {
        return 0;
    }
    if (p < n && s[p] == '.') {
        ++p;
        if (p == n || !mn_json_digit((unsigned char)s[p])) {
            return 0;
        }
        while (p < n && mn_json_digit((unsigned char)s[p])) {
            ++p;
        }
    }
    if (p < n && (s[p] == 'e' || s[p] == 'E')) {
        ++p;
        if (p < n && (s[p] == '+' || s[p] == '-')) {
            ++p;
        }
        if (p == n || !mn_json_digit((unsigned char)s[p])) {
            return 0;
        }
        while (p < n && mn_json_digit((unsigned char)s[p])) {
            ++p;
        }
    }
    return p == n;
}

static int mn_json_validate_primitive(const struct mn_json *j, const jsmntok_t *t)
{
    const char *s = j->buf + t->start;
    size_t n = (size_t)(t->end - t->start);

    if ((n == 4 && memcmp(s, "true", 4) == 0) ||
        (n == 5 && memcmp(s, "false", 5) == 0) ||
        (n == 4 && memcmp(s, "null", 4) == 0)) {
        return 0;
    }
    return mn_json_number_valid(s, n) ? 0 : -1;
}

static int mn_json_check_token(const struct mn_json *j, int idx)
{
    const jsmntok_t *t = mn_json_tok(j, idx);
    int len = (int)j->len;

    if (t == NULL || t->start < 0 || t->end < t->start || t->start > len ||
        t->end > len || t->size < 0) {
        return -1;
    }
    switch (t->type) {
    case JSMN_OBJECT:
        if (t->end <= t->start + 1 || j->buf[t->start] != '{' ||
            j->buf[t->end - 1] != '}') {
            return -1;
        }
        return 0;
    case JSMN_ARRAY:
        if (t->end <= t->start + 1 || j->buf[t->start] != '[' ||
            j->buf[t->end - 1] != ']') {
            return -1;
        }
        return 0;
    case JSMN_STRING:
        if (t->start < 1 || t->end >= len || j->buf[t->start - 1] != '"' ||
            j->buf[t->end] != '"') {
            return -1;
        }
        return mn_json_validate_string_raw(j, t);
    case JSMN_PRIMITIVE:
        if (t->end == t->start) {
            return -1;
        }
        return mn_json_validate_primitive(j, t);
    default:
        return -1;
    }
}

static int mn_json_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int mn_json_check_gap(const struct mn_json *j, int from, int to, int comma)
{
    int p = from;

    if (from < 0 || to < from || to > (int)j->len) {
        return -1;
    }
    if (comma) {
        while (p < to && mn_json_ws(j->buf[p])) {
            ++p;
        }
        if (p >= to || j->buf[p] != ',') {
            return -1;
        }
        ++p;
    }
    while (p < to && mn_json_ws(j->buf[p])) {
        ++p;
    }
    return p == to ? 0 : -1;
}

static int mn_json_check_colon(const struct mn_json *j, int from, int to)
{
    int p = from;

    if (from < 0 || to < from || to > (int)j->len) {
        return -1;
    }
    while (p < to && mn_json_ws(j->buf[p])) {
        ++p;
    }
    if (p >= to || j->buf[p] != ':') {
        return -1;
    }
    ++p;
    while (p < to && mn_json_ws(j->buf[p])) {
        ++p;
    }
    return p == to ? 0 : -1;
}

static int mn_json_outer_start(const struct mn_json *j, int idx)
{
    const jsmntok_t *t = mn_json_tok(j, idx);

    if (t == NULL || t->start < 0 || t->start >= (int)j->len) {
        return -1;
    }
    if (t->type == JSMN_STRING) {
        if (t->start < 1 || j->buf[t->start - 1] != '"') {
            return -1;
        }
        return t->start - 1;
    }
    return t->start;
}

static int mn_json_raw_end(const jsmntok_t *t)
{
    return t->type == JSMN_STRING ? t->end + 1 : t->end;
}

static int mn_json_validate_value(const struct mn_json *j, int idx, int *next,
                                  int *raw_end, int depth)
{
    const jsmntok_t *t;
    int available;

    if (depth > MN_JSON_MAX_DEPTH || mn_json_check_token(j, idx) < 0) {
        return -1;
    }
    t = mn_json_tok(j, idx);
    if (t->type == JSMN_STRING || t->type == JSMN_PRIMITIVE) {
        *next = idx + 1;
        *raw_end = mn_json_raw_end(t);
        return 0;
    }

    available = j->ntok - (idx + 1);
    if (available < 0) {
        return -1;
    }
    if (t->type == JSMN_OBJECT &&
        (size_t)t->size > (size_t)available / 2u) {
        return -1;
    }
    if (t->type == JSMN_ARRAY && (size_t)t->size > (size_t)available) {
        return -1;
    }

    {
        int cur = idx + 1;
        int last_end = t->start + 1;
        int k;
        char close = t->type == JSMN_OBJECT ? '}' : ']';

        for (k = 0; k < t->size; ++k) {
            int value;
            int value_outer;
            int value_next;
            int value_end;
            const jsmntok_t *value_tok;

            if (cur >= j->ntok || mn_json_check_token(j, cur) < 0) {
                return -1;
            }
            value_tok = mn_json_tok(j, cur);
            if (t->type == JSMN_OBJECT) {
                int key_outer = mn_json_outer_start(j, cur);

                if (value_tok->type != JSMN_STRING || key_outer < 0 ||
                    mn_json_check_gap(j, last_end, key_outer, k > 0) < 0) {
                    return -1;
                }
                value = cur + 1;
                if (value >= j->ntok || mn_json_check_token(j, value) < 0) {
                    return -1;
                }
                value_outer = mn_json_outer_start(j, value);
                if (value_outer < 0 ||
                    mn_json_check_colon(j, mn_json_raw_end(value_tok), value_outer) < 0) {
                    return -1;
                }
            } else {
                value = cur;
                value_outer = mn_json_outer_start(j, value);
                if (value_outer < 0 ||
                    mn_json_check_gap(j, last_end, value_outer, k > 0) < 0) {
                    return -1;
                }
            }
            if (mn_json_validate_value(j, value, &value_next, &value_end, depth + 1) < 0 ||
                value_next <= value) {
                return -1;
            }
            cur = value_next;
            last_end = value_end;
        }
        if (t->end - 1 < 0 || j->buf[t->end - 1] != close ||
            mn_json_check_gap(j, last_end, t->end - 1, 0) < 0) {
            return -1;
        }
        *next = cur;
        *raw_end = t->end;
        return 0;
    }
}

static int mn_json_validate_root(const struct mn_json *j)
{
    int outer;
    int next = 0;
    int raw_end = 0;

    if (j->ntok < 1 || mn_json_check_token(j, 0) < 0) {
        return -1;
    }
    outer = mn_json_outer_start(j, 0);
    if (outer < 0 || mn_json_check_gap(j, 0, outer, 0) < 0 ||
        mn_json_validate_value(j, 0, &next, &raw_end, 0) < 0 ||
        next != j->ntok || mn_json_check_gap(j, raw_end, (int)j->len, 0) < 0) {
        return -1;
    }
    return 0;
}

static int mn_json_skip(const struct mn_json *j, int idx, int depth)
{
    const jsmntok_t *t = mn_json_tok(j, idx);
    int cur;
    int k;

    if (t == NULL || depth > MN_JSON_MAX_DEPTH || t->size < 0) {
        return -1;
    }
    if (t->type == JSMN_STRING || t->type == JSMN_PRIMITIVE) {
        return idx + 1 <= j->ntok ? idx + 1 : -1;
    }
    if (t->type != JSMN_OBJECT && t->type != JSMN_ARRAY) {
        return -1;
    }
    cur = idx + 1;
    if (cur > j->ntok) {
        return -1;
    }
    if ((t->type == JSMN_OBJECT && (size_t)t->size > (size_t)(j->ntok - cur) / 2u) ||
        (t->type == JSMN_ARRAY && (size_t)t->size > (size_t)(j->ntok - cur))) {
        return -1;
    }
    for (k = 0; k < t->size; ++k) {
        int next;

        if (cur >= j->ntok) {
            return -1;
        }
        if (t->type == JSMN_OBJECT) {
            const jsmntok_t *key = mn_json_tok(j, cur);
            if (key == NULL || key->type != JSMN_STRING) {
                return -1;
            }
            next = mn_json_skip(j, cur, depth + 1);
            if (next < 0 || next >= j->ntok) {
                return -1;
            }
            next = mn_json_skip(j, next, depth + 1);
        } else {
            next = mn_json_skip(j, cur, depth + 1);
        }
        if (next < 0 || next <= cur) {
            return -1;
        }
        cur = next;
    }
    return cur <= j->ntok ? cur : -1;
}

static int mn_json_key_equal(const struct mn_json *j, int idx, const char *key)
{
    const jsmntok_t *t = mn_json_tok(j, idx);
    char stack[128];
    char *buf = stack;
    size_t cap;
    int equal;

    if (t == NULL || t->type != JSMN_STRING || key == NULL) {
        return 0;
    }
    cap = (size_t)(t->end - t->start) + 1u;
    if (cap > sizeof(stack)) {
        buf = (char *)malloc(cap);
        if (buf == NULL) {
            return 0;
        }
    }
    equal = mn_json_string(j, idx, buf, cap) == 0 && strcmp(buf, key) == 0;
    if (buf != stack) {
        memset(buf, 0, cap);
        free(buf);
    }
    return equal;
}

int mn_json_parse(struct mn_json *j, const char *buf, size_t len)
{
    jsmn_parser parser;
    jsmntok_t *toks;
    size_t cap = (size_t)MN_JSON_INITIAL_TOKENS;
    size_t alloc_max = (size_t)-1 / sizeof(*toks);

    if (j == NULL) {
        return E_PARSE;
    }
    j->buf = NULL;
    j->len = 0;
    j->tokens = NULL;
    j->ntok = 0;
    if (buf == NULL || len == 0 || len > (size_t)INT_MAX ||
        memchr(buf, '\0', len) != NULL) {
        return E_PARSE;
    }
    if (cap > alloc_max) {
        return E_PARSE;
    }
    toks = (jsmntok_t *)malloc(cap * sizeof(*toks));
    if (toks == NULL) {
        return E_PARSE;
    }
    j->buf = buf;
    j->len = len;
    j->tokens = toks;

    for (;;) {
        int r;

        jsmn_init(&parser);
        r = jsmn_parse(&parser, buf, len, toks, (unsigned int)cap);
        if (r == JSMN_ERROR_NOMEM) {
            jsmntok_t *grown;
            size_t newcap;

            if (cap > (size_t)UINT_MAX / 2u || cap > alloc_max / 2u) {
                break;
            }
            newcap = cap * 2u;
            grown = (jsmntok_t *)realloc(toks, newcap * sizeof(*toks));
            if (grown == NULL) {
                break;
            }
            toks = grown;
            j->tokens = toks;
            cap = newcap;
            continue;
        }
        if (r <= 0 || r > (int)cap) {
            break;
        }
        j->ntok = r;
        if (mn_json_validate_root(j) == 0) {
            return MN_OK;
        }
        break;
    }
    mn_json_free(j);
    return E_PARSE;
}

void mn_json_free(struct mn_json *j)
{
    if (j == NULL) {
        return;
    }
    free(j->tokens);
    j->buf = NULL;
    j->len = 0;
    j->tokens = NULL;
    j->ntok = 0;
}

int mn_json_field(const struct mn_json *j, int obj, const char *key)
{
    const jsmntok_t *t = mn_json_tok(j, obj);
    int cur;
    int k;

    if (t == NULL || t->type != JSMN_OBJECT || key == NULL || t->size < 0) {
        return -1;
    }
    cur = obj + 1;
    for (k = 0; k < t->size; ++k) {
        int next;

        if (cur >= j->ntok || mn_json_tok(j, cur)->type != JSMN_STRING) {
            return -1;
        }
        if (mn_json_key_equal(j, cur, key)) {
            return cur + 1 < j->ntok ? cur + 1 : -1;
        }
        next = mn_json_skip(j, cur, 0);
        if (next < 0 || next >= j->ntok) {
            return -1;
        }
        next = mn_json_skip(j, next, 0);
        if (next < 0) {
            return -1;
        }
        cur = next;
    }
    return -1;
}

int mn_json_array_at(const struct mn_json *j, int arr, int n)
{
    const jsmntok_t *t = mn_json_tok(j, arr);
    int cur;
    int k;

    if (t == NULL || t->type != JSMN_ARRAY || n < 0 || n >= t->size) {
        return -1;
    }
    cur = arr + 1;
    if (cur >= j->ntok) {
        return -1;
    }
    for (k = 0; k < n; ++k) {
        int next = mn_json_skip(j, cur, 0);
        if (next < 0 || next >= j->ntok) {
            return -1;
        }
        cur = next;
    }
    return cur;
}

static int mn_json_append(char *out, size_t cap, size_t *used,
                          const unsigned char *bytes, size_t n)
{
    if (cap == 0 || *used >= cap - 1u || n > (cap - 1u) - *used) {
        return 0;
    }
    memcpy(out + *used, bytes, n);
    *used += n;
    out[*used] = '\0';
    return 1;
}

static size_t mn_json_encode_utf8(unsigned int cp, unsigned char out[4])
{
    if (cp == 0 || (cp >= 0xd800u && cp <= 0xdfffu) || cp > 0x10ffffu) {
        cp = 0xfffdu; /* C strings cannot carry U+0000; lone surrogates are invalid. */
    }
    if (cp <= 0x7fu) {
        out[0] = (unsigned char)cp;
        return 1;
    }
    if (cp <= 0x7ffu) {
        out[0] = (unsigned char)(0xc0u | (cp >> 6));
        out[1] = (unsigned char)(0x80u | (cp & 0x3fu));
        return 2;
    }
    if (cp <= 0xffffu) {
        out[0] = (unsigned char)(0xe0u | (cp >> 12));
        out[1] = (unsigned char)(0x80u | ((cp >> 6) & 0x3fu));
        out[2] = (unsigned char)(0x80u | (cp & 0x3fu));
        return 3;
    }
    out[0] = (unsigned char)(0xf0u | (cp >> 18));
    out[1] = (unsigned char)(0x80u | ((cp >> 12) & 0x3fu));
    out[2] = (unsigned char)(0x80u | ((cp >> 6) & 0x3fu));
    out[3] = (unsigned char)(0x80u | (cp & 0x3fu));
    return 4;
}

int mn_json_string(const struct mn_json *j, int tok, char *out, size_t cap)
{
    const jsmntok_t *t = mn_json_tok(j, tok);
    size_t used = 0;
    int pos;
    int end;

    if (t == NULL || t->type != JSMN_STRING || out == NULL || cap == 0 ||
        t->start < 0 || t->end < t->start || t->end > (int)j->len) {
        return E_PARSE;
    }
    out[0] = '\0';
    pos = t->start;
    end = t->end;
    while (pos < end) {
        unsigned char c = (unsigned char)j->buf[pos];

        if (c == '\\') {
            unsigned char e;
            unsigned int cp;
            unsigned char bytes[4];
            size_t n;
            int advance;

            if (pos + 1 >= end) {
                return E_PARSE;
            }
            e = (unsigned char)j->buf[pos + 1];
            if (e == 'u') {
                if (pos + 5 >= end || mn_json_hex4(j->buf + pos + 2, &cp) < 0) {
                    return E_PARSE;
                }
                advance = 6;
                if (cp >= 0xd800u && cp <= 0xdbffu && pos + 11 < end &&
                    j->buf[pos + 6] == '\\' && j->buf[pos + 7] == 'u') {
                    unsigned int low = 0;
                    if (mn_json_hex4(j->buf + pos + 8, &low) == 0 &&
                        low >= 0xdc00u && low <= 0xdfffu) {
                        cp = 0x10000u + ((cp - 0xd800u) << 10) + (low - 0xdc00u);
                        advance = 12;
                    } else {
                        cp = 0xfffdu;
                    }
                } else if ((cp >= 0xd800u && cp <= 0xdbffu) ||
                           (cp >= 0xdc00u && cp <= 0xdfffu)) {
                    cp = 0xfffdu;
                }
                n = mn_json_encode_utf8(cp, bytes);
                if (!mn_json_append(out, cap, &used, bytes, n)) {
                    break;
                }
                pos += advance;
                continue;
            }
            switch (e) {
            case '"':  bytes[0] = '"';  break;
            case '\\': bytes[0] = '\\'; break;
            case '/':  bytes[0] = '/';  break;
            case 'b':  bytes[0] = '\b'; break;
            case 'f':  bytes[0] = '\f'; break;
            case 'n':  bytes[0] = '\n'; break;
            case 'r':  bytes[0] = '\r'; break;
            case 't':  bytes[0] = '\t'; break;
            default:
                return E_PARSE;
            }
            if (!mn_json_append(out, cap, &used, bytes, 1)) {
                break;
            }
            pos += 2;
            continue;
        }
        if (c < 0x20u) {
            unsigned char bytes[4];
            size_t n = mn_json_encode_utf8(0xfffdu, bytes);
            if (!mn_json_append(out, cap, &used, bytes, n)) {
                break;
            }
            ++pos;
            continue;
        }
        if (c < 0x80u) {
            unsigned char bytes[1];
            bytes[0] = c;
            if (!mn_json_append(out, cap, &used, bytes, 1)) {
                break;
            }
            ++pos;
            continue;
        }
        {
            size_t seq = mn_json_utf8_seq_len(j->buf, pos, end);
            if (seq == 0) {
                unsigned char bytes[4];
                size_t n = mn_json_encode_utf8(0xfffdu, bytes);
                if (!mn_json_append(out, cap, &used, bytes, n)) {
                    break;
                }
                ++pos;
            } else {
                if (!mn_json_append(out, cap, &used,
                                    (const unsigned char *)j->buf + pos, seq)) {
                    break;
                }
                pos += (int)seq;
            }
        }
    }
    out[used] = '\0';
    return MN_OK;
}

int mn_json_bool(const struct mn_json *j, int tok, int *v)
{
    const jsmntok_t *t = mn_json_tok(j, tok);
    const char *s;
    size_t n;

    if (t == NULL || t->type != JSMN_PRIMITIVE || v == NULL ||
        t->start < 0 || t->end < t->start || t->end > (int)j->len) {
        return E_PARSE;
    }
    s = j->buf + t->start;
    n = (size_t)(t->end - t->start);
    if (n == 4 && memcmp(s, "true", 4) == 0) {
        *v = 1;
        return MN_OK;
    }
    if (n == 5 && memcmp(s, "false", 5) == 0) {
        *v = 0;
        return MN_OK;
    }
    return E_PARSE;
}

int mn_json_int(const struct mn_json *j, int tok, int *v)
{
    const jsmntok_t *t = mn_json_tok(j, tok);
    const unsigned char *s;
    size_t n, p = 0;
    long long value = 0;
    int negative = 0;

    if (t == NULL || t->type != JSMN_PRIMITIVE || v == NULL ||
        t->start < 0 || t->end < t->start || t->end > (int)j->len) {
        return E_PARSE;
    }
    s = (const unsigned char *)j->buf + t->start;
    n = (size_t)(t->end - t->start);
    if (p < n && s[p] == '-') {
        negative = 1;
        ++p;
    }
    if (p >= n) {
        return E_PARSE;
    }
    if (s[p] == '0') {
        ++p;
        if (p < n) {
            return E_PARSE;
        }
    } else if (s[p] >= '1' && s[p] <= '9') {
        while (p < n && mn_json_digit(s[p])) {
            int d = (int)(s[p] - '0');
            if (value > (LLONG_MAX - (long long)d) / 10LL) {
                return E_PARSE;
            }
            value = value * 10LL + (long long)d;
            ++p;
        }
        if (p != n) {
            return E_PARSE;
        }
    } else {
        return E_PARSE;
    }
    if (negative) {
        value = -value;
    }
    if (value < (long long)INT_MIN || value > (long long)INT_MAX) {
        return E_PARSE;
    }
    *v = (int)value;
    return MN_OK;
}

static int mn_json_token_is(const struct mn_json *j, int idx, const char *literal)
{
    const jsmntok_t *t = mn_json_tok(j, idx);
    size_t n = strlen(literal);

    if (t == NULL || t->type != JSMN_PRIMITIVE ||
        (size_t)(t->end - t->start) != n ||
        memcmp(j->buf + t->start, literal, n) != 0) {
        return 0;
    }
    return 1;
}

static int mn_json_number_token(const struct mn_json *j, int idx)
{
    const jsmntok_t *t = mn_json_tok(j, idx);

    if (t == NULL || t->type != JSMN_PRIMITIVE) {
        return 0;
    }
    return mn_json_number_valid(j->buf + t->start,
                                (size_t)(t->end - t->start));
}

static void mn_cf_reset(int *success, char *result_id, size_t idcap,
                        char *result_content, size_t contentcap,
                        int *n_results, char *api_code, size_t codecap,
                        char *api_msg, size_t msgcap,
                        char *err, size_t errlen)
{
    if (success != NULL) {
        *success = 0;
    }
    if (n_results != NULL) {
        *n_results = 0;
    }
    if (result_id != NULL && idcap > 0) {
        result_id[0] = '\0';
    }
    if (result_content != NULL && contentcap > 0) {
        result_content[0] = '\0';
    }
    if (api_code != NULL && codecap > 0) {
        api_code[0] = '\0';
    }
    if (api_msg != NULL && msgcap > 0) {
        api_msg[0] = '\0';
    }
    if (err != NULL && errlen > 0) {
        err[0] = '\0';
    }
}

static void mn_cf_set_err(char *err, size_t errlen)
{
    static const char reason[] = "reason=json";

    if (err == NULL || errlen == 0) {
        return;
    }
    if (errlen < sizeof(reason)) {
        memcpy(err, reason, errlen - 1u);
        err[errlen - 1u] = '\0';
    } else {
        memcpy(err, reason, sizeof(reason));
    }
}

static int mn_cf_copy_string(const struct mn_json *j, int tok,
                             char *out, size_t cap)
{
    const jsmntok_t *t = mn_json_tok(j, tok);

    if (out == NULL || cap == 0) {
        return MN_OK;
    }
    out[0] = '\0';
    if (t == NULL) {
        return E_PARSE;
    }
    if (t->type == JSMN_STRING) {
        return mn_json_string(j, tok, out, cap);
    }
    if (t->type == JSMN_PRIMITIVE && mn_json_token_is(j, tok, "null")) {
        return MN_OK;
    }
    return E_PARSE;
}

static int mn_cf_copy_code(const struct mn_json *j, int tok,
                           char *out, size_t cap)
{
    const jsmntok_t *t = mn_json_tok(j, tok);
    size_t n, copy;

    if (out == NULL || cap == 0) {
        return MN_OK;
    }
    out[0] = '\0';
    if (t == NULL) {
        return E_PARSE;
    }
    if (t->type == JSMN_STRING) {
        return mn_json_string(j, tok, out, cap);
    }
    if (t->type == JSMN_PRIMITIVE && mn_json_token_is(j, tok, "null")) {
        return MN_OK;
    }
    if (t->type != JSMN_PRIMITIVE || !mn_json_number_token(j, tok)) {
        return E_PARSE;
    }
    n = (size_t)(t->end - t->start);
    copy = n < cap - 1u ? n : cap - 1u;
    memcpy(out, j->buf + t->start, copy);
    out[copy] = '\0';
    return MN_OK;
}

static int mn_cf_read_result(const struct mn_json *j, int obj,
                             char *id, size_t idcap,
                             char *content, size_t contentcap)
{
    int field = mn_json_field(j, obj, "id");

    if (field >= 0 && mn_cf_copy_string(j, field, id, idcap) != MN_OK) {
        return E_PARSE;
    }
    field = mn_json_field(j, obj, "content");
    if (field >= 0 && mn_cf_copy_string(j, field, content, contentcap) != MN_OK) {
        return E_PARSE;
    }
    return MN_OK;
}

static int mn_cf_read_error(const struct mn_json *j, int obj,
                            char *code, size_t codecap,
                            char *msg, size_t msgcap)
{
    int field = mn_json_field(j, obj, "code");

    if (field >= 0 && mn_cf_copy_code(j, field, code, codecap) != MN_OK) {
        return E_PARSE;
    }
    field = mn_json_field(j, obj, "message");
    if (field >= 0 && mn_cf_copy_string(j, field, msg, msgcap) != MN_OK) {
        return E_PARSE;
    }
    return MN_OK;
}

int mn_cf_parse(const char *body, size_t len, int *success,
                char *result_id, size_t idcap,
                char *result_content, size_t contentcap,
                int *n_results,
                char *api_code, size_t codecap,
                char *api_msg, size_t msgcap,
                char *err, size_t errlen)
{
    struct mn_json j;
    const jsmntok_t *t;
    int success_value = 0;
    int field;

    mn_cf_reset(success, result_id, idcap, result_content, contentcap,
                n_results, api_code, codecap, api_msg, msgcap, err, errlen);
    if (mn_json_parse(&j, body, len) != MN_OK) {
        goto fail;
    }
    t = mn_json_tok(&j, 0);
    if (t == NULL || t->type != JSMN_OBJECT || mn_json_skip(&j, 0, 0) != j.ntok) {
        goto fail;
    }
    field = mn_json_field(&j, 0, "success");
    if (field < 0 || mn_json_bool(&j, field, &success_value) != MN_OK) {
        goto fail;
    }
    if (success != NULL) {
        *success = success_value;
    }

    field = mn_json_field(&j, 0, "result");
    if (field >= 0) {
        const jsmntok_t *r = mn_json_tok(&j, field);

        if (r == NULL) {
            goto fail;
        }
        if (r->type == JSMN_ARRAY) {
            int count = r->size;
            if (count < 0) {
                goto fail;
            }
            if (n_results != NULL) {
                *n_results = count;
            }
            if (count > 0) {
                int first = mn_json_array_at(&j, field, 0);
                const jsmntok_t *e = mn_json_tok(&j, first);
                if (e == NULL || e->type != JSMN_OBJECT ||
                    mn_cf_read_result(&j, first, result_id, idcap,
                                      result_content, contentcap) != MN_OK) {
                    goto fail;
                }
            }
        } else if (r->type == JSMN_OBJECT) {
            /* CF list endpoints use result[]; create/update use one result object. */
            if (n_results != NULL) {
                *n_results = 1;
            }
            if (mn_cf_read_result(&j, field, result_id, idcap,
                                  result_content, contentcap) != MN_OK) {
                goto fail;
            }
        } else if (r->type == JSMN_PRIMITIVE && mn_json_token_is(&j, field, "null")) {
            if (n_results != NULL) {
                *n_results = 0;
            }
        } else {
            goto fail;
        }
    }

    field = mn_json_field(&j, 0, "errors");
    if (field >= 0) {
        const jsmntok_t *e = mn_json_tok(&j, field);

        if (e == NULL) {
            goto fail;
        }
        if (e->type == JSMN_ARRAY) {
            if (e->size > 0) {
                int first = mn_json_array_at(&j, field, 0);
                const jsmntok_t *o = mn_json_tok(&j, first);
                if (o == NULL || o->type != JSMN_OBJECT ||
                    mn_cf_read_error(&j, first, api_code, codecap,
                                     api_msg, msgcap) != MN_OK) {
                    goto fail;
                }
            }
        } else if (!(e->type == JSMN_PRIMITIVE && mn_json_token_is(&j, field, "null"))) {
            goto fail;
        }
    }

    mn_json_free(&j);
    return MN_OK;

fail:
    mn_json_free(&j);
    mn_cf_set_err(err, errlen);
    return E_PARSE;
}

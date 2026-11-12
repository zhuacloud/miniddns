/* log.c — §10: <PRI> prefix + level= + escaping + noise control */
#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int  g_level = MN_LOG_INFO;
static int  g_target = MN_LOG_JOURNALD;
static FILE *g_file = NULL;
static void (*g_sink)(int, const char *, void *) = NULL;
static void *g_sink_ctx = NULL;

#define MN_FOLD_MAX 16
struct fold_entry {
    int  used;
    int  level;
    char key[64];
    char body[MN_LOG_LINE_MAX];
    int  count;
};
static struct fold_entry g_folds[MN_FOLD_MAX];

void mn_log_init(int level, int target, const char *file)
{
    g_level = level;
    g_target = target;
    if (g_file && g_file != stdout) fclose(g_file);
    g_file = NULL;
    if (target == MN_LOG_FILE && file && file[0]) {
        g_file = fopen(file, "a");
        if (!g_file) {
            fprintf(stderr, "<3>miniddns: log_open_failed path=%s level=error\n", file);
            g_file = stdout;
        } else {
            setvbuf(g_file, NULL, _IOLBF, 0);
        }
    } else {
        g_file = stdout;
    }
}

void mn_log_close(void)
{
    if (g_file && g_file != stdout) fclose(g_file);
    g_file = stdout;
}

void mn_log_set_level(int level) { g_level = level; }
int  mn_log_get_level(void) { return g_level; }

void mn_log_set_sink(void (*sink)(int level, const char *line, void *ctx), void *ctx)
{
    g_sink = sink;
    g_sink_ctx = ctx;
}

static const char *level_name(int level)
{
    switch (level) {
    case MN_LOG_ERROR: return "error";
    case MN_LOG_WARN:  return "warn";
    case MN_LOG_INFO:  return "info";
    case MN_LOG_DEBUG: return "debug";
    default:           return "info";
    }
}

/* Never emit raw control characters (§10.1). Returns 1 when truncated. */
static int sanitize(char *dst, size_t cap, const char *src)
{
    size_t o = 0;

    if (cap == 0) return 1;
    for (; *src; src++) {
        unsigned char c = (unsigned char)*src;
        const char *rep = NULL;
        char hex[8];

        switch (c) {
        case '\n': rep = "\\n"; break;
        case '\r': rep = "\\r"; break;
        case '\t': rep = "\\t"; break;
        default:
            if (c < 0x20 || c == 0x7f) {
                snprintf(hex, sizeof(hex), "\\x%02x", c);
                rep = hex;
            }
        }
        if (rep != NULL) {
            size_t n = strlen(rep);
            if (o + n + 1 > cap) { dst[o] = '\0'; return 1; }
            memcpy(dst + o, rep, n);
            o += n;
        } else {
            if (o + 2 > cap) { dst[o] = '\0'; return 1; }
            dst[o++] = (char)c;
        }
    }
    dst[o] = '\0';
    return 0;
}

static void emit(int level, const char *body)
{
    char line[MN_LOG_LINE_MAX + 1];
    const char *lvl = level_name(level);
    size_t prefix, suffix_max, avail, used;
    int truncated;

    if (level > g_level) return;             /* numeric syslog priorities */
    prefix = (size_t)snprintf(line, sizeof(line), "<%d>miniddns: ", level);
    if (prefix >= sizeof(line)) prefix = sizeof(line) - 1;
    suffix_max = strlen(" level=") + strlen(lvl) + strlen(" truncated=1");
    if (prefix + suffix_max + 1 > sizeof(line)) {
        /* Defensive: should never happen with the fixed level names. */
        line[0] = '\0';
        used = 0;
        avail = 0;
    } else {
        avail = sizeof(line) - 1 - prefix - suffix_max;
        used = prefix;
    }
    truncated = sanitize(line + used, avail + 1, body);
    used += strlen(line + used);
    snprintf(line + used, sizeof(line) - used, " level=%s%s",
             lvl, truncated ? " truncated=1" : "");
    if (g_sink) {
        g_sink(level, line, g_sink_ctx);
    } else {
        FILE *out = g_file ? g_file : stdout;
        fputs(line, out);
        fputc('\n', out);
        fflush(out);
    }
    (void)g_target;
}

void mn_log(int level, const char *fmt, ...)
{
    char body[MN_LOG_LINE_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    emit(level, body);
}

int mn_log_escape(char *out, size_t cap, const char *in)
{
    size_t o = 0, n = in ? strlen(in) : 0, i;
    int truncated = 0;
    if (cap == 0) return 1;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)in[i];
        const char *rep = NULL;
        char hex[8];
        switch (c) {
        case '"':  rep = "\\\""; break;
        case '\\': rep = "\\\\"; break;
        case '\n': rep = "\\n"; break;
        case '\t': rep = "\\t"; break;
        case '\r': rep = "\\r"; break;
        default:
            if (c < 0x20 || c == 0x7f) { snprintf(hex, sizeof(hex), "\\x%02x", c); rep = hex; }
        }
        if (rep) {
            size_t rl = strlen(rep);
            if (o + rl >= MN_LOG_FIELD_MAX || o + rl + 1 >= cap) { truncated = 1; break; }
            memcpy(out + o, rep, rl); o += rl;
        } else {
            if (o + 1 >= MN_LOG_FIELD_MAX || o + 2 >= cap) { truncated = 1; break; }
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
    return truncated || i < n;
}

void mn_logkv(int level, const char *message,
              const char *const *keys, const char *const *values, size_t n)
{
    char body[MN_LOG_LINE_MAX];
    char esc[512];
    size_t used, i;
    int n2 = snprintf(body, sizeof(body), "%s", message);
    if (n2 < 0 || (size_t)n2 >= sizeof(body)) { emit(level, body); return; }
    used = (size_t)n2;
    for (i = 0; i < n; i++) {
        int truncated = mn_log_escape(esc, sizeof(esc), values[i] ? values[i] : "");
        int r = snprintf(body + used, sizeof(body) - used, " %s=\"%s\"%s",
                         keys[i], esc, truncated ? " truncated=1" : "");
        if (r < 0 || (size_t)r >= sizeof(body) - used) break;
        used += (size_t)r;
    }
    emit(level, body);
}

static void fold_emit(struct fold_entry *e)
{
    char body[MN_LOG_LINE_MAX + 32];
    if (e->count > 1)
        snprintf(body, sizeof(body), "%s repeat=%d", e->body, e->count);
    else
        snprintf(body, sizeof(body), "%s", e->body);
    emit(e->level, body);
    e->used = 0; e->count = 0;
}

void mn_log_repeat(int level, const char *fold_key, const char *fmt, ...)
{
    char body[MN_LOG_LINE_MAX];
    struct fold_entry *slot = NULL, *oldest = NULL;
    int i;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    for (i = 0; i < MN_FOLD_MAX; i++) {
        if (!g_folds[i].used) { slot = &g_folds[i]; break; }
        if (strcmp(g_folds[i].key, fold_key) == 0) { slot = &g_folds[i]; break; }
        if (!oldest) oldest = &g_folds[i];
    }
    if (!slot) { slot = oldest; fold_emit(slot); }
    if (!slot->used || strcmp(slot->body, body) != 0) {
        if (slot->used) fold_emit(slot);
        slot->used = 1;
        slot->level = level;
        snprintf(slot->key, sizeof(slot->key), "%s", fold_key);
        snprintf(slot->body, sizeof(slot->body), "%s", body);
        slot->count = 1;
        return;
    }
    slot->count++;
    if (slot->count >= 10) fold_emit(slot);
}

void mn_log_repeat_flush(void)
{
    int i;
    for (i = 0; i < MN_FOLD_MAX; i++)
        if (g_folds[i].used) fold_emit(&g_folds[i]);
}

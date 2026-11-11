/* log.h — §10 structured logging: <PRI> prefix, level=, escaping, folding */
#ifndef MN_LOG_H
#define MN_LOG_H

#include "miniddns.h"

void mn_log_init(int level, int target, const char *file);
void mn_log_close(void);
void mn_log_set_level(int level);
int  mn_log_get_level(void);

/* Body is "message key=value ...". <PRI> and level= are generated here. */
void mn_log(int level, const char *fmt, ...);

/* Auto-escapes every value; appends level= at the end. */
void mn_logkv(int level, const char *message,
              const char *const *keys, const char *const *values, size_t n);

/* Escapes ", \, newline, tab, CR; truncates to MN_LOG_FIELD_MAX with truncated=1 marker optional */
int  mn_log_escape(char *out, size_t cap, const char *in);

/* §10.3: fold identical info lines 10:1; flush residuals at cycle end.
   Never use for action=update/create. */
void mn_log_repeat(int level, const char *fold_key, const char *fmt, ...);
void mn_log_repeat_flush(void);

/* test hook: capture formatted lines instead of writing to stdout/file */
void mn_log_set_sink(void (*sink)(int level, const char *line, void *ctx), void *ctx);

#endif /* MN_LOG_H */

/* cfg.h — §04 INI parser + validation + §03 path resolution */
#ifndef MN_CFG_H
#define MN_CFG_H

#include "miniddns.h"

/* Fill a config with all defaults and a resolved artifact root (used by
   --check-ca when no config file exists, §09.6). */
void mn_cfg_defaults(struct mn_cfg *cfg, const char *root);

/* diagnostic=1: --check-config / --check-ca / --print-ip / --dry-run
   (missing $CREDENTIALS_DIRECTORY is a warn, not E_CFG, see §04.4/§09.6) */
int mn_cfg_load(const char *cli_path, int diagnostic, int allow_non_root_owner,
                struct mn_cfg *cfg, char *err, size_t errlen);

/* normalized --check-config output; token/zone_id masked */
void mn_cfg_print(const struct mn_cfg *cfg);

/* §14.6 spec self-check: every default must be a member of its enum */
int mn_cfg_check_defaults(char *err, size_t errlen);

const char *mn_log_level_name(int level);
int         mn_log_level_parse(const char *s, int *out);
const char *mn_ip4_mode_name(int mode);
const char *mn_ip6_mode_name(int mode);
void        mn_cfg_wipe_secrets(struct mn_cfg *cfg);

#endif /* MN_CFG_H */

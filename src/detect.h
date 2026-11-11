/* detect.h — §06 IP detection: pure classification/normalisation + selection */
#ifndef MN_DETECT_H
#define MN_DETECT_H

#include "miniddns.h"
#include "nl_addr.h"
#include "ca.h"

/* §06.1 pure predicates: 1 = publishable, 0 = must not be published.
   v4 argument is in NETWORK byte order (struct in_addr.s_addr). */
int mn_ip4_publishable(uint32_t addr_be);
int mn_ip6_publishable(const uint8_t b[16]);

/* §06.5 normalisation: parse text (incl. IPv4-mapped/zone-id), validate,
   return RFC 5952 lowercase compressed form. 0 ok, -1 invalid. */
int mn_ip_normalize(int family, const char *text, char out[MN_IP_STRLEN]);
int mn_ip_equal(int family, const char *a, const char *b);

/* iface_include / iface_exclude evaluation (trailing '*' wildcard only) */
int mn_iface_allowed(const char *name, const char *include, const char *exclude);

struct mn_detect_result {
    char ip[MN_IP_STRLEN];
    int  candidates;
    int  filtered_temporary;
    int  filtered_dadfailed;
    int  filtered_deprecated;
    int  filtered_tentative;
    int  filtered_optimistic;
    int  filtered_lifetime;
    int  filtered_private;
    int  filtered_scope;
    int  filtered_iface_down;
    int  filtered_iface_name;
    int  source;                 /* 0 none, 1 iface, 2 external */
};

/* 0 = found (result->ip), E_NO_IP = no publishable address, other = transport error */
int mn_detect_ipv4(const struct mn_cfg *cfg, const struct mn_addr_set *addrs,
                   struct mn_ca *ca, struct mn_detect_result *res,
                   char *err, size_t errlen);
int mn_detect_ipv6(const struct mn_cfg *cfg, const struct mn_addr_set *addrs,
                   struct mn_detect_result *res, char *err, size_t errlen);

#endif /* MN_DETECT_H */

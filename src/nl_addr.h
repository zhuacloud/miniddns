/* nl_addr.h — §05.2 rtnetlink edge trigger + full dump */
#ifndef MN_NL_ADDR_H
#define MN_NL_ADDR_H

#include "miniddns.h"

struct mn_addr {
    int      family;                /* AF_INET | AF_INET6 */
    uint8_t  bytes[16];             /* network order, v4 in first 4 */
    uint8_t  scope;
    uint32_t flags;                 /* IFA_FLAGS (32-bit) when present */
    int      has_cacheinfo;
    uint32_t valid_lft;             /* 0 = no valid lifetime left */
    unsigned ifindex;
    char     ifname[MN_IFNAME_MAX]; /* always if_indextoname(), never IFA_LABEL */
    int      if_up;                 /* IFF_UP from RTM_GETLINK */
};

struct mn_addr_set {
    struct mn_addr a[MN_MAX_ADDRS];
    size_t n;
};

struct mn_nl {
    int fd;
    uint32_t seq;
    size_t rcvbuf_actual;
    /* ifindex -> { ifname, IFF_UP } from RTM_GETLINK */
    struct { unsigned idx; char name[MN_IFNAME_MAX]; int up; } links[MN_MAX_ADDRS];
    size_t n_links;
};

int  mn_nl_open(struct mn_nl *nl, char *err, size_t errlen);
void mn_nl_close(struct mn_nl *nl);
int  mn_nl_fd(const struct mn_nl *nl);

/* Full resync: RTM_GETLINK + RTM_GETADDR dumps (§05.2). Called at boot,
   at each cycle, and after ENOBUFS. */
int  mn_nl_rescan(struct mn_nl *nl, struct mn_addr_set *out,
                  char *err, size_t errlen);

/* Drain pending netlink messages (non-blocking). *overflow=1 on ENOBUFS.
   Returns 1 when at least one interesting event was seen. */
int  mn_nl_drain(struct mn_nl *nl, int *overflow, char *err, size_t errlen);

#endif /* MN_NL_ADDR_H */

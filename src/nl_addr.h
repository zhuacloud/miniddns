/* nl_addr.h — §05.2 rtnetlink edge trigger + full dump */
#ifndef MN_NL_ADDR_H
#define MN_NL_ADDR_H

#include "miniddns.h"

struct nlmsghdr;

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

struct mn_nl_addr_fp {
    uint8_t  family;
    uint8_t  scope;
    uint8_t  valid_nonzero;
    uint8_t  bytes[16];
    unsigned ifindex;
    uint32_t crit_flags;
};

struct mn_nl {
    int fd;
    uint32_t seq;
    size_t rcvbuf_actual;
    /* ifindex -> { ifname, IFF_UP, IFF_RUNNING } from RTM_GETLINK */
    struct { unsigned idx; char name[MN_IFNAME_MAX]; int up; int running; } links[MN_MAX_ADDRS];
    size_t n_links;
    /* last rescan address fingerprints for RA lifetime-refresh deduplication */
    struct mn_nl_addr_fp fps[MN_MAX_ADDRS];
    size_t n_fps;
};

int  mn_nl_open(struct mn_nl *nl, char *err, size_t errlen);
void mn_nl_close(struct mn_nl *nl);
int  mn_nl_fd(const struct mn_nl *nl);

/* Full resync: RTM_GETLINK + RTM_GETADDR dumps (§05.2). Called at boot,
   at each cycle, and after ENOBUFS. */
int  mn_nl_rescan(struct mn_nl *nl, struct mn_addr_set *out,
                  char *err, size_t errlen);

/* Update the in-memory address fingerprint snapshot from a completed addr_set. */
void mn_nl_snapshot_fps(struct mn_nl *nl, const struct mn_addr_set *addrs);

/* Drain pending netlink messages (non-blocking). *overflow=1 on ENOBUFS.
   Returns 1 when at least one interesting event was seen. */
int  mn_nl_drain(struct mn_nl *nl, int *overflow, char *err, size_t errlen);

/* Filtered drain (v1.3 REQ-07): suppresses pure RA IFA_CACHEINFO refreshes,
   excluded interfaces, non-global scope and tentative/temporary noise while
   reporting IFF_UP/IFF_RUNNING flips via *carrier_changed. */
int  mn_nl_drain_filtered(struct mn_nl *nl, const struct mn_detect_cfg *det_cfg,
                          int *overflow, int *carrier_changed,
                          char *err, size_t errlen);

/* Exposed for unit tests (§14.1). */
int  mn_nl_decode_addr(struct mn_nl *nl, const struct nlmsghdr *nh, struct mn_addr *a);
/* Classify a recvmsg() errno other than EINTR: 1 = stop, -1 = hard error. */
int  mn_nl_recv_error(int errnum, int *overflow, char *err, size_t errlen);

#endif /* MN_NL_ADDR_H */

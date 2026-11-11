/* miniddns — rtnetlink address/link dump and edge-trigger drain (design.md §05.2) */
#include "nl_addr.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#define MN_NL_RCVBUF_WANT   (1024 * 1024)
#define MN_NL_RCVBUF_MIN    (256 * 1024)
#define MN_NL_BUFSZ         (32 * 1024)
#define MN_NL_DUMP_MS       1500
#define MN_NL_POLL_SLICE_MS 100

enum { NL_DUMP_OK = 0, NL_DUMP_HARD = -1, NL_DUMP_OVERFLOW = 1 };

static void nl_copy_into(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (dst == NULL || cap == 0)
        return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    n = strlen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void nl_set_err_text(char *err, size_t errlen, const char *text)
{
    nl_copy_into(err, errlen, text);
}

static void nl_append_err(char *err, size_t errlen, const char *prefix,
                          const char *detail)
{
    size_t used, n;

    if (err == NULL || errlen == 0)
        return;
    err[0] = '\0';
    used = 0;
    if (prefix != NULL) {
        n = strlen(prefix);
        if (n >= errlen - used)
            n = errlen - used - 1;
        memcpy(err + used, prefix, n);
        used += n;
    }
    if (detail != NULL && used + 1 < errlen) {
        if (used > 0)
            err[used++] = ' ';
        n = strlen(detail);
        if (n >= errlen - used)
            n = errlen - used - 1;
        memcpy(err + used, detail, n);
        used += n;
    }
    err[used] = '\0';
}

static void nl_set_err(char *err, size_t errlen, const char *what, int e)
{
    nl_append_err(err, errlen, what, e != 0 ? strerror(e) : "failed");
}

static void nl_log_overflow(void)
{
    mn_log(MN_LOG_WARN, "netlink overflow resync=full_dump pending_cleared=1");
}

static int nl_now_ms(int64_t *out)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    *out = (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
    return 0;
}

static void nl_copy_name(char *dst, const char *src)
{
    nl_copy_into(dst, MN_IFNAME_MAX, src);
}

static void nl_update_link(struct mn_nl *nl, unsigned idx, const char *name,
                           int up)
{
    size_t i;

    for (i = 0; i < nl->n_links; i++) {
        if (nl->links[i].idx == idx) {
            nl_copy_name(nl->links[i].name, name);
            nl->links[i].up = up;
            return;
        }
    }
    if (nl->n_links < MN_MAX_ADDRS) {
        nl->links[nl->n_links].idx = idx;
        nl_copy_name(nl->links[nl->n_links].name, name);
        nl->links[nl->n_links].up = up;
        nl->n_links++;
    }
}

static int nl_link_up(const struct mn_nl *nl, unsigned idx)
{
    size_t i;

    for (i = 0; i < nl->n_links; i++) {
        if (nl->links[i].idx == idx)
            return nl->links[i].up;
    }
    return 0;
}

static void nl_handle_link(struct mn_nl *nl, const struct nlmsghdr *nh,
                           int deleted)
{
    struct ifinfomsg ifi;
    unsigned idx;
    int up;
    char name[MN_IFNAME_MAX];

    if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(ifi)))
        return;
    memcpy(&ifi, NLMSG_DATA(nh), sizeof(ifi));
    if (ifi.ifi_index <= 0)
        return;
    idx = (unsigned)ifi.ifi_index;
    up = deleted ? 0 : ((ifi.ifi_flags & IFF_UP) != 0);
    if (if_indextoname(idx, name) == NULL)
        name[0] = '\0';
    nl_update_link(nl, idx, name, up);
}

static int nl_decode_addr(struct mn_nl *nl, const struct nlmsghdr *nh,
                          struct mn_addr *a)
{
    struct ifaddrmsg *ifa_p;
    struct ifaddrmsg ifa;
    const unsigned char *address = NULL;
    const unsigned char *local = NULL;
    const unsigned char *src;
    uint32_t flags_attr = 0;
    uint32_t valid_lft = 0;
    int have_flags_attr = 0;
    int have_cacheinfo = 0;
    size_t alen;
    int rem;
    struct rtattr *rta;

    if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(ifa)))
        return 0;
    ifa_p = (struct ifaddrmsg *)NLMSG_DATA(nh);
    memcpy(&ifa, ifa_p, sizeof(ifa));
    if (ifa.ifa_family == AF_INET)
        alen = 4;
    else if (ifa.ifa_family == AF_INET6)
        alen = 16;
    else
        return 0;
    if (ifa.ifa_index <= 0)
        return 0;

    rem = (int)(nh->nlmsg_len - NLMSG_LENGTH(sizeof(ifa)));
    for (rta = IFA_RTA(ifa_p); RTA_OK(rta, rem); rta = RTA_NEXT(rta, rem)) {
        const unsigned char *data = (const unsigned char *)RTA_DATA(rta);
        size_t dlen = (size_t)RTA_PAYLOAD(rta);

        switch (rta->rta_type) {
        case IFA_ADDRESS:
            if (dlen >= alen)
                address = data;
            break;
        case IFA_LOCAL:
            if (dlen >= alen)
                local = data;
            break;
        case IFA_FLAGS:
            if (dlen >= sizeof(flags_attr)) {
                memcpy(&flags_attr, data, sizeof(flags_attr));
                have_flags_attr = 1;
            }
            break;
        case IFA_CACHEINFO:
            if (dlen >= 2 * sizeof(valid_lft)) {
                memcpy(&valid_lft, data + sizeof(valid_lft), sizeof(valid_lft));
                have_cacheinfo = 1;
            }
            break;
        case IFA_LABEL:
            /* Interface names come only from if_indextoname(). */
            break;
        default:
            break;
        }
    }
    src = local != NULL ? local : address;
    if (src == NULL)
        return 0;

    memset(a, 0, sizeof(*a));
    a->family = ifa.ifa_family;
    memcpy(a->bytes, src, alen);
    a->scope = ifa.ifa_scope;
    a->flags = have_flags_attr ? flags_attr : (uint32_t)ifa.ifa_flags;
    a->has_cacheinfo = have_cacheinfo;
    a->valid_lft = have_cacheinfo ? valid_lft : 0;
    a->ifindex = (unsigned)ifa.ifa_index;
    if (if_indextoname(a->ifindex, a->ifname) == NULL)
        a->ifname[0] = '\0';
    a->if_up = nl_link_up(nl, a->ifindex);
    return 1;
}

static void nl_add_addr(struct mn_nl *nl, struct mn_addr_set *out,
                        const struct nlmsghdr *nh)
{
    struct mn_addr a;

    if (out->n >= MN_MAX_ADDRS)
        return;
    if (nl_decode_addr(nl, nh, &a))
        out->a[out->n++] = a;
}

static void nl_debug_addr_event(struct mn_nl *nl, const struct nlmsghdr *nh,
                                const char *action)
{
    struct mn_addr a;
    char ip[MN_IP_STRLEN];
    const char *family;

    if (mn_log_get_level() < MN_LOG_DEBUG)
        return;
    if (!nl_decode_addr(nl, nh, &a))
        return;
    if (a.family == AF_INET6)
        family = "inet6";
    else if (a.family == AF_INET)
        family = "inet4";
    else
        return;
    if (inet_ntop(a.family, a.bytes, ip, sizeof(ip)) == NULL)
        return;
    mn_log(MN_LOG_DEBUG, "addr event family=%s action=%s iface=%s addr=%s",
           family, action, a.ifname, ip);
}

static int nl_process_dump(struct mn_nl *nl, uint32_t seq,
                           struct mn_addr_set *out, const unsigned char *buf,
                           size_t len, int *done, int *seen_any,
                           char *err, size_t errlen)
{
    int rem = (int)len;
    struct nlmsghdr *nh;

    for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, rem);
         nh = NLMSG_NEXT(nh, rem)) {
        if (nh->nlmsg_seq != seq)
            continue;
        *seen_any = 1;
        switch (nh->nlmsg_type) {
        case NLMSG_DONE:
            *done = 1;
            return NL_DUMP_OK;
        case NLMSG_ERROR: {
            struct nlmsgerr ne;
            size_t payload = (size_t)(nh->nlmsg_len - NLMSG_HDRLEN);
            int error = 0;

            if (payload >= sizeof(ne)) {
                memcpy(&ne, NLMSG_DATA(nh), sizeof(ne));
                error = ne.error;
            } else if (payload >= sizeof(int)) {
                memcpy(&error, NLMSG_DATA(nh), sizeof(error));
            }
            if (error != 0) {
                nl_set_err(err, errlen, "netlink dump error", -error);
                return NL_DUMP_HARD;
            }
            *done = 1;
            return NL_DUMP_OK;
        }
        case RTM_NEWLINK:
        case RTM_GETLINK:
            nl_handle_link(nl, nh, 0);
            break;
        case RTM_NEWADDR:
        case RTM_GETADDR:
            nl_add_addr(nl, out, nh);
            break;
        default:
            break;
        }
    }
    return NL_DUMP_OK;
}

static int nl_process_events(struct mn_nl *nl, const unsigned char *buf,
                             size_t len)
{
    int rem = (int)len;
    int interesting = 0;
    struct nlmsghdr *nh;

    for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, rem);
         nh = NLMSG_NEXT(nh, rem)) {
        switch (nh->nlmsg_type) {
        case RTM_NEWADDR:
            nl_debug_addr_event(nl, nh, "add");
            interesting = 1;
            break;
        case RTM_DELADDR:
            nl_debug_addr_event(nl, nh, "del");
            interesting = 1;
            break;
        case RTM_NEWLINK:
            nl_handle_link(nl, nh, 0);
            interesting = 1;
            break;
        case RTM_DELLINK:
            nl_handle_link(nl, nh, 1);
            interesting = 1;
            break;
        default:
            break;
        }
    }
    return interesting;
}

static int nl_send_dump(struct mn_nl *nl, const void *buf, size_t len,
                        int64_t deadline, char *err, size_t errlen)
{
    struct sockaddr_nl kernel;
    struct iovec iov;
    struct msghdr msg;
    int named = 1;

    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = (void *)buf;
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    for (;;) {
        ssize_t sent;
        int64_t now;

        if (named) {
            msg.msg_name = &kernel;
            msg.msg_namelen = sizeof(kernel);
        } else {
            msg.msg_name = NULL;
            msg.msg_namelen = 0;
        }
        sent = sendmsg(nl->fd, &msg, 0);
        if (sent >= 0) {
            if ((size_t)sent != len) {
                nl_set_err_text(err, errlen, "netlink sendmsg: short request");
                return NL_DUMP_HARD;
            }
            return NL_DUMP_OK;
        }
        if (named && (errno == EISCONN || errno == EINVAL ||
                      errno == EDESTADDRREQ || errno == EAFNOSUPPORT)) {
            /* A connected test socket already knows its peer. */
            named = 0;
            continue;
        }
        if (errno == EINTR) {
            if (nl_now_ms(&now) != 0 || now >= deadline) {
                nl_set_err_text(err, errlen, "netlink sendmsg: timeout");
                return NL_DUMP_HARD;
            }
            continue;
        }
        if (errno == ENOBUFS) {
            nl_set_err(err, errlen, "netlink sendmsg", ENOBUFS);
            nl_log_overflow();
            return NL_DUMP_OVERFLOW;
        }
        nl_set_err(err, errlen, "netlink sendmsg", errno);
        return NL_DUMP_HARD;
    }
}

static int nl_read_dump(struct mn_nl *nl, uint32_t seq,
                        struct mn_addr_set *out, int64_t deadline,
                        char *err, size_t errlen)
{
    union {
        struct nlmsghdr align;
        unsigned char buf[MN_NL_BUFSZ];
    } u;
    struct iovec iov;
    struct msghdr msg;
    int done = 0;
    int seen_any = 0;

    for (;;) {
        int64_t now, remain;
        ssize_t n;
        int timeout;
        struct pollfd pfd;
        int pr;

        if (nl_now_ms(&now) != 0) {
            nl_set_err_text(err, errlen, "netlink clock_gettime failed");
            return NL_DUMP_HARD;
        }
        remain = deadline - now;
        if (remain <= 0) {
            nl_set_err_text(err, errlen, "netlink recvmsg: dump timeout");
            return NL_DUMP_HARD;
        }
        timeout = remain > MN_NL_POLL_SLICE_MS ? MN_NL_POLL_SLICE_MS : (int)remain;

        iov.iov_base = u.buf;
        iov.iov_len = sizeof(u.buf);
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        n = recvmsg(nl->fd, &msg, MSG_DONTWAIT);
        if (n > 0) {
            int rc;

            if (msg.msg_flags & MSG_TRUNC) {
                nl_set_err_text(err, errlen, "netlink recvmsg: truncated dump datagram");
                nl_log_overflow();
                return NL_DUMP_OVERFLOW;
            }
            rc = nl_process_dump(nl, seq, out, u.buf, (size_t)n, &done,
                                 &seen_any, err, errlen);
            if (rc != NL_DUMP_OK)
                return rc;
            if (done)
                return NL_DUMP_OK;
            continue;
        }
        if (n == 0) {
            /* Connected test peers may end the stream after a complete dump. */
            if (seen_any)
                return NL_DUMP_OK;
            nl_set_err_text(err, errlen, "netlink recvmsg: empty dump");
            return NL_DUMP_HARD;
        }
        if (errno == EINTR)
            continue;
        if (errno == ENOBUFS) {
            nl_set_err(err, errlen, "netlink recvmsg", ENOBUFS);
            nl_log_overflow();
            return NL_DUMP_OVERFLOW;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            nl_set_err(err, errlen, "netlink recvmsg", errno);
            return NL_DUMP_HARD;
        }

        pfd.fd = nl->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pr = poll(&pfd, 1, timeout);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            nl_set_err(err, errlen, "netlink poll", errno);
            return NL_DUMP_HARD;
        }
        if (pr > 0 && (pfd.revents & POLLNVAL)) {
            nl_set_err_text(err, errlen, "netlink poll: invalid fd");
            return NL_DUMP_HARD;
        }
    }
}

static uint32_t nl_next_seq(struct mn_nl *nl)
{
    uint32_t seq = ++nl->seq;

    if (seq == 0)
        seq = ++nl->seq;
    return seq;
}

static int nl_dump_once(struct mn_nl *nl, struct mn_addr_set *out,
                        char *err, size_t errlen)
{
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg gen;
    } link_req;
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } addr_req;
    int64_t start, deadline;
    uint32_t seq;
    int rc;

    nl->n_links = 0;
    out->n = 0;
    if (nl_now_ms(&start) != 0) {
        nl_set_err_text(err, errlen, "netlink clock_gettime failed");
        return NL_DUMP_HARD;
    }
    deadline = start + MN_NL_DUMP_MS;

    memset(&link_req, 0, sizeof(link_req));
    link_req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(link_req.gen));
    link_req.nlh.nlmsg_type = RTM_GETLINK;
    link_req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    link_req.nlh.nlmsg_seq = nl_next_seq(nl);
    link_req.gen.rtgen_family = AF_UNSPEC;
    rc = nl_send_dump(nl, &link_req, link_req.nlh.nlmsg_len, deadline,
                      err, errlen);
    if (rc != NL_DUMP_OK)
        return rc;
    rc = nl_read_dump(nl, link_req.nlh.nlmsg_seq, out, deadline, err, errlen);
    if (rc != NL_DUMP_OK)
        return rc;

    memset(&addr_req, 0, sizeof(addr_req));
    addr_req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(addr_req.ifa));
    addr_req.nlh.nlmsg_type = RTM_GETADDR;
    addr_req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    addr_req.nlh.nlmsg_seq = nl_next_seq(nl);
    addr_req.ifa.ifa_family = AF_UNSPEC;
    rc = nl_send_dump(nl, &addr_req, addr_req.nlh.nlmsg_len, deadline,
                      err, errlen);
    if (rc != NL_DUMP_OK)
        return rc;
    seq = addr_req.nlh.nlmsg_seq;
    return nl_read_dump(nl, seq, out, deadline, err, errlen);
}

int mn_nl_open(struct mn_nl *nl, char *err, size_t errlen)
{
    struct sockaddr_nl sa;
    struct mn_addr_set initial;
    socklen_t alen;
    int fd, want, actual, flags;
    uint32_t groups;

    if (nl == NULL) {
        nl_set_err_text(err, errlen, "netlink open: invalid argument");
        return E_CFG;
    }
    memset(nl, 0, sizeof(*nl));
    nl->fd = -1;
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        nl_set_err(err, errlen, "netlink socket", errno);
        return E_CFG;
    }
    nl->fd = fd;

    want = MN_NL_RCVBUF_WANT;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &want, sizeof(want)) < 0) {
        nl_set_err(err, errlen, "netlink setsockopt SO_RCVBUF", errno);
        close(fd);
        nl->fd = -1;
        return E_CFG;
    }
    actual = 0;
    alen = sizeof(actual);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual, &alen) < 0) {
        nl_set_err(err, errlen, "netlink getsockopt SO_RCVBUF", errno);
        close(fd);
        nl->fd = -1;
        return E_CFG;
    }
    nl->rcvbuf_actual = actual > 0 ? (size_t)actual : 0;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    groups = (1u << (RTNLGRP_LINK - 1)) |
             (1u << (RTNLGRP_IPV4_IFADDR - 1)) |
             (1u << (RTNLGRP_IPV6_IFADDR - 1));
    sa.nl_groups = groups;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        nl_set_err(err, errlen, "netlink bind", errno);
        close(fd);
        nl->fd = -1;
        return E_CFG;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        nl_set_err(err, errlen, "netlink fcntl O_NONBLOCK", errno);
        close(fd);
        nl->fd = -1;
        return E_CFG;
    }

    if (mn_nl_rescan(nl, &initial, err, errlen) != MN_OK) {
        close(fd);
        nl->fd = -1;
        return E_CFG;
    }
    mn_log(MN_LOG_INFO,
           "netlink subscribed groups=link,ipv4_ifaddr,ipv6_ifaddr "
           "rcvbuf_actual=%zu initial_addrs=%zu",
           nl->rcvbuf_actual, initial.n);
    if (nl->rcvbuf_actual < MN_NL_RCVBUF_MIN)
        mn_log(MN_LOG_WARN, "netlink rcvbuf_actual=%zu hint=net.core.rmem_max",
               nl->rcvbuf_actual);
    return MN_OK;
}

void mn_nl_close(struct mn_nl *nl)
{
    if (nl == NULL)
        return;
    if (nl->fd >= 0)
        close(nl->fd);
    nl->fd = -1;
}

int mn_nl_fd(const struct mn_nl *nl)
{
    return nl != NULL ? nl->fd : -1;
}

int mn_nl_rescan(struct mn_nl *nl, struct mn_addr_set *out,
                 char *err, size_t errlen)
{
    int rc;

    if (nl == NULL || nl->fd < 0 || out == NULL) {
        nl_set_err_text(err, errlen, "netlink rescan: invalid argument");
        return E_CFG;
    }
    out->n = 0;
    rc = nl_dump_once(nl, out, err, errlen);
    if (rc == NL_DUMP_OVERFLOW)
        rc = nl_dump_once(nl, out, err, errlen);
    if (rc == NL_DUMP_OVERFLOW) {
        nl_set_err_text(err, errlen, "netlink rescan: repeated dump overflow");
        nl->n_links = 0;
        out->n = 0;
        return E_CFG;
    }
    if (rc != NL_DUMP_OK) {
        nl->n_links = 0;
        out->n = 0;
        return E_CFG;
    }
    return MN_OK;
}

int mn_nl_drain(struct mn_nl *nl, int *overflow, char *err, size_t errlen)
{
    union {
        struct nlmsghdr align;
        unsigned char buf[MN_NL_BUFSZ];
    } u;
    struct iovec iov;
    struct msghdr msg;
    int interesting = 0;
    int spins = 0;

    if (overflow != NULL)
        *overflow = 0;
    if (nl == NULL || nl->fd < 0) {
        nl_set_err_text(err, errlen, "netlink drain: invalid argument");
        return -1;
    }

    for (;;) {
        ssize_t n;

        iov.iov_base = u.buf;
        iov.iov_len = sizeof(u.buf);
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        n = recvmsg(nl->fd, &msg, MSG_DONTWAIT);
        if (n > 0) {
            if (msg.msg_flags & MSG_TRUNC) {
                if (overflow != NULL)
                    *overflow = 1;
                nl_log_overflow();
                continue;
            }
            if (nl_process_events(nl, u.buf, (size_t)n))
                interesting = 1;
            continue;
        }
        if (n == 0)
            break;
        if (errno == EINTR) {
            if (++spins > 64)
                break;
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        if (errno == ENOBUFS) {
            if (overflow != NULL)
                *overflow = 1;
            nl_set_err(err, errlen, "netlink drain recvmsg", ENOBUFS);
            nl_log_overflow();
            break;
        }
        nl_set_err(err, errlen, "netlink drain recvmsg", errno);
        return -1;
    }
    return interesting ? 1 : 0;
}

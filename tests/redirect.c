/* LD_PRELOAD shim: map api.cloudflare.com / echo hosts to the local TLS mock.
   Only used by integration tests; NEVER part of the shipped binary. */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>

static int mock_port(void)
{
    const char *s = getenv("MOCK_PORT");
    return (s && *s) ? atoi(s) : 0;
}

static int is_target(const char *node)
{
    static const char *defaults[] = {
        "api.cloudflare.com", "api.ipify.org", "ipv4.icanhazip.com",
        "ipv4.ident.me", NULL
    };
    const char *extra = getenv("MOCK_HOSTS");
    int i;
    if (!node) return 0;
    for (i = 0; defaults[i]; i++) if (!strcasecmp(node, defaults[i])) return 1;
    if (extra) {
        char buf[512], *p;
        snprintf(buf, sizeof(buf), "%s", extra);
        for (p = strtok(buf, ","); p; p = strtok(NULL, ","))
            if (!strcasecmp(node, p)) return 1;
    }
    return 0;
}

typedef int (*gai_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res)
{
    static gai_fn real;
    if (!real) real = (gai_fn)dlsym(RTLD_NEXT, "getaddrinfo");
    if (mock_port() > 0 && is_target(node))
        return real("127.0.0.1", service, hints, res);
    return real(node, service, hints, res);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    static connect_fn real;
    struct sockaddr_storage copy;
    if (!real) real = (connect_fn)dlsym(RTLD_NEXT, "connect");
    if (mock_port() > 0 && addr && len <= sizeof(copy)) {
        memcpy(&copy, addr, len);
        if (copy.ss_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)&copy;
            if (ntohs(in->sin_port) == 443) {
                in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                in->sin_port = htons((unsigned short)mock_port());
                return real(fd, (const struct sockaddr *)&copy, len);
            }
        } else if (copy.ss_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&copy;
            if (ntohs(in6->sin6_port) == 443) {
                static const unsigned char loopback[16] = {
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
                };
                memcpy(&in6->sin6_addr, loopback, 16);
                in6->sin6_port = htons((unsigned short)mock_port());
                return real(fd, (const struct sockaddr *)&copy, len);
            }
        }
    }
    return real(fd, addr, len);
}

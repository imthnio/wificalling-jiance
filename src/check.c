/* WiFi Calling (VoWiFi) 网络探测 v3
 *
 * 检测思路：
 *   1. 解析运营商 ePDG 域名（自带 DNS 客户端：EDNS0、TC 时转 TCP、跟随 CNAME，
 *      区分"域名不存在"和"DNS 失败"）。
 *   2. 对每个 IP 同时向 UDP 500 和 UDP 4500（带 non-ESP marker）发送和手机一样的
 *      IKE_SA_INIT（多套算法 + NAT_DETECTION），按 IKE 规范重传 3 次。
 *   3. 只要收到 SPI 匹配、结构合法的 IKE_SA_INIT 响应（包括 NO_PROPOSAL_CHOSEN、
 *      INVALID_KE_PAYLOAD、COOKIE 等错误通知），就证明 VPS <-> ePDG 的 UDP 往返通。
 *   4. 区分超时 / ICMP 拒绝 / 本机发送失败，并根据全部运营商的结果推断问题在 VPS 还是运营商。
 *
 * 只做未认证的 IKE 首包探测，不生成会话密钥，不需要 root。 */
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "carriers.h"

#define VERSION "3.0.0"
#define COUNTRY_COUNT (sizeof countries / sizeof *countries)
#define CARRIER_COUNT (sizeof carriers / sizeof *carriers)
#define MAX_RESOLVERS 5
#define MAX_ADDRS 6        /* 每个运营商最多检测的 IP 数 */
#define MAX_FQDN 2
#define MAX_TARGETS 64
#define BATCH_PROBES 96    /* 同时打开的 UDP 套接字上限 */
#define BATCH_TARGETS 6
#define IKE_MAX 512
#define SENDS 3

/* ---------- 基础工具 ---------- */

static uint16_t rd16(const unsigned char *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t rd32(const unsigned char *p) { return (uint32_t)rd16(p) << 16 | rd16(p + 2); }
static void wr16(unsigned char *p, unsigned v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v; }
static void wr32(unsigned char *p, uint32_t v) { wr16(p, v >> 16); wr16(p + 2, v & 0xffff); }

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void random_bytes(void *buf, size_t n) {
    static int fd = -1;
    unsigned char *p = buf;
    if (fd < 0 && (fd = open("/dev/urandom", O_RDONLY)) < 0) { perror("/dev/urandom"); exit(3); }
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { fputs("无法读取系统随机数\n", stderr); exit(3); }
        p += r; n -= (size_t)r;
    }
}

static int use_color;
static const char *C(const char *code) { return use_color ? code : ""; }
#define RESET C("\033[0m")
#define BOLD_CYAN C("\033[1;36m")
#define GREEN C("\033[1;32m")
#define YELLOW C("\033[1;33m")
#define RED C("\033[1;31m")
#define GRAY C("\033[2m")

/* ---------- 地址 ---------- */

struct addr { int family; unsigned char b[16]; };

static size_t addr_len(const struct addr *a) { return a->family == AF_INET6 ? 16 : 4; }
static int addr_eq(const struct addr *a, const struct addr *b) {
    return a->family == b->family && !memcmp(a->b, b->b, addr_len(a));
}
static int parse_addr(const char *s, struct addr *a) {
    memset(a, 0, sizeof *a);
    if (inet_pton(AF_INET, s, a->b) == 1) { a->family = AF_INET; return 1; }
    if (inet_pton(AF_INET6, s, a->b) == 1) { a->family = AF_INET6; return 1; }
    return 0;
}
static const char *addr_str(const struct addr *a, char buf[INET6_ADDRSTRLEN]) {
    return inet_ntop(a->family, a->b, buf, INET6_ADDRSTRLEN);
}
static socklen_t to_sockaddr(const struct addr *a, unsigned port, struct sockaddr_storage *ss) {
    memset(ss, 0, sizeof *ss);
    if (a->family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)ss;
        s->sin_family = AF_INET; s->sin_port = htons((uint16_t)port); memcpy(&s->sin_addr, a->b, 4);
#ifdef __APPLE__
        s->sin_len = sizeof *s;
#endif
        return sizeof *s;
    }
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;
    s->sin6_family = AF_INET6; s->sin6_port = htons((uint16_t)port); memcpy(&s->sin6_addr, a->b, 16);
#ifdef __APPLE__
    s->sin6_len = sizeof *s;
#endif
    return sizeof *s;
}
static int local_endpoint(int fd, struct addr *a, unsigned *port) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof ss;
    if (getsockname(fd, (struct sockaddr *)&ss, &len)) return 0;
    memset(a, 0, sizeof *a);
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&ss;
        a->family = AF_INET; memcpy(a->b, &s->sin_addr, 4); *port = ntohs(s->sin_port);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss;
        a->family = AF_INET6; memcpy(a->b, &s->sin6_addr, 16); *port = ntohs(s->sin6_port);
    }
    return 1;
}

static int sock_open(const struct addr *dst, unsigned port, int type) {
    struct sockaddr_storage ss;
    socklen_t len = to_sockaddr(dst, port, &ss);
    int fd = socket(dst->family, type, 0);
    if (fd < 0) return -1;
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0 ||
        (connect(fd, (struct sockaddr *)&ss, len) < 0 && errno != EINPROGRESS)) {
        int e = errno; close(fd); errno = e; return -1;
    }
    return fd;
}

/* 1 = 就绪，0 = 到期 */
static int wait_fd(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t left = deadline - now_ms();
        if (left <= 0) return 0;
        struct pollfd p = {fd, events, 0};
        int r = poll(&p, 1, (int)left);
        if (r < 0 && errno == EINTR) continue;
        return r > 0;
    }
}

/* recv() 会静默截断超长数据报，截断的包一律丢弃，返回 -2。 */
static ssize_t recv_dgram(int fd, unsigned char *buf, size_t cap) {
    struct iovec iov = {buf, cap};
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov; m.msg_iovlen = 1;
    ssize_t n = recvmsg(fd, &m, 0);
    if (n >= 0 && (m.msg_flags & MSG_TRUNC)) return -2;
    return n;
}

/* ---------- SHA-1（仅用于 NAT_DETECTION 哈希，RFC 7296 2.23） ---------- */

static uint32_t rol(uint32_t x, int n) { return x << n | x >> (32 - n); }
static void sha1_block(uint32_t h[5], const unsigned char *p) {
    uint32_t w[80], a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 16; i++) w[i] = rd32(p + 4 * i);
    for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}
static void sha1(const unsigned char *m, size_t n, unsigned char out[20]) {
    uint32_t h[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    size_t i = 0;
    for (; i + 64 <= n; i += 64) sha1_block(h, m + i);
    unsigned char tail[128] = {0};
    size_t rest = n - i, tl = rest + 9 <= 64 ? 64 : 128;
    memcpy(tail, m + i, rest);
    tail[rest] = 0x80;
    uint64_t bits = (uint64_t)n * 8;
    for (int j = 0; j < 8; j++) tail[tl - 1 - j] = (unsigned char)(bits >> (8 * j));
    sha1_block(h, tail);
    if (tl == 128) sha1_block(h, tail + 64);
    for (int j = 0; j < 5; j++) wr32(out + 4 * j, h[j]);
}
static void natd_hash(const unsigned char spi_i[8], const unsigned char spi_r[8],
                      const struct addr *a, unsigned port, unsigned char out[20]) {
    unsigned char buf[34];
    size_t n = 16;
    memcpy(buf, spi_i, 8); memcpy(buf + 8, spi_r, 8);
    memcpy(buf + n, a->b, addr_len(a)); n += addr_len(a);
    wr16(buf + n, port); n += 2;
    sha1(buf, n, out);
}

/* ---------- DNS ---------- */

enum { DNS_NODATA = 0, DNS_FAIL = -1, DNS_NXDOMAIN = -2, DNS_IGNORE = -3, DNS_TRUNC = -4 };

static struct addr resolvers[MAX_RESOLVERS];
static int resolver_count;
static unsigned dns_port = 53;
static int dns_timeout_ms = 2500;

static int host_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}
/* 规范化：小写、去掉末尾的点；不合法返回 0。 */
static int normalize_host(const char *in, char out[256]) {
    size_t n = strlen(in), label = 0;
    if (n && in[n - 1] == '.') n--;
    if (!n || n > 253) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        out[i] = (char)c;
        if (c == '.') { if (!label) return 0; label = 0; continue; }
        if (!host_char(c) || ++label > 63) return 0;
    }
    out[n] = 0;
    return 1;
}

static size_t dns_build(unsigned char *b, const char *name, unsigned qtype, uint16_t id) {
    memset(b, 0, 12);
    wr16(b, id); wr16(b + 2, 0x0100); wr16(b + 4, 1); wr16(b + 10, 1);
    size_t n = 12;
    for (const char *p = name; *p;) {
        size_t len = strcspn(p, ".");
        b[n++] = (unsigned char)len; memcpy(b + n, p, len); n += len; p += len;
        if (*p) p++;
    }
    b[n++] = 0; wr16(b + n, qtype); wr16(b + n + 2, 1); n += 4;
    /* EDNS0 OPT：允许 1232 字节 UDP 响应，减少截断。 */
    b[n] = 0; wr16(b + n + 1, 41); wr16(b + n + 3, 1232); wr32(b + n + 5, 0); wr16(b + n + 9, 0);
    return n + 11;
}

static int dns_name(const unsigned char *b, size_t n, size_t *off, char out[256]) {
    size_t pos = *off, used = 0;
    int jumped = 0, hops = 0;
    for (;;) {
        if (pos >= n) return 0;
        unsigned len = b[pos];
        if ((len & 0xc0) == 0xc0) {
            if (pos + 1 >= n || ++hops > 32) return 0;
            if (!jumped) *off = pos + 2;
            jumped = 1;
            pos = (size_t)(len & 0x3f) << 8 | b[pos + 1];
            continue;
        }
        if (len & 0xc0) return 0;
        pos++;
        if (!len) { out[used] = 0; if (!jumped) *off = pos; return 1; }
        if (pos + len > n || used + len + 1 > 254) return 0;
        if (used) out[used++] = '.';
        for (unsigned i = 0; i < len; i++) {
            unsigned char c = b[pos + i];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
            out[used++] = c > 32 && c < 127 && c != '.' ? (char)c : '?';
        }
        pos += len;
    }
}

/* >0 = 地址数；DNS_NODATA 时若 next 非空，表示 CNAME 链断在 next，需要再查。 */
static int dns_parse(const unsigned char *b, size_t n, uint16_t id, const char *qname, unsigned qtype,
                     struct addr *out, int max, char next[256]) {
    static struct rr { char owner[256]; unsigned type; size_t rd, rdlen; } rrs[48];
    char name[256], cur[256];
    size_t off = 12;
    next[0] = 0;
    if (n < 12 || rd16(b) != id || !(b[2] & 0x80) || (b[2] & 0x78)) return DNS_IGNORE;
    if (b[2] & 0x02) return DNS_TRUNC;
    if (rd16(b + 4) != 1 || !dns_name(b, n, &off, name) || strcmp(name, qname) ||
        off + 4 > n || rd16(b + off) != qtype || rd16(b + off + 2) != 1) return DNS_IGNORE;
    off += 4;
    unsigned rcode = b[3] & 15, an = rd16(b + 6), nr = 0;
    if (rcode == 3) return DNS_NXDOMAIN;
    if (rcode) return DNS_FAIL;
    for (unsigned i = 0; i < an; i++) {
        struct rr r;
        if (!dns_name(b, n, &off, r.owner) || off + 10 > n) return DNS_FAIL;
        r.type = rd16(b + off);
        unsigned cls = rd16(b + off + 2);
        r.rdlen = rd16(b + off + 8);
        off += 10; r.rd = off;
        if (r.rdlen > n - off) return DNS_FAIL;
        off += r.rdlen;
        if (cls == 1 && nr < sizeof rrs / sizeof *rrs) rrs[nr++] = r;
    }
    snprintf(cur, sizeof cur, "%s", qname);
    for (int depth = 0; depth < 12; depth++) {
        unsigned i = 0;
        while (i < nr && !(rrs[i].type == 5 && !strcmp(rrs[i].owner, cur))) i++;
        if (i == nr) break;
        size_t t = rrs[i].rd;
        if (!dns_name(b, n, &t, name) || t != rrs[i].rd + rrs[i].rdlen) return DNS_FAIL;
        snprintf(cur, sizeof cur, "%s", name);
    }
    int count = 0;
    size_t alen = qtype == 28 ? 16 : 4;
    for (unsigned i = 0; i < nr && count < max; i++) {
        if (rrs[i].type != qtype || rrs[i].rdlen != alen || strcmp(rrs[i].owner, cur)) continue;
        struct addr a;
        memset(&a, 0, sizeof a);
        a.family = qtype == 28 ? AF_INET6 : AF_INET;
        memcpy(a.b, b + rrs[i].rd, alen);
        int dup = 0;
        for (int j = 0; j < count; j++) dup |= addr_eq(&out[j], &a);
        if (!dup) out[count++] = a;
    }
    if (count) return count;
    if (strcmp(cur, qname)) snprintf(next, 256, "%s", cur);
    return DNS_NODATA;
}

static int io_all(int fd, unsigned char *buf, size_t n, int writing, int64_t deadline) {
    while (n) {
        if (!wait_fd(fd, writing ? POLLOUT : POLLIN, deadline)) return 0;
        ssize_t r = writing ? write(fd, buf, n) : read(fd, buf, n);
        if (r < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (r <= 0) return 0;
        buf += r; n -= (size_t)r;
    }
    return 1;
}

static int dns_tcp(const struct addr *srv, const unsigned char *q, size_t qn, uint16_t id, const char *qname,
                   unsigned qtype, struct addr *out, int max, char next[256]) {
    static unsigned char r[65536];
    unsigned char req[2 + 320];
    int64_t deadline = now_ms() + dns_timeout_ms;
    int fd = sock_open(srv, dns_port, SOCK_STREAM), result = DNS_FAIL, err = 0;
    socklen_t elen = sizeof err;
    if (fd < 0) return DNS_FAIL;
    wr16(req, (unsigned)qn); memcpy(req + 2, q, qn);
    if (wait_fd(fd, POLLOUT, deadline) && !getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) && !err &&
        io_all(fd, req, qn + 2, 1, deadline) && io_all(fd, r, 2, 0, deadline)) {
        size_t len = rd16(r);
        if (io_all(fd, r, len, 0, deadline)) {
            result = dns_parse(r, len, id, qname, qtype, out, max, next);
            if (result == DNS_IGNORE || result == DNS_TRUNC) result = DNS_FAIL;
        }
    }
    close(fd);
    return result;
}

static int dns_query(const struct addr *srv, const char *qname, unsigned qtype,
                     struct addr *out, int max, char next[256]) {
    unsigned char q[320], r[4096];
    uint16_t id;
    random_bytes(&id, sizeof id);
    size_t qn = dns_build(q, qname, qtype, id);
    int fd = sock_open(srv, dns_port, SOCK_DGRAM), result = DNS_FAIL, resent = 0;
    if (fd < 0) return DNS_FAIL;
    int64_t start = now_ms(), deadline = start + dns_timeout_ms, resend = start + dns_timeout_ms / 2;
    if (send(fd, q, qn, 0) != (ssize_t)qn) { close(fd); return DNS_FAIL; }
    while (now_ms() < deadline) {
        if (!resent && now_ms() >= resend) { (void)!send(fd, q, qn, 0); resent = 1; }
        if (!wait_fd(fd, POLLIN, resent ? deadline : resend)) continue;
        ssize_t len = recv_dgram(fd, r, sizeof r);
        if (len == -2) { result = DNS_TRUNC; break; }
        if (len < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
        int x = dns_parse(r, (size_t)len, id, qname, qtype, out, max, next);
        if (x != DNS_IGNORE) { result = x; break; }
    }
    close(fd);
    if (result == DNS_TRUNC) result = dns_tcp(srv, q, qn, id, qname, qtype, out, max, next);
    return result;
}

/* 返回地址数，或 DNS_NODATA / DNS_NXDOMAIN（确定性答案）/ DNS_FAIL（所有解析器都失败）。 */
static int resolve(const char *name, unsigned qtype, struct addr *out, int max) {
    int last = DNS_FAIL;
    for (int i = 0; i < resolver_count; i++) {
        char cur[256], next[256];
        int r = DNS_FAIL;
        snprintf(cur, sizeof cur, "%s", name);
        for (int hop = 0; hop < 4; hop++) {
            r = dns_query(&resolvers[i], cur, qtype, out, max, next);
            if (r != DNS_NODATA || !next[0]) break;
            snprintf(cur, sizeof cur, "%s", next);
        }
        if (r > 0 || r == DNS_NXDOMAIN || r == DNS_NODATA) return r;
        last = r;
    }
    return last;
}

static int add_resolver(const char *s) {
    struct addr a;
    if (!parse_addr(s, &a)) return 0;
    for (int i = 0; i < resolver_count; i++) if (addr_eq(&resolvers[i], &a)) return 1;
    if (resolver_count >= MAX_RESOLVERS) return 0;
    resolvers[resolver_count++] = a;
    return 1;
}
static void load_resolvers(void) {
    FILE *f = fopen("/etc/resolv.conf", "r");
    if (f) {
        char line[512], key[32], value[128];
        while (resolver_count < 3 && fgets(line, sizeof line, f))
            if (sscanf(line, "%31s %127s", key, value) == 2 && !strcmp(key, "nameserver")) add_resolver(value);
        fclose(f);
    }
    /* 系统解析器坏掉时的兜底。 */
    add_resolver("1.1.1.1");
    add_resolver("8.8.8.8");
}

/* ---------- IKEv2 ---------- */

enum { P_PENDING, P_ACCEPT, P_NOTIFY, P_OTHER, P_TIMEOUT, P_ICMP, P_LOCALERR };
enum { NAT_UNKNOWN, NAT_NONE, NAT_BEHIND };
#define REACHED(s) ((s) == P_ACCEPT || (s) == P_NOTIFY || (s) == P_OTHER)

struct probe {
    struct addr dst, local;
    unsigned port, local_port;
    int natt, fd, sends, state, notify, nat, err;
    int64_t next_send;
    size_t len;
    unsigned char spi[8], pkt[4 + IKE_MAX];
};

/* 和手机类似的 IKE_SA_INIT：一个提案里给出多种常见算法，KE 用 DH14，附带 NAT_DETECTION。
 * KE 值只需落在 (1, p-1) 内：我们不会完成密钥交换，用随机数即可，不必做大数运算。 */
static size_t build_ike(unsigned char *o, const unsigned char spi[8], const struct addr *src, unsigned sport,
                        const struct addr *dst, unsigned dport) {
    static const struct { unsigned char type; unsigned short id, keylen; } tf[] = {
        {1, 12, 256}, {1, 12, 128},   /* ENCR AES-CBC-256 / 128 */
        {2, 5, 0}, {2, 2, 0},         /* PRF HMAC-SHA256 / SHA1 */
        {3, 12, 0}, {3, 2, 0},        /* INTEG HMAC-SHA256-128 / SHA1-96 */
        {4, 14, 0}, {4, 5, 0}, {4, 2, 0}, /* DH 2048 / 1536 / 1024 */
    };
    const unsigned nt = sizeof tf / sizeof *tf;
    static const unsigned char zero[8];
    memset(o, 0, IKE_MAX);
    memcpy(o, spi, 8);
    o[16] = 33; o[17] = 0x20; o[18] = 34; o[19] = 0x08;
    size_t n = 28, sa = n, prop;
    o[sa] = 34; n += 4;
    prop = n; n += 8;
    o[prop + 4] = 1; o[prop + 5] = 1; o[prop + 7] = (unsigned char)nt;
    for (unsigned i = 0; i < nt; i++) {
        size_t len = tf[i].keylen ? 12 : 8;
        o[n] = i + 1 < nt ? 3 : 0;
        wr16(o + n + 2, (unsigned)len); o[n + 4] = tf[i].type; wr16(o + n + 6, tf[i].id);
        if (tf[i].keylen) { wr16(o + n + 8, 0x800e); wr16(o + n + 10, tf[i].keylen); }
        n += len;
    }
    wr16(o + prop + 2, (unsigned)(n - prop)); wr16(o + sa + 2, (unsigned)(n - sa));
    o[n] = 40; wr16(o + n + 2, 264); wr16(o + n + 4, 14);
    random_bytes(o + n + 8, 256);
    o[n + 8] = (unsigned char)((o[n + 8] & 0x3f) | 0x40);
    n += 264;
    o[n] = 41; wr16(o + n + 2, 36); random_bytes(o + n + 4, 32); n += 36;
    o[n] = 41; wr16(o + n + 2, 28); wr16(o + n + 6, 16388); natd_hash(spi, zero, src, sport, o + n + 8); n += 28;
    o[n] = 0; wr16(o + n + 2, 28); wr16(o + n + 6, 16389); natd_hash(spi, zero, dst, dport, o + n + 8); n += 28;
    wr32(o + 24, (uint32_t)n);
    return n;
}

/* 只要求包结构合法、SPI/交换类型/标志匹配；不在乎对方选了什么算法或返回了哪种错误。
 * Notify 的 Protocol ID 按 RFC 7296 忽略，未知载荷（即使 critical）也只跳过。 */
static void ike_parse(struct probe *p, const unsigned char *b, size_t n) {
    if (p->natt) { if (n < 4 || rd32(b)) return; b += 4; n -= 4; }
    if (n < 28 || memcmp(b, p->spi, 8) || (b[17] >> 4) != 2 || b[18] != 34 ||
        !(b[19] & 0x20) || (b[19] & 0x08) || rd32(b + 20) || rd32(b + 24) != n) return;
    unsigned next = b[16];
    size_t off = 28;
    int sa = 0, ke = 0, nonce = 0, err = 0, cookie = 0, natd = NAT_UNKNOWN;
    for (int count = 0; next; count++) {
        if (count >= 32 || n - off < 4) return;
        size_t len = rd16(b + off + 2);
        if (len < 4 || len > n - off) return;
        if (next == 33) sa = 1;
        else if (next == 34) ke = 1;
        else if (next == 40) nonce = 1;
        else if (next == 41) {
            if (len < 8 || 8u + b[off + 5] > len) return;
            unsigned type = rd16(b + off + 6);
            const unsigned char *data = b + off + 8 + b[off + 5];
            size_t dlen = len - 8 - b[off + 5];
            if (type && type < 16384) { if (!err) err = (int)type; }
            else if (type == 16390) cookie = 1;
            else if (type == 16389 && dlen == 20 && natd != NAT_NONE) {
                /* 对方看到的我方地址 == 本机地址 → VPS 没有经过 NAT */
                unsigned char h[20];
                natd_hash(b, b + 8, &p->local, p->local_port, h);
                natd = memcmp(h, data, 20) ? NAT_BEHIND : NAT_NONE;
            }
        }
        next = b[off];
        off += len;
    }
    if (off != n) return;
    p->notify = err ? err : cookie ? 16390 : 0;
    p->nat = natd;
    p->state = p->notify ? P_NOTIFY : sa && ke && nonce ? P_ACCEPT : P_OTHER;
}

static int icmp_errno(int e) { return e == ECONNREFUSED || e == EHOSTUNREACH || e == ENETUNREACH; }

/* 并发执行一批探测；每个探测在超时内均匀重传 SENDS 次。 */
static void run_probes(struct probe *ps, int np, int timeout_ms) {
    struct pollfd pf[BATCH_PROBES];
    int idx[BATCH_PROBES];
    unsigned char buf[4096];
    int64_t start = now_ms(), deadline = start + timeout_ms;
    int interval = timeout_ms / SENDS;
    for (int i = 0; i < np; i++) {
        struct probe *p = &ps[i];
        size_t off = p->natt ? 4 : 0;
        p->state = P_PENDING; p->sends = 0; p->notify = 0; p->nat = NAT_UNKNOWN; p->err = 0;
        p->next_send = start;
        random_bytes(p->spi, 8);
        p->fd = sock_open(&p->dst, p->port, SOCK_DGRAM);
        if (p->fd < 0 || !local_endpoint(p->fd, &p->local, &p->local_port)) {
            p->err = errno; p->state = P_LOCALERR;
            continue;
        }
        memset(p->pkt, 0, 4);
        p->len = off + build_ike(p->pkt + off, p->spi, &p->local, p->local_port, &p->dst, p->port);
    }
    for (;;) {
        int64_t t = now_ms(), wake = deadline;
        int k = 0;
        if (t >= deadline) break;
        for (int i = 0; i < np; i++) {
            struct probe *p = &ps[i];
            if (p->state != P_PENDING) continue;
            if (p->sends < SENDS && t >= p->next_send) {
                if (send(p->fd, p->pkt, p->len, 0) < 0 && errno != EAGAIN && errno != EINTR && errno != ENOBUFS) {
                    p->err = errno;
                    p->state = errno == ECONNREFUSED ? P_ICMP : P_LOCALERR;
                    continue;
                }
                p->sends++;
                p->next_send = t + interval;
            }
            if (p->sends < SENDS && p->next_send < wake) wake = p->next_send;
            pf[k].fd = p->fd; pf[k].events = POLLIN; pf[k].revents = 0;
            idx[k++] = i;
        }
        if (!k) break;
        if (poll(pf, (nfds_t)k, (int)(wake - t)) < 0 && errno != EINTR) break;
        for (int j = 0; j < k; j++) {
            if (!pf[j].revents) continue;
            struct probe *p = &ps[idx[j]];
            while (p->state == P_PENDING) {
                ssize_t len = recv_dgram(p->fd, buf, sizeof buf);
                if (len == -2) continue;
                if (len < 0) {
                    if (icmp_errno(errno)) { p->err = errno; p->state = P_ICMP; }
                    break;
                }
                ike_parse(p, buf, (size_t)len);
            }
        }
    }
    for (int i = 0; i < np; i++) {
        if (ps[i].state == P_PENDING) ps[i].state = P_TIMEOUT;
        if (ps[i].fd >= 0) close(ps[i].fd);
        ps[i].fd = -1;
    }
}

/* ---------- 检测目标与结论 ---------- */

enum { V_PASS, V_ONLY500, V_ONLY4500, V_NODNS, V_DNSFAIL, V_LOCALERR, V_ICMP, V_TIMEOUT, V_COUNT };

struct target {
    char label[96];
    const char *country; /* --host 时为 NULL */
    char fqdn[MAX_FQDN][256];
    int nfqdn, dns[MAX_FQDN], naddr, first, resolved;
    struct addr addrs[MAX_ADDRS];
};

static struct target targets[MAX_TARGETS];
static int target_count;
static int want_ipv6, details, timeout_ms = 3000;
static unsigned ike_port = 500, natt_port = 4500;

static void resolve_target(struct target *t) {
    if (t->resolved) return;
    t->resolved = 1;
    t->naddr = 0;
    for (int f = 0; f < t->nfqdn; f++) {
        struct addr tmp[MAX_ADDRS], lit;
        if (parse_addr(t->fqdn[f], &lit)) { t->addrs[t->naddr++] = lit; t->dns[f] = 1; continue; }
        int r4 = resolve(t->fqdn[f], 1, tmp, MAX_ADDRS), got = r4 > 0 ? r4 : 0;
        int r6 = want_ipv6 && got < MAX_ADDRS ? resolve(t->fqdn[f], 28, tmp + got, MAX_ADDRS - got) : DNS_NODATA;
        if (r6 > 0) got += r6;
        /* 有地址 > 有解析失败 > 域名不存在 > 无记录 */
        t->dns[f] = got ? got : r4 == DNS_FAIL || r6 == DNS_FAIL ? DNS_FAIL :
                    r4 == DNS_NXDOMAIN || r6 == DNS_NXDOMAIN ? DNS_NXDOMAIN : DNS_NODATA;
        for (int i = 0; i < got && t->naddr < MAX_ADDRS; i++) {
            int dup = 0;
            for (int j = 0; j < t->naddr; j++) dup |= addr_eq(&t->addrs[j], &tmp[i]);
            if (!dup) t->addrs[t->naddr++] = tmp[i];
        }
    }
}

static const char *notify_name(int type) {
    switch (type) {
    case 5: return "INVALID_IKE_SPI";
    case 7: return "INVALID_SYNTAX";
    case 14: return "NO_PROPOSAL_CHOSEN";
    case 17: return "INVALID_KE_PAYLOAD";
    case 24: return "AUTHENTICATION_FAILED";
    case 16390: return "COOKIE";
    default: return NULL;
    }
}
static const char *probe_text(const struct probe *p, char buf[64]) {
    const char *name;
    switch (p->state) {
    case P_ACCEPT: return "完整握手响应";
    case P_NOTIFY:
        if ((name = notify_name(p->notify))) snprintf(buf, 64, "有响应(%s)", name);
        else snprintf(buf, 64, "有响应(通知 %d)", p->notify);
        return buf;
    case P_OTHER: return "有响应";
    case P_ICMP: return "ICMP 拒绝/不可达";
    case P_LOCALERR: snprintf(buf, 64, "本机发送失败(%s)", strerror(p->err)); return buf;
    default: return "超时";
    }
}

static int judge(const struct target *t, const struct probe *ps) {
    int any500 = 0, any4500 = 0, icmp = 0, local = 0;
    if (!t->naddr) {
        for (int f = 0; f < t->nfqdn; f++) if (t->dns[f] == DNS_FAIL) return V_DNSFAIL;
        return V_NODNS;
    }
    for (int i = 0; i < t->naddr; i++) {
        const struct probe *a = &ps[t->first + 2 * i], *b = a + 1;
        if (REACHED(a->state) && REACHED(b->state)) return V_PASS;
        any500 |= REACHED(a->state); any4500 |= REACHED(b->state);
        icmp += (a->state == P_ICMP) + (b->state == P_ICMP);
        local += (a->state == P_LOCALERR) + (b->state == P_LOCALERR);
    }
    if (any500) return V_ONLY500;
    if (any4500) return V_ONLY4500;
    if (local == 2 * t->naddr) return V_LOCALERR;
    if (icmp) return V_ICMP;
    return V_TIMEOUT;
}

static void report(const struct target *t, const struct probe *ps, int verdict) {
    static const char *const text[V_COUNT] = {
        "✅ 通过：UDP 500 和 4500 都收到 IKE 响应",
        "⚠️ 部分：500 有响应，4500 没有（手机经过 NAT 时会切到 4500，可能注册失败）",
        "⚠️ 部分：4500 有响应，500 没有（手机首包走 500，可能无法发起）",
        "⚪ 跳过：ePDG 域名不存在（运营商未公开或使用其他域名），无法检测",
        "⚠️ DNS 查询失败，拿不到运营商服务器地址",
        "❌ 本机无法发出 UDP（检查网络/防火墙）",
        "❌ 失败：收到 ICMP 拒绝/不可达，UDP 500/4500 被拒",
        "❌ 失败：500/4500 均无响应（可能被 VPS 线路封 UDP，或运营商按地区/IP 屏蔽）",
    };
    const char *shade = verdict == V_PASS ? GREEN : verdict == V_NODNS ? GRAY :
                        verdict >= V_LOCALERR ? RED : YELLOW;
    printf("%s[%s]%s %s%s%s\n", BOLD_CYAN, t->label, RESET, shade, text[verdict], RESET);
    if (!details) return;
    for (int f = 0; f < t->nfqdn; f++) {
        const char *d = t->dns[f] > 0 ? NULL : t->dns[f] == DNS_NXDOMAIN ? "NXDOMAIN（不存在）" :
                        t->dns[f] == DNS_NODATA ? "无 A/AAAA 记录" : "解析失败/超时";
        if (d) printf("    %s%s：%s%s\n", GRAY, t->fqdn[f], d, RESET);
        else printf("    %s%s：%d 个地址%s\n", GRAY, t->fqdn[f], t->dns[f], RESET);
    }
    for (int i = 0; i < t->naddr; i++) {
        const struct probe *a = &ps[t->first + 2 * i], *b = a + 1;
        char ip[INET6_ADDRSTRLEN], x[64], y[64];
        int nat = a->nat ? a->nat : b->nat;
        printf("    %s%-15s UDP %u: %s | UDP %u: %s%s%s\n", GRAY, addr_str(&t->addrs[i], ip),
               a->port, probe_text(a, x), b->port, probe_text(b, y),
               nat == NAT_BEHIND ? " | 本机出口经过 NAT" : nat == NAT_NONE ? " | 本机无 NAT" : "", RESET);
    }
}

/* ---------- 选择目标 ---------- */

static int country_index(const char *name) {
    for (size_t i = 0; i < COUNTRY_COUNT; i++) if (!strcmp(countries[i].name, name)) return (int)i;
    return -1;
}
static void add_carrier(const struct carrier *c) {
    struct target *t = &targets[target_count++];
    memset(t, 0, sizeof *t);
    snprintf(t->label, sizeof t->label, "%s %s", c->country, c->name);
    t->country = c->country;
    snprintf(t->fqdn[t->nfqdn++], 256, "epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", c->mnc, c->mcc);
    if (c->extra) snprintf(t->fqdn[t->nfqdn++], 256, "%s", c->extra);
}

/* 菜单顺序：按洲分组，组内按拼音。 */
static int menu_order(int order[COUNTRY_COUNT]) {
    int n = 0;
    for (int c = 0; c < CONTINENT_COUNT; c++)
        for (size_t i = 0; i < COUNTRY_COUNT; i++) {
            if (countries[i].continent != c) continue;
            int pos = n++;
            while (pos && countries[order[pos - 1]].continent == c &&
                   strcmp(countries[order[pos - 1]].pinyin, countries[i].pinyin) > 0) {
                order[pos] = order[pos - 1]; pos--;
            }
            order[pos] = (int)i;
        }
    return n;
}

/* 返回 1 已选择，0 取消。selected[] 按 countries 下标标记；all 置 1 表示全部。 */
static int run_menu(FILE *in, FILE *out, int selected[COUNTRY_COUNT], int *all) {
    int order[COUNTRY_COUNT], n = menu_order(order), last = -1;
    fputs("请选择手机卡所属国家（是 SIM 卡的国家，不是 VPS 所在地）：\n", out);
    for (int i = 0; i < n; i++) {
        const struct country *c = &countries[order[i]];
        int count = 0;
        for (size_t j = 0; j < CARRIER_COUNT; j++) count += !strcmp(carriers[j].country, c->name);
        if (c->continent != last) fprintf(out, "%s%s%s\n", BOLD_CYAN, continent_names[last = c->continent], RESET);
        fprintf(out, "  %2d. %s（%d 家）\n", i + 1, c->name, count);
    }
    fputs("   0. 全部国家\n   q. 退出\n", out);
    for (;;) {
        char line[256], *tok, *save;
        int ok = 1, any = 0;
        fputs("输入编号或国家名，多个用空格/逗号分隔：", out);
        fflush(out);
        if (!fgets(line, sizeof line, in)) return 0;
        if (!strchr(line, '\n') && !feof(in)) {
            int ch;
            while ((ch = fgetc(in)) != EOF && ch != '\n') {}
            fputs("输入过长，请重新输入。\n", out);
            continue;
        }
        /* 全角逗号 "，"(EF BC 8C) 也当分隔符 */
        for (char *p = line; (p = strstr(p, "\xef\xbc\x8c"));) memset(p, ' ', 3);
        memset(selected, 0, sizeof(int) * COUNTRY_COUNT);
        *all = 0;
        for (tok = strtok_r(line, " ,\t\r\n", &save); tok; tok = strtok_r(NULL, " ,\t\r\n", &save)) {
            char *end;
            long v = strtol(tok, &end, 10);
            int ci;
            if (!strcmp(tok, "q") || !strcmp(tok, "Q")) return 0;
            if (!*end && end != tok && v >= 0 && v <= n) { if (v) selected[order[v - 1]] = 1; else *all = 1; }
            else if ((ci = country_index(tok)) >= 0) selected[ci] = 1;
            else { fprintf(out, "无效输入：%s\n", tok); ok = 0; break; }
            any = 1;
        }
        if (ok && any) return 1;
    }
}

static void usage(void) {
    puts("WiFi Calling 网络探测 " VERSION "\n"
         "用法: check [选择] [选项]\n"
         "选择（四选一，不给则弹出菜单）：\n"
         "  --country 国家     按国家检测，可重复，如 --country 英国 --country 美国\n"
         "  --filter 关键词    按名称筛选，如 Vodafone、T-Mobile\n"
         "  --host 域名或IP    检测指定 ePDG\n"
         "  --all              检测全部运营商\n"
         "选项：\n"
         "  --details          显示每个域名、IP、端口的明细（含 NAT 判断）\n"
         "  --ipv6             同时检测 IPv6 地址（AAAA）\n"
         "  --dns IP           只用指定 DNS（可重复，最多 5 个）\n"
         "  --timeout 毫秒     每个端口的总等待时间，期间重传 3 次（默认 3000，范围 500-20000）\n"
         "  --list             列出运营商与 ePDG 域名\n"
         "  NO_COLOR=1         关闭颜色\n"
         "说明：只验证 VPS 与运营商 ePDG 之间的 IKE（UDP 500/4500）往返是否通，\n"
         "不验证 SIM 认证、IMS 注册和真实通话。");
}

static long parse_num(const char *s, long lo, long hi) {
    char *end;
    long v = strtol(s, &end, 10);
    return *s && !*end && v >= lo && v <= hi ? v : -1;
}

int main(int argc, char **argv) {
    const char *filter = NULL, *host = NULL;
    int selected[COUNTRY_COUNT] = {0}, by_country = 0, all = 0;
    signal(SIGPIPE, SIG_IGN);
    use_color = isatty(STDOUT_FILENO) && !getenv("NO_COLOR");

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        long num;
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(); return 0; }
        if (!strcmp(a, "--version")) { puts(VERSION); return 0; }
        if (!strcmp(a, "--list")) {
            for (size_t c = 0; c < CARRIER_COUNT; c++) {
                printf("%s %s  epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", carriers[c].country, carriers[c].name,
                       carriers[c].mnc, carriers[c].mcc);
                if (carriers[c].extra) printf("  %s", carriers[c].extra);
                putchar('\n');
            }
            return 0;
        }
        if (!strcmp(a, "--details")) { details = 1; continue; }
        if (!strcmp(a, "--all")) { all = 1; continue; }
        if (!strcmp(a, "--ipv6")) { want_ipv6 = 1; continue; }
        if (!v) { fprintf(stderr, "%s 缺少参数值，见 --help\n", a); return 2; }
        i++;
        if (!strcmp(a, "--country")) {
            int ci = country_index(v);
            if (ci < 0) { fprintf(stderr, "未知国家：%s（用 --list 查看）\n", v); return 2; }
            selected[ci] = by_country = 1;
        } else if (!strcmp(a, "--filter")) filter = v;
        else if (!strcmp(a, "--host")) host = v;
        else if (!strcmp(a, "--dns")) {
            if (!add_resolver(v)) { fprintf(stderr, "无效 DNS 地址或超过 %d 个：%s\n", MAX_RESOLVERS, v); return 2; }
        } else if (!strcmp(a, "--timeout")) {
            if ((num = parse_num(v, 500, 20000)) < 0) { fputs("--timeout 范围 500-20000\n", stderr); return 2; }
            timeout_ms = (int)num;
        }
        /* 以下仅供测试使用 */
        else if (!strcmp(a, "--ike-port") && (num = parse_num(v, 1, 65535)) > 0) ike_port = (unsigned)num;
        else if (!strcmp(a, "--natt-port") && (num = parse_num(v, 1, 65535)) > 0) natt_port = (unsigned)num;
        else if (!strcmp(a, "--dns-port") && (num = parse_num(v, 1, 65535)) > 0) dns_port = (unsigned)num;
        else { fprintf(stderr, "未知参数或参数值无效：%s %s\n", a, v); return 2; }
    }
    if (by_country + all + !!filter + !!host > 1) {
        fputs("--country、--filter、--host、--all 只能选一种。\n", stderr);
        return 2;
    }
    if (filter && !*filter) { fputs("--filter 不能为空。\n", stderr); return 2; }

    if (!by_country && !all && !filter && !host) {
        /* 通过 curl | sh 运行时 stdin 被占用，直接读控制终端。 */
        FILE *in = fopen("/dev/tty", "r"), *out = in ? fopen("/dev/tty", "w") : NULL;
        if (!in && isatty(STDIN_FILENO)) in = stdin;
        if (!in) {
            fputs("没有交互终端；请用 --country 国家、--filter、--host 或 --all 指定检测目标。\n", stderr);
            return 2;
        }
        int chosen = run_menu(in, out ? out : stderr, selected, &all);
        if (out) fclose(out);
        if (in != stdin) fclose(in);
        if (!chosen) { puts("已取消。"); return 0; }
        by_country = !all;
    }

    if (host) {
        struct target *t = &targets[target_count++];
        struct addr lit;
        memset(t, 0, sizeof *t);
        snprintf(t->label, sizeof t->label, "%s", host);
        if (parse_addr(host, &lit)) addr_str(&lit, t->fqdn[0]);
        else if (!normalize_host(host, t->fqdn[0])) { fputs("无效的域名或 IP。\n", stderr); return 2; }
        t->nfqdn = 1;
    } else {
        for (size_t c = 0; c < CARRIER_COUNT; c++) {
            char label[96];
            snprintf(label, sizeof label, "%s %s", carriers[c].country, carriers[c].name);
            if (by_country && !selected[country_index(carriers[c].country)]) continue;
            if (filter && !strstr(label, filter)) continue;
            add_carrier(&carriers[c]);
        }
        if (!target_count) { fputs("没有匹配的运营商（用 --list 查看）。\n", stderr); return 2; }
    }
    if (!resolver_count) load_resolvers();

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("%sWiFi 通话网络检测 " VERSION "%s\n", BOLD_CYAN, RESET);
    printf("共 %d 个目标，每个端口最多等待 %.1f 秒，请稍候…\n\n", target_count, timeout_ms / 1000.0);

    static struct probe probes[BATCH_PROBES];
    int counts[V_COUNT] = {0}, nat_seen = NAT_UNKNOWN;
    for (int start = 0; start < target_count;) {
        int end = start, np = 0;
        while (end < target_count && end - start < BATCH_TARGETS) {
            struct target *t = &targets[end];
            resolve_target(t);
            if (end > start && np + 2 * t->naddr > BATCH_PROBES) break;
            t->first = np;
            for (int i = 0; i < t->naddr; i++)
                for (int k = 0; k < 2; k++) {
                    struct probe *p = &probes[np++];
                    p->dst = t->addrs[i];
                    p->natt = k;
                    p->port = k ? natt_port : ike_port;
                }
            end++;
        }
        run_probes(probes, np, timeout_ms);
        for (int i = start; i < end; i++) {
            int v = judge(&targets[i], probes);
            counts[v]++;
            report(&targets[i], probes, v);
        }
        for (int i = 0; i < np; i++) if (probes[i].nat != NAT_UNKNOWN) nat_seen = probes[i].nat;
        start = end;
    }

    int tested = target_count - counts[V_NODNS] - counts[V_DNSFAIL], multi_country = 0;
    for (int i = 1; i < target_count; i++)
        multi_country |= !targets[0].country || !targets[i].country || strcmp(targets[0].country, targets[i].country);
    int partial = counts[V_ONLY500] + counts[V_ONLY4500];
    int failed = counts[V_TIMEOUT] + counts[V_ICMP] + counts[V_LOCALERR];
    printf("\n%s汇总%s：%d 个目标，实际探测 %d 个 —— 通过 %d，部分 %d，失败 %d",
           BOLD_CYAN, RESET, target_count, tested, counts[V_PASS], partial, failed);
    if (counts[V_NODNS] || counts[V_DNSFAIL])
        printf("；无法解析 %d", counts[V_NODNS] + counts[V_DNSFAIL]);
    puts("。");

    /* 结合所有运营商的结果判断问题在哪一侧。 */
    if (counts[V_PASS])
        printf("%s✅ 这台 VPS 到通过的运营商之间 IKE 往返正常，可以用对应的手机卡实际试一下。%s\n", GREEN, RESET);
    if (counts[V_LOCALERR] == tested && tested)
        printf("%s❌ 本机发不出 UDP 包，请检查 VPS 网络或本机防火墙出站规则。%s\n", RED, RESET);
    else if (!counts[V_PASS] && !partial && tested >= 2 && multi_country)
        printf("%s❌ 多个国家的运营商全都不通，最可能是 VPS 线路/机房封锁了 UDP 500/4500，"
               "而不是运营商的问题；建议换线路或机房。%s\n", RED, RESET);
    else if (!counts[V_PASS] && !partial && tested >= 1)
        printf("%s❌ 未通。只测了一个国家，无法区分是 VPS 封 UDP 还是该国运营商屏蔽境外 IP，"
               "可加 --all 对比：其他国家能通就说明 VPS 没问题。%s\n", RED, RESET);
    else if (failed && (counts[V_PASS] || partial))
        printf("%s⚠️ 部分运营商不通而其他运营商通，说明 VPS 的 UDP 500/4500 没被封，"
               "不通的那几家可能按地区/IP 段屏蔽。%s\n", YELLOW, RESET);
    if (partial)
        printf("%s⚠️ \"部分\"表示只有一个端口通；WiFi 通话需要 500 和 4500 都通。%s\n", YELLOW, RESET);
    if (nat_seen == NAT_BEHIND && details)
        puts("提示：本机出口经过 NAT（云厂商 1:1 NAT 很常见），这本身不影响使用，ePDG 会走 4500。");
    if (tested == 0)
        puts("所有目标都无法解析域名，没有进行探测。可加 --details 查看原因，或用 --dns 指定 DNS。");
    if (!details) puts("加 --details 可查看每个 IP 和端口的明细。");
    puts("注意：通过只说明网络层通，能否通话以手机实际注册 WiFi 通话为准。");
    return counts[V_PASS] ? 0 : 1;
}

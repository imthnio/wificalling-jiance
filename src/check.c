#define _POSIX_C_SOURCE 200809L
/* Bounded, unprivileged IPv4 ePDG reachability probe. No IKE_AUTH/session keys. */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define VERSION "2.0.0"
#define MAX_IPS 2
#define MAX_DNS 4
#define DNS_SIZE 4096
#define IKE_SIZE 376
#include "carriers.h"

static uint16_t rd16(const unsigned char *p) { return (uint16_t)((p[0]<<8)|p[1]); }
static uint32_t rd32(const unsigned char *p) { return ((uint32_t)rd16(p)<<16)|rd16(p+2); }
static void wr16(unsigned char *p, unsigned v) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }
static void wr32(unsigned char *p, uint32_t v) { wr16(p,v>>16); wr16(p+2,v&65535); }
static int64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)) { perror("clock_gettime"); exit(1); }
    return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
static void random_bytes(void *p, size_t n) {
    int fd=open("/dev/urandom",O_RDONLY);
    if(fd<0) { perror("/dev/urandom"); exit(1); }
    unsigned char *out=p;
    while(n) {
        ssize_t r=read(fd,out,n);
        if(r<0 && errno==EINTR) continue;
        if(r<=0) { fputs("无法读取系统随机数\n",stderr); close(fd); exit(1); }
        out+=r; n-=(size_t)r;
    }
    close(fd);
}
static int wait_read(int fd,int64_t deadline) {
    for(;;) {
        int64_t left=deadline-now_ms();
        if(left<=0) return 0;
        struct pollfd p={fd,POLLIN,0};
        int n=poll(&p,1,(int)left);
        if(n<0 && errno==EINTR) continue;
        return n>0 && (p.revents&(POLLIN|POLLERR|POLLHUP));
    }
}
static int udp_connect(const char *ip,unsigned port) {
    struct sockaddr_storage ss;
    memset(&ss,0,sizeof ss);
    struct sockaddr_in *a=(struct sockaddr_in*)&ss;
    struct sockaddr_in6 *b=(struct sockaddr_in6*)&ss;
    int family; socklen_t len;
    if(inet_pton(AF_INET,ip,&a->sin_addr)==1) {
        family=AF_INET; a->sin_family=AF_INET; a->sin_port=htons((uint16_t)port); len=sizeof *a;
    } else if(inet_pton(AF_INET6,ip,&b->sin6_addr)==1) {
        family=AF_INET6; b->sin6_family=AF_INET6; b->sin6_port=htons((uint16_t)port); len=sizeof *b;
    } else return -1;
    int fd=socket(family,SOCK_DGRAM,0);
    if(fd<0) return -1;
    if(connect(fd,(struct sockaddr*)&ss,len) || fcntl(fd,F_SETFL,O_NONBLOCK)<0) { close(fd); return -1; }
    return fd;
}

/* RFC 3526 group 14; fixed stack storage. Only creates public probe material.
 * This is NOT a constant-time cryptographic library or a VPN implementation. */
typedef uint32_t bigint[64];
static const char prime_hex[]=
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE"
"39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
"3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
static void get_prime(bigint p) {
    for(int i=0;i<64;i++) { char word[9]; memcpy(word,prime_hex+512-8*(i+1),8); word[8]=0; p[i]=(uint32_t)strtoul(word,NULL,16); }
}
static int ge(const bigint a,const bigint b) {
    for(int i=63;i>=0;i--) if(a[i]!=b[i]) return a[i]>b[i];
    return 1;
}
static void addmod(bigint out,const bigint a,const bigint b,const bigint p) {
    uint64_t carry=0;
    for(int i=0;i<64;i++) { uint64_t v=(uint64_t)a[i]+b[i]+carry; out[i]=(uint32_t)v; carry=v>>32; }
    if(carry || ge(out,p)) {
        uint64_t borrow=0;
        for(int i=0;i<64;i++) { uint64_t sub=(uint64_t)p[i]+borrow; uint32_t old=out[i]; out[i]=(uint32_t)((uint64_t)old-sub); borrow=(uint64_t)old<sub; }
    }
}
static void mulmod(bigint out,const bigint a,const bigint b,const bigint p) {
    bigint acc={0},term; memcpy(term,a,sizeof term);
    for(int i=0;i<64;i++) for(int j=0;j<32;j++) {
        if((b[i]>>j)&1) addmod(acc,acc,term,p);
        addmod(term,term,term,p);
    }
    memcpy(out,acc,sizeof acc);
}
static void dh_public(unsigned char out[256],const unsigned char exponent[32]) {
    bigint p,acc={1}; get_prime(p);
    for(int i=0;i<32;i++) for(int j=7;j>=0;j--) {
        mulmod(acc,acc,acc,p);
        if((exponent[i]>>j)&1) addmod(acc,acc,acc,p);
    }
    for(int i=0;i<64;i++) wr32(out+256-4*(i+1),acc[i]);
}
static void build_ike(unsigned char out[IKE_SIZE],const unsigned char public_key[256]) {
    memset(out,0,IKE_SIZE); random_bytes(out,8);
    out[16]=33; out[17]=0x20; out[18]=34; out[19]=0x08; wr32(out+24,IKE_SIZE);
    /* SA -> KE -> Nonce, not SA -> Nonce -> KE. */
    unsigned char *sa=out+28;
    sa[0]=34; wr16(sa+2,48);
    unsigned char *proposal=sa+4;
    wr16(proposal+2,44); proposal[4]=1; proposal[5]=1; proposal[7]=4;
    unsigned char *t=proposal+8;
    t[0]=3; wr16(t+2,12); t[4]=1; wr16(t+6,12); wr16(t+8,0x800e); wr16(t+10,128);
    t+=12; t[0]=3; wr16(t+2,8); t[4]=2; wr16(t+6,5); /* PRF HMAC-SHA256 */
    t+=8; t[0]=3; wr16(t+2,8); t[4]=3; wr16(t+6,12); /* AUTH HMAC-SHA256-128 */
    t+=8; wr16(t+2,8); t[4]=4; wr16(t+6,14);
    unsigned char *ke=out+76;
    ke[0]=40; wr16(ke+2,264); wr16(ke+4,14); memcpy(ke+8,public_key,256);
    unsigned char *nonce=out+340;
    wr16(nonce+2,36); random_bytes(nonce+4,32);
}
/* Header, SPI, exchange, message ID, payload bounds and NAT-T marker validation.
 * A matching, structurally valid unauthenticated reply proves a return path only. */
static int valid_ike(const unsigned char *b,size_t n,const unsigned char spi[8],int natt) {
    if(natt) { if(n<4 || rd32(b)!=0) return 0; b+=4; n-=4; }
    if(n<32 || memcmp(b,spi,8) || (b[17]>>4)!=2 || b[18]!=34 ||
       !(b[19]&0x20) || (b[19]&0x08) || rd32(b+20)!=0 || rd32(b+24)!=n) return 0;
    size_t off=28; unsigned next=b[16]; int count=0,seen_sa=0,seen_ke=0,seen_nonce=0,seen_notify=0;
    if(!next) return 0;
    while(next) {
        if(++count>64 || off+4>n) return 0;
        size_t len=rd16(b+off+2);
        if(len<4 || len>n-off) return 0;
        if(next==41) { /* Notify: protocol, SPI size, type, optional SPI/data. */
            if(len<8 || b[off+4]!=0 || b[off+5]!=0 || rd16(b+off+6)==0) return 0;
            seen_notify=1;
        } else if(next==34) {
            if(len<9 || rd16(b+off+4)==0) return 0;
            seen_ke=1;
        } else if(next==40) {
            if(len<20 || len>260) return 0;
            seen_nonce=1;
        } else if(next==33) {
            if(len<20) return 0;
            size_t pos=off+4;
            while(pos<off+len) {
                if(pos+8>off+len) return 0;
                size_t plen=rd16(b+pos+2),tpos=pos+8+b[pos+6];
                if(plen<8 || plen>off+len-pos || tpos>pos+plen || b[pos+5]!=1 || !b[pos+7]) return 0;
                unsigned transforms=0;
                while(tpos<pos+plen) {
                    if(tpos+8>pos+plen) return 0;
                    size_t tlen=rd16(b+tpos+2);
                    if(tlen<8 || tlen>pos+plen-tpos || b[tpos]!=(tpos+tlen<pos+plen?3:0)) return 0;
                    transforms++; tpos+=tlen;
                }
                if(transforms!=b[pos+7] || b[pos]!=(pos+plen<off+len?2:0)) return 0;
                pos+=plen;
            }
            seen_sa=1;
        } else if(b[off+1]&0x80) return 0;
        next=b[off]; off+=len;
    }
    return off==n && (seen_notify || (seen_sa && seen_ke && seen_nonce));
}
static int ike_probe(const char *ip,unsigned port,int natt,int timeout_ms,const unsigned char key[256]) {
    unsigned char packet[IKE_SIZE+4]={0},reply[4096];
    size_t offset=natt?4:0;
    build_ike(packet+offset,key);
    int fd=udp_connect(ip,port);
    if(fd<0) return -1;
    int64_t deadline=now_ms()+timeout_ms;
    if(send(fd,packet,IKE_SIZE+offset,0)!=(ssize_t)(IKE_SIZE+offset)) { close(fd); return -1; }
    int ok=0;
    while(wait_read(fd,deadline)) {
        ssize_t n=recv(fd,reply,sizeof reply,0);
        if(n<0) { if(errno==EINTR || errno==EAGAIN) continue; break; }
        if(valid_ike(reply,(size_t)n,packet+offset,natt)) { ok=1; break; }
    }
    close(fd); return ok;
}

/* DNS: connected UDP filters source IP/port; validate ID, flags, question and
 * owner/CNAME chain. Compression parsing has strict byte and hop bounds. */
static int dns_name(const unsigned char *b,size_t n,size_t *offset,char out[254]) {
    size_t pos=*offset,used=0,end=0; int jumped=0;
    for(int hops=0;hops<128;hops++) {
        if(pos>=n) return 0;
        unsigned len=b[pos++];
        if((len&0xc0)==0xc0) {
            if(pos>=n) return 0;
            size_t target=((len&63)<<8)|b[pos++];
            if(target>=n) return 0;
            if(!jumped) end=pos;
            jumped=1; pos=target; continue;
        }
        if(len&0xc0 || len>63 || pos+len>n) return 0;
        if(!len) { out[used]=0; *offset=jumped?end:pos; return 1; }
        if(used) { if(used>=253) return 0; out[used++]='.'; }
        if(used+len>253) return 0;
        for(unsigned i=0;i<len;i++) {
            unsigned char c=b[pos++];
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_')) return 0;
            out[used++]=(char)tolower(c);
        }
    }
    return 0;
}
static size_t dns_request(unsigned char *b,const char *host,uint16_t id) {
    size_t n=12; memset(b,0,12); wr16(b,id); wr16(b+2,0x0100); wr16(b+4,1);
    const char *p=host;
    if(!*p || strlen(host)>253) return 0;
    while(*p) {
        const char *dot=strchr(p,'.'); size_t len=dot?(size_t)(dot-p):strlen(p);
        if(!len || len>63 || n+len+6>512) return 0;
        b[n++]=(unsigned char)len; memcpy(b+n,p,len); n+=len;
        if(!dot) break;
        p=dot+1; if(!*p) return 0;
    }
    b[n++]=0; wr16(b+n,1); wr16(b+n+2,1); return n+4;
}
struct dns_record { char owner[254],target[254]; unsigned type; struct in_addr addr; };
/* -1 = invalid/truncated/server error, 0 = valid answer without IPv4, >0 = IP count */
static int parse_dns(const unsigned char *b,size_t n,uint16_t id,const char *host,struct in_addr ips[MAX_IPS]) {
    if(n<12 || rd16(b)!=id || !(b[2]&0x80) || (b[2]&0x7a) || rd16(b+4)!=1) return -1;
    unsigned rcode=b[3]&15,answers=rd16(b+6);
    if(rcode!=0 && rcode!=3) return -1;
    size_t off=12; char question[254];
    if(!dns_name(b,n,&off,question) || strcasecmp(host,question) || off+4>n || rd16(b+off)!=1 || rd16(b+off+2)!=1) return -1;
    off+=4;
    if(rcode==3) return 0;
    if(answers>64) return -1;
    struct dns_record records[64]; unsigned nr=0;
    for(unsigned i=0;i<answers;i++) {
        struct dns_record rec; memset(&rec,0,sizeof rec);
        if(!dns_name(b,n,&off,rec.owner) || off+10>n) return -1;
        unsigned type=rd16(b+off),cls=rd16(b+off+2),len=rd16(b+off+8);
        off+=10; if(len>n-off) return -1;
        if(cls==1 && type==1 && len==4) { rec.type=1; memcpy(&rec.addr,b+off,4); records[nr++]=rec; }
        else if(cls==1 && type==5) {
            size_t tmp=off;
            if(!dns_name(b,n,&tmp,rec.target) || tmp!=off+len) return -1;
            rec.type=5; records[nr++]=rec;
        }
        off+=len;
    }
    char current[254]; snprintf(current,sizeof current,"%s",host);
    for(int depth=0;depth<16;depth++) {
        int count=0; const char *alias=NULL;
        for(unsigned i=0;i<nr;i++) if(!strcasecmp(records[i].owner,current)) {
            if(records[i].type==5) alias=records[i].target;
            if(records[i].type==1 && count<MAX_IPS) {
                int duplicate=0;
                for(int j=0;j<count;j++) if(ips[j].s_addr==records[i].addr.s_addr) duplicate=1;
                if(!duplicate) ips[count++]=records[i].addr;
            }
        }
        if(count) return count;
        if(!alias) return 0;
        snprintf(current,sizeof current,"%s",alias);
    }
    return -1;
}
static int dns_query(const char *server,const char *host,int timeout_ms,struct in_addr ips[MAX_IPS]) {
    unsigned char q[512],reply[DNS_SIZE]; uint16_t id; random_bytes(&id,sizeof id);
    size_t n=dns_request(q,host,id); if(!n) return -1;
    int fd=udp_connect(server,53); if(fd<0) return -1;
    int64_t deadline=now_ms()+timeout_ms;
    if(send(fd,q,n,0)!=(ssize_t)n) { close(fd); return -1; }
    int result=-1;
    while(wait_read(fd,deadline)) {
        ssize_t size=recv(fd,reply,sizeof reply,0);
        if(size<0) { if(errno==EINTR || errno==EAGAIN) continue; break; }
        result=parse_dns(reply,(size_t)size,id,host,ips);
        if(result>=0) break;
    }
    close(fd); return result;
}
static char resolvers[MAX_DNS][INET6_ADDRSTRLEN];
static int resolver_count;
static int add_resolver(const char *ip) {
    unsigned char addr[16];
    if(inet_pton(AF_INET,ip,addr)!=1 && inet_pton(AF_INET6,ip,addr)!=1) return 0;
    for(int i=0;i<resolver_count;i++) if(!strcmp(resolvers[i],ip)) return 1;
    if(resolver_count<MAX_DNS) snprintf(resolvers[resolver_count++],INET6_ADDRSTRLEN,"%s",ip);
    return 1;
}
static void load_resolvers(void) {
    FILE *f=fopen("/etc/resolv.conf","r");
    if(f) {
        char line[512],word[64],ip[64];
        while(resolver_count<2 && fgets(line,sizeof line,f))
            if(sscanf(line,"%63s %63s",word,ip)==2 && !strcmp(word,"nameserver")) add_resolver(ip);
        fclose(f);
    }
    add_resolver("1.1.1.1"); add_resolver("8.8.8.8");
}
static int resolve_host(const char *host,int ms,struct in_addr ips[MAX_IPS]) {
    if(inet_pton(AF_INET,host,ips)==1) return 1;
    for(int i=0;i<resolver_count;i++) { int n=dns_query(resolvers[i],host,ms,ips); if(n>0) return n; }
    return 0;
}
static unsigned positive_int(const char *s,unsigned max) {
    if(!*s) return 0;
    unsigned value=0;
    for(;*s;s++) { if(*s<'0'||*s>'9' || value>max/10) return 0; value=value*10+(unsigned)(*s-'0'); if(value>max) return 0; }
    return value;
}
static void usage(void) {
    puts("WiFi Calling 网络探测 " VERSION "（低内存 / IPv4）\n"
         "用法: check [--filter 名称] [--host 域名或IPv4] [--dns DNS地址] [--timeout 毫秒]\n"
         "      check --list | --version | --help\n"
         "默认串行检测，每次请求最多等待 1500 毫秒；完整扫描可能需要数分钟。\n"
         "--filter 示例: 德国、英国、T-Mobile；--host 覆盖默认运营商候选名单。\n"
         "--dns 仅使用指定解析器（可重复最多4个）；--timeout 范围 1..10000。\n"
         "只验证未认证 IKEv2 响应，不能证明 SIM 注册、通话、IPv6 或代理 UDP 转发可用。");
}
int main(int argc,char **argv) {
    const char *filter=NULL,*host=NULL; int timeout_ms=1500;
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--help")) { usage(); return 0; }
        if(!strcmp(argv[i],"--version")) { puts(VERSION); return 0; }
        if(!strcmp(argv[i],"--list")) {
            for(size_t c=0;c<sizeof carriers/sizeof *carriers;c++) printf("%s  epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org\n",carriers[c].name,carriers[c].mnc,carriers[c].mcc);
            return 0;
        }
        if(i+1>=argc) { usage(); return 2; }
        const char *opt=argv[i++],*value=argv[i];
        if(!strcmp(opt,"--filter")) filter=value;
        else if(!strcmp(opt,"--host")) host=value;
        else if(!strcmp(opt,"--dns")) { if(resolver_count>=MAX_DNS || !add_resolver(value)) { fputs("无效 DNS 地址或超过4个\n",stderr); return 2; } }
        else if(!strcmp(opt,"--timeout")) { unsigned n=positive_int(value,10000); if(!n) return 2; timeout_ms=(int)n; }
        else { usage(); return 2; }
    }
    if(host) { unsigned char q[512]; if(!dns_request(q,host,0)) { fputs("无效目标地址\n",stderr); return 2; } }
    if(!resolver_count) load_resolvers();
    setvbuf(stdout,NULL,_IOLBF,0);
    puts("============================================================\nWiFi Calling 网络探测 " VERSION " / 64 MB 低内存设计\n串行探测 IPv4；无需 root、Python、Docker、入站端口映射。\n有效响应只说明网关返回路径可达；超时表示未确认。\n============================================================");
    puts("第 1 步：DNS/UDP 53 参考测试（不能代表 UDP 500/4500）");
    struct in_addr ips[MAX_IPS]; int dns_ok=0;
    for(int i=0;i<resolver_count;i++) if(dns_query(resolvers[i],"example.com",timeout_ms,ips)>0) { dns_ok=1; break; }
    puts(dns_ok?"  收到有效 DNS 回答。":"  未取得 DNS IPv4 回答；继续 IKE 检测，不能据此断定所有 UDP 被封锁。");
    puts("第 2 步：检测 ePDG 候选地址（每个域名最多取两个不同 IPv4）");
    unsigned char exponent[32],public_key[256]; random_bytes(exponent,sizeof exponent); exponent[0]|=0x80;
    dh_public(public_key,exponent); memset(exponent,0,sizeof exponent);
    int total=0,both=0,any=0,unresolved=0,local_errors=0;
    size_t count=host?1:sizeof carriers/sizeof *carriers;
    for(size_t i=0;i<count;i++) {
        const char *name=host?host:carriers[i].name;
        if(!host && filter && !strstr(name,filter)) continue;
        total++;
        char candidate[254];
        if(host) snprintf(candidate,sizeof candidate,"%s",host);
        else snprintf(candidate,sizeof candidate,"epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org",carriers[i].mnc,carriers[i].mcc);
        int n=resolve_host(candidate,timeout_ms,ips);
        if(!n) { printf("[%s] 未取得 IPv4 地址（DNS 失败、无 A 记录或候选域名未公开）\n",name); unresolved++; continue; }
        int carrier_both=0,carrier_any=0;
        for(int j=0;j<n;j++) {
            char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&ips[j],ip,sizeof ip);
            int p500=ike_probe(ip,500,0,timeout_ms,public_key);
            int p4500=ike_probe(ip,4500,1,timeout_ms,public_key);
            local_errors+=(p500<0)+(p4500<0);
            printf("[%s] %s  UDP 500: %s  UDP 4500: %s\n",name,ip,
                   p500>0?"有效响应":p500<0?"本地发送失败":"未确认",
                   p4500>0?"有效响应":p4500<0?"本地发送失败":"未确认");
            carrier_both|=p500>0 && p4500>0; carrier_any|=p500>0 || p4500>0;
        }
        both+=carrier_both; any+=carrier_any;
    }
    if(!total) { fputs("筛选未匹配运营商；使用 --list 查看名称。\n",stderr); return 2; }
    printf("\n检测结论：%d 个候选目标；同一 IP 双端口有效响应 %d；至少一个端口响应 %d；无 IPv4 地址 %d。\n",total,both,any,unresolved);
    if(any) puts("已观察到 IKEv2 返回路径；仍需用实际 SIM/手机验证注册和通话。");
    else puts("未确认 IKEv2 返回路径；不能区分丢包、防火墙、运营商策略、算法不接受或地址变更。");
    if(local_errors) printf("本地套接字/发送失败 %d 次，请检查出站权限和路由。\n",local_errors);
    puts("NAT 小机不需要映射入站 500/4500；实际通话还取决于 UDP 转发和 NAT 会话保持。\n检测完成（这是连通性诊断，不是 VoWiFi 开通或注册测试）。");
    return local_errors && !any?1:0;
}

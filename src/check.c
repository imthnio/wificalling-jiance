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

#define VERSION "2.2.0"
#define MAX_IPS 2
#define MAX_DNS 4
#define DNS_SIZE 4096
#define IKE_SIZE 376
#include "carriers.h"
#define CARRIER_COUNT (sizeof carriers/sizeof *carriers)

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
/* recv() silently discards a datagram suffix; never validate just its prefix. */
static ssize_t recv_datagram(int fd, unsigned char *buffer, size_t capacity) {
    struct iovec iov={buffer,capacity};
    struct msghdr msg;
    memset(&msg,0,sizeof msg); msg.msg_iov=&iov; msg.msg_iovlen=1;
    ssize_t n=recvmsg(fd,&msg,0);
    if(n>=0 && (msg.msg_flags&MSG_TRUNC)) return 0;
    return n;
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
    size_t off=28; unsigned next=b[16]; int count=0,seen_sa=0,seen_ke=0,seen_nonce=0,seen_error=0;
    if(!next) return 0;
    while(next) {
        if(++count>64 || off+4>n) return 0;
        size_t len=rd16(b+off+2);
        if(len<4 || len>n-off) return 0;
        if(next==41) { /* Notify: protocol, SPI size, type, optional SPI/data. */
            if(len<8 || b[off+4]!=0 || b[off+5]!=0 || rd16(b+off+6)==0) return 0;
            unsigned type=rd16(b+off+6);
            /* Status notifications alone do not constitute an SA_INIT reply.
             * COOKIE and INVALID_KE_PAYLOAD need their specified data. */
            if(type==16390) { if(len<9 || len>72) return 0; seen_error=1; }
            else if(type==17) { if(len!=10 || !rd16(b+off+8)) return 0; seen_error=1; }
            else if(type==1) { if(len!=9) return 0; seen_error=1; }
            else if(type<16384) seen_error=1;
        } else if(next==34) {
            if(seen_ke || len!=264 || rd16(b+off+4)!=14) return 0;
            seen_ke=1;
        } else if(next==40) {
            if(seen_nonce || len<20 || len>260) return 0;
            seen_nonce=1;
        } else if(next==33) {
            if(seen_sa || len<20) return 0;
            size_t pos=off+4,plen=rd16(b+pos+2);
            /* We offered exactly one proposal with four transforms. A successful
             * response must choose it, not merely contain a plausible SA shape. */
            if(plen!=len-4 || b[pos]!=0 || b[pos+4]!=1 || b[pos+5]!=1 ||
               b[pos+6]!=0 || b[pos+7]!=4) return 0;
            size_t tpos=pos+8; unsigned types=0;
            while(tpos<pos+plen) {
                if(tpos+8>pos+plen) return 0;
                size_t tlen=rd16(b+tpos+2); unsigned type=b[tpos+4],id=rd16(b+tpos+6);
                if(tlen<8 || tlen>pos+plen-tpos || b[tpos]!=(tpos+tlen<pos+plen?3:0) ||
                   type<1 || type>4 || (types&(1u<<type))) return 0;
                types|=1u<<type;
                if(type==1) {
                    if(id!=12) return 0;
                    if(tlen==12) { if(rd16(b+tpos+8)!=0x800e || rd16(b+tpos+10)!=128) return 0; }
                    else if(tlen==14) {
                        if(rd16(b+tpos+8)!=14 || rd16(b+tpos+10)!=2 || rd16(b+tpos+12)!=128) return 0;
                    } else return 0;
                } else if(tlen!=8 || id!=(type==2?5:type==3?12:14)) return 0;
                tpos+=tlen;
            }
            if(types!=30) return 0;
            seen_sa=1;
        } else if(b[off+1]&0x80) return 0;
        next=b[off]; off+=len;
    }
    unsigned char responder_spi=0;
    for(int i=8;i<16;i++) responder_spi|=b[i];
    return off==n && (seen_error || (responder_spi && seen_sa && seen_ke && seen_nonce));
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
        ssize_t n=recv_datagram(fd,reply,sizeof reply);
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
        for(size_t i=0;i<len;i++) {
            unsigned char c=(unsigned char)p[i];
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_')) return 0;
        }
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
    unsigned total_records=answers+rd16(b+8)+rd16(b+10);
    if(answers>64 || total_records>128) return -1;
    struct dns_record records[64]; unsigned nr=0;
    for(unsigned i=0;i<total_records;i++) {
        struct dns_record rec; memset(&rec,0,sizeof rec);
        if(!dns_name(b,n,&off,rec.owner) || off+10>n) return -1;
        unsigned type=rd16(b+off),cls=rd16(b+off+2),len=rd16(b+off+8);
        off+=10; if(len>n-off) return -1;
        if(cls==1 && type==1 && len!=4) return -1;
        if(i>=answers) { off+=len; continue; }
        if(cls==1 && type==1 && len==4) { rec.type=1; memcpy(&rec.addr,b+off,4); records[nr++]=rec; }
        else if(cls==1 && type==5) {
            size_t tmp=off;
            if(!dns_name(b,n,&tmp,rec.target) || tmp!=off+len) return -1;
            rec.type=5; records[nr++]=rec;
        }
        off+=len;
    }
    if(off!=n) return -1;
    if(rcode==3) return 0;
    char current[254]; snprintf(current,sizeof current,"%s",host);
    for(int depth=0;depth<16;depth++) {
        int count=0; const char *alias=NULL;
        for(unsigned i=0;i<nr;i++) if(!strcasecmp(records[i].owner,current)) {
            if(records[i].type==5) {
                if(alias && strcasecmp(alias,records[i].target)) return -1;
                alias=records[i].target;
            }
            if(records[i].type==1 && count<MAX_IPS) {
                int duplicate=0;
                for(int j=0;j<count;j++) if(ips[j].s_addr==records[i].addr.s_addr) duplicate=1;
                if(!duplicate) ips[count++]=records[i].addr;
            }
        }
        if(count && alias) return -1;
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
        ssize_t size=recv_datagram(fd,reply,sizeof reply);
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
static const char *color(FILE *out,const char *code) {
    return isatty(fileno(out)) && !getenv("NO_COLOR")?code:"";
}
static void carrier_result(const char *name,int both,int any,int unresolved,int errors) {
    const char *message,*shade;
    if(both) { message="✅ 网络检测通过，可以用手机试通话"; shade="\033[1;32m"; }
    else if(any) { message="⚠️ 只测通了部分连接，暂不能确认能用"; shade="\033[1;33m"; }
    else if(errors) { message="❌ 检测出错：本机无法发送，请检查网络设置"; shade="\033[1;31m"; }
    else if(unresolved) { message="⚠️ 暂未测通：找不到运营商服务器地址"; shade="\033[1;33m"; }
    else { message="⚠️ 暂未测通：运营商没有有效回应，可稍后重试"; shade="\033[1;33m"; }
    printf("%s[%s]%s %s%s%s\n",color(stdout,"\033[1;36m"),name,color(stdout,"\033[0m"),
           color(stdout,shade),message,color(stdout,"\033[0m"));
}
/* Country names come from the existing carrier labels; no duplicate catalog. */
static int country_names(char names[CARRIER_COUNT][64]) {
    int count=0;
    for(size_t i=0;i<sizeof carriers/sizeof *carriers;i++) {
        size_t n=strcspn(carriers[i].name," ");
        if(n>=64) continue;
        int found=0;
        for(int j=0;j<count;j++) if(strlen(names[j])==n && !memcmp(names[j],carriers[i].name,n)) found=1;
        if(!found) { memcpy(names[count],carriers[i].name,n); names[count++][n]=0; }
    }
    return count;
}
static int country_matches(const char *name,const char *country) {
    size_t n=strlen(country);
    return !strncmp(name,country,n) && name[n]==' ';
}
/* 1: selected country; 0: explicitly all; -1: cancel/EOF. */
static int choose_country(FILE *input,FILE *output,char selected[64]) {
    char names[CARRIER_COUNT][64]; int count=country_names(names);
    fputs("请选择要检测的手机卡所属国家（不是 VPS 所在国家）：\n",output);
    for(int i=0;i<count;i++) {
        int carriers_count=0;
        for(size_t j=0;j<sizeof carriers/sizeof *carriers;j++) carriers_count+=country_matches(carriers[j].name,names[i]);
        fprintf(output,"%s  %2d. %s（%d 家）%s\n",color(output,"\033[1;36m"),i+1,names[i],carriers_count,color(output,"\033[0m"));
    }
    fputs("   0. 全部国家（较慢）\n   q. 退出\n",output);
    for(;;) {
        char line[128];
        fputs("输入编号或国家名称：",output); fflush(output);
        if(!fgets(line,sizeof line,input)) return -1;
        if(!strchr(line,'\n') && !feof(input)) {
            int c; while((c=fgetc(input))!=EOF && c!='\n') {}
            if(c==EOF) return -1;
            fputs("输入过长，请重新选择。\n",output); continue;
        }
        char *value=line; while(isspace((unsigned char)*value)) value++;
        size_t n=strlen(value); while(n && isspace((unsigned char)value[n-1])) value[--n]=0;
        if(!strcmp(value,"q") || !strcmp(value,"Q")) return -1;
        if(!strcmp(value,"0")) return 0;
        unsigned index=positive_int(value,(unsigned)count);
        for(int i=0;i<count;i++) if((unsigned)(i+1)==index || !strcmp(value,names[i])) {
            snprintf(selected,64,"%.63s",names[i]); return 1;
        }
        fputs("无效选择，请输入列表中的编号或国家名称。\n",output);
    }
}
static void usage(void) {
    puts("WiFi Calling 网络探测 " VERSION "（低内存 / IPv4）\n"
         "用法: check [--country 国家 | --all | --filter 名称] [--host 域名或IPv4] [--dns DNS地址] [--timeout 毫秒]\n"
         "      check --list | --version | --help\n"
         "--details 显示地址和端口明细；NO_COLOR=1 关闭颜色。\n"
         "默认先选择手机卡所属国家；--country 英国 跳过菜单，--all 检测全部。\n"
         "--filter 示例: 德国、英国、T-Mobile；--host 覆盖默认运营商候选名单。\n"
         "--dns 仅使用指定解析器（可重复最多4个）；--timeout 范围 1..10000。\n"
         "只验证未认证 IKEv2 响应，不能证明 SIM 注册、通话、IPv6 或代理 UDP 转发可用。");
}
int main(int argc,char **argv) {
    const char *filter=NULL,*host=NULL,*country=NULL; char selected[64],normalized_host[254]; int timeout_ms=1500,all=0,details=0;
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--help")) { usage(); return 0; }
        if(!strcmp(argv[i],"--version")) { puts(VERSION); return 0; }
        if(!strcmp(argv[i],"--list")) {
            for(size_t c=0;c<sizeof carriers/sizeof *carriers;c++) printf("%s  epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org\n",carriers[c].name,carriers[c].mnc,carriers[c].mcc);
            return 0;
        }
        if(!strcmp(argv[i],"--details")) { details=1; continue; }
        if(!strcmp(argv[i],"--all")) { all=1; continue; }
        if(i+1>=argc) { usage(); return 2; }
        const char *opt=argv[i++],*value=argv[i];
        if(!strcmp(opt,"--filter")) filter=value;
        else if(!strcmp(opt,"--country")) country=value;
        else if(!strcmp(opt,"--host")) host=value;
        else if(!strcmp(opt,"--dns")) { if(resolver_count>=MAX_DNS || !add_resolver(value)) { fputs("无效 DNS 地址或超过4个\n",stderr); return 2; } }
        else if(!strcmp(opt,"--timeout")) { unsigned n=positive_int(value,10000); if(!n) return 2; timeout_ms=(int)n; }
        else { usage(); return 2; }
    }
    if((filter!=NULL)+(host!=NULL)+(country!=NULL)+all>1 || (filter && !*filter)) {
        fputs("--country、--filter、--host、--all 请只选一种，筛选内容不能为空。\n",stderr); return 2;
    }
    if(country) {
        char names[CARRIER_COUNT][64]; int n=country_names(names),found=0;
        for(int i=0;i<n;i++) if(!strcmp(country,names[i])) found=1;
        if(!found) { fputs("未知国家；不带筛选参数运行可查看国家菜单。\n",stderr); return 2; }
    }
    if(!country && !filter && !host && !all) {
        /* Piped installers consume stdin themselves; read the controlling tty. */
        FILE *terminal=fopen("/dev/tty","r");
        FILE *input=terminal?terminal:(isatty(STDIN_FILENO)?stdin:NULL);
        if(!input) {
            fputs("没有交互终端；请指定 --country 英国、--filter 名称、--host 地址或 --all。\n",stderr); return 2;
        }
        FILE *menu_output=terminal?fopen("/dev/tty","w"):NULL;
        int choice=choose_country(input,menu_output?menu_output:stderr,selected);
        if(menu_output) fclose(menu_output);
        if(terminal) fclose(terminal);
        if(choice<0) { puts("已取消检测。"); return 0; }
        if(choice) country=selected;
    }
    if(host) {
        size_t n=strlen(host); if(n && host[n-1]=='.') n--;
        if(!n || n>=sizeof normalized_host) { fputs("无效目标地址\n",stderr); return 2; }
        memcpy(normalized_host,host,n); normalized_host[n]=0; host=normalized_host;
        unsigned char q[512];
        if(!dns_request(q,host,0)) { fputs("无效目标地址（仅支持 ASCII 域名或 IPv4）\n",stderr); return 2; }
    }
    if(filter) {
        int matched=0;
        for(size_t i=0;i<CARRIER_COUNT;i++) if(strstr(carriers[i].name,filter)) matched=1;
        if(!matched) { fputs("筛选未匹配运营商；使用 --list 查看名称。\n",stderr); return 2; }
    }
    if(!resolver_count) load_resolvers();
    setvbuf(stdout,NULL,_IOLBF,0);
    printf("%sWiFi 通话网络检测 " VERSION "%s\n",color(stdout,"\033[1;36m"),color(stdout,"\033[0m"));
    puts("正在检测，请稍等。每家运营商测完后会显示结果。");
    if(details) puts("第 1 步：DNS/UDP 53 参考测试（不能代表 UDP 500/4500）");
    struct in_addr ips[MAX_IPS]; int dns_ok=0;
    for(int i=0;i<resolver_count;i++) if(dns_query(resolvers[i],"example.com",timeout_ms,ips)>0) { dns_ok=1; break; }
    if(details) puts(dns_ok?"  收到有效 DNS 回答。":"  未取得 DNS IPv4 回答；继续 IKE 检测，不能据此断定所有 UDP 被封锁。");
    if(details) puts("第 2 步：检测 ePDG 候选地址（每个域名最多取两个不同 IPv4）");
    unsigned char exponent[32],public_key[256]; random_bytes(exponent,sizeof exponent); exponent[0]|=0x80;
    dh_public(public_key,exponent); memset(exponent,0,sizeof exponent);
    int total=0,both=0,any=0,unresolved=0,local_errors=0;
    size_t count=host?1:sizeof carriers/sizeof *carriers;
    for(size_t i=0;i<count;i++) {
        const char *name=host?host:carriers[i].name;
        if(!host && filter && !strstr(name,filter)) continue;
        if(!host && country && !country_matches(name,country)) continue;
        total++;
        char candidate[254];
        if(host) snprintf(candidate,sizeof candidate,"%s",host);
        else snprintf(candidate,sizeof candidate,"epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org",carriers[i].mnc,carriers[i].mcc);
        int n=resolve_host(candidate,timeout_ms,ips);
        if(!n) { carrier_result(name,0,0,1,0); unresolved++; continue; }
        int carrier_both=0,carrier_any=0,carrier_errors=0;
        for(int j=0;j<n;j++) {
            char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&ips[j],ip,sizeof ip);
            int p500=ike_probe(ip,500,0,timeout_ms,public_key);
            int p4500=ike_probe(ip,4500,1,timeout_ms,public_key);
            local_errors+=(p500<0)+(p4500<0);
            carrier_errors+=(p500<0)+(p4500<0);
            if(details) printf("[%s] %s  UDP 500: %s  UDP 4500: %s\n",name,ip,
                   p500>0?"有效响应":p500<0?"本地发送失败":"未确认",
                   p4500>0?"有效响应":p4500<0?"本地发送失败":"未确认");
            carrier_both|=p500>0 && p4500>0; carrier_any|=p500>0 || p4500>0;
        }
        carrier_result(name,carrier_both,carrier_any,0,carrier_errors);
        both+=carrier_both; any+=carrier_any;
    }
    if(!total) { fputs("筛选未匹配运营商；使用 --list 查看名称。\n",stderr); return 2; }
    printf("\n%s检测结果%s：共检查 %d 家；网络检测通过 %d 家；部分测通 %d 家；其余未测通或检测出错 %d 家。\n",
           color(stdout,"\033[1;36m"),color(stdout,"\033[0m"),total,both,any-both,total-any);
    const char *summary=both?"✅ 有运营商网络检测通过，可以用对应手机卡试通话。":
                            any?"⚠️ 只测通了部分连接，目前还不能确认能用。":
                                "⚠️ 这次没有测通，暂不能确认能用；不要仅凭这个结果换 VPS。";
    printf("%s%s%s\n",color(stdout,both?"\033[1;32m":"\033[1;33m"),summary,color(stdout,"\033[0m"));
    puts("手机需支持并开通 WiFi 通话，连接也要经过这台 VPS；能否打电话，以手机实际注册和试拨为准。");
    if(details) {
        printf("技术汇总：%d 个候选目标；同一 IP 双端口响应 %d；至少单端口响应 %d；无 IPv4 地址 %d；本地发送失败 %d 次。\n",total,both,any,unresolved,local_errors);
        puts("这是未认证 IKE 返回路径检测，不验证手机到 VPS 的连接、SIM 注册或真实通话。");
    } else puts("需要排查原因，可加 --details 查看地址和端口明细。");
    return local_errors && !any?1:0;
}

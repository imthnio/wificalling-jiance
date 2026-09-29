#define main check_main
#include "../src/check.c"
#undef main
int main(int argc,char **argv) {
    unsigned char key[256],exponent[32]={0};
    if(argc<2) return 2;
    if(!strcmp(argv[1],"result") && argc==6) {
        carrier_result("美国 Test",atoi(argv[2]),atoi(argv[3]),atoi(argv[4]),atoi(argv[5])); return 0;
    }
    if(!strcmp(argv[1],"menu")) {
        char selected[64]={0}; int result=choose_country(stdin,stderr,selected);
        printf("%d:%s\n",result,selected); return 0;
    }
    if(!strcmp(argv[1],"dh")) {
        if(argc!=3 || strlen(argv[2])!=64) return 2;
        for(int i=0;i<32;i++) { char s[3]={argv[2][i*2],argv[2][i*2+1],0}; exponent[i]=(unsigned char)strtoul(s,NULL,16); }
        dh_public(key,exponent); for(int i=0;i<256;i++) printf("%02x",key[i]); puts(""); return 0;
    }
    if(!strcmp(argv[1],"packet") || !strcmp(argv[1],"probe")) { exponent[0]=0x80; dh_public(key,exponent); }
    if(!strcmp(argv[1],"packet")) { unsigned char p[IKE_SIZE]; build_ike(p,key); return fwrite(p,1,sizeof p,stdout)==sizeof p?0:1; }
    if(!strcmp(argv[1],"probe") && argc==5) {
        int r=ike_probe("127.0.0.1",positive_int(argv[2],65535),atoi(argv[3]),atoi(argv[4]),key);
        printf("%d\n",r); return 0;
    }
    if(!strcmp(argv[1],"ike") && argc==3) {
        unsigned char b[4096],spi[8]={1,2,3,4,5,6,7,8}; size_t n=fread(b,1,sizeof b,stdin);
        printf("%d\n",valid_ike(b,n,spi,atoi(argv[2]))); return 0;
    }
    if(!strcmp(argv[1],"dns")) {
        unsigned char b[DNS_SIZE]; struct in_addr ips[MAX_IPS]; size_t n=fread(b,1,sizeof b,stdin);
        int count=parse_dns(b,n,0x1234,"epdg.example",ips); printf("%d\n",count);
        for(int i=0;i<count;i++) { char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&ips[i],ip,sizeof ip); puts(ip); }
        return 0;
    }
    return 2;
}

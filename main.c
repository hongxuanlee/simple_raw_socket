#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h> 
#include "print.c"

#define PROXY_IP "100.69.167.224"

#define PROXY_INPORT 55555 // in

#define PROXY_OUTPORT 55556 // out

u_int32_t source_ip;

u_int16_t source_port;

char dest_ip[32];

int dest_port = 80;

struct pseudoHeader
{
    u_int32_t  ip_src;
    u_int32_t  ip_dst;
    u_int8_t zero;   //always zero
    u_int8_t protocol;  //for tcp
    u_int16_t tcp_len;
};

void str_replace(char *target, const char *needle, const char *replacement)
{
    char buffer[8064] = { 0 };
    char *insert_point = &buffer[0];
    const char *tmp = target;
    size_t needle_len = strlen(needle);
    size_t repl_len = strlen(replacement);

    while (1) {
        const char *p = strstr(tmp, needle);

        if (p == NULL) {
            strcpy(insert_point, tmp);
            break;
        }

        memcpy(insert_point, tmp, p - tmp);
        insert_point += p - tmp;

        memcpy(insert_point, replacement, repl_len);
        insert_point += repl_len;

        tmp = p + needle_len;
    }

    strcpy(target, buffer);
}

char *handlePayload(char* buffer){
    char host_str[80];
    memset(host_str, 0, 80);
    sprintf(host_str, "Host: %s:%d", dest_ip, dest_port);
    str_replace(buffer, "Host: 100.69.167.224:55555", host_str);
}

unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);

    return(short)~sum;
}

unsigned short ipCheckSum(struct iphdr* iph, struct tcphdr* tcph, char* data, int size)
{
    iph -> check = 0;
    unsigned int ip_len = iph -> ihl * 4;
    unsigned int tcp_len = tcph -> doff * 4;
    char pseudoData[4096];
    memset(pseudoData, 0, 4096);
    memcpy(pseudoData, data, 20);
    return csum((unsigned short *)pseudoData, 20);
}

unsigned short tcpCheckSum(struct iphdr* iph, struct tcphdr* tcph, char* data, int size)
{
    tcph -> check = 0;
    struct pseudoHeader psd_header;
    psd_header.ip_src = iph -> saddr;
    psd_header.ip_dst = iph -> daddr;
    psd_header.zero = 0;
    psd_header.protocol= IPPROTO_TCP;
    unsigned int tcp_len = tcph -> doff * 4;
    psd_header.tcp_len = htons(tcp_len + size);

    int psize = sizeof(struct pseudoHeader) + tcp_len + size;

    char* tcpBuf = malloc(psize);
    memcpy(tcpBuf, &psd_header, sizeof(struct pseudoHeader));
    memcpy(tcpBuf + sizeof(struct pseudoHeader), tcph, tcp_len + size);
    return csum((unsigned short *)tcpBuf, psize);
}

void ProcessPacket(unsigned char* buffer, int size, int s){
    struct iphdr *iph = (struct iphdr *)buffer;
    unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
    unsigned short tcphdrlen = tcph->doff*4;
    unsigned char *payload = buffer + iphdrlen + tcphdrlen;
    struct sockaddr_in src, dst;
    src.sin_addr.s_addr = iph->saddr;
    dst.sin_addr.s_addr = iph->daddr; 
    u_int32_t source = iph -> saddr;      
    u_int32_t dest = iph -> daddr;
    if(ntohs(tcph -> dest) == PROXY_INPORT)
    {
        source_port = tcph -> source;
        source_ip = iph -> saddr;
        iph -> saddr = inet_addr(PROXY_IP); 
        iph -> daddr = inet_addr(dest_ip); 
        tcph -> source = htons(PROXY_OUTPORT);
        tcph -> dest = htons(dest_port); 
        unsigned short data_len = ntohs(iph -> tot_len) - iphdrlen - tcphdrlen; 
        if(data_len > 0){
          handlePayload(payload);
          iph -> tot_len = htons(iphdrlen + tcphdrlen + strlen(payload));
        }
   }
    else if(ntohs(tcph -> dest) == PROXY_OUTPORT)
    {
        iph -> daddr = source_ip; 
        iph -> saddr = inet_addr(PROXY_IP); 
        tcph -> dest = source_port;
        tcph -> source = htons(PROXY_INPORT);
    }else
    {
        return;
    }
    printf("Source IP        : %s\n",inet_ntoa(src.sin_addr));
    printf("Destination IP   : %s\n",inet_ntoa(dst.sin_addr));

    iph -> check = ipCheckSum(iph, tcph, buffer, size);              
    tcph -> check = tcpCheckSum(iph, tcph, payload, strlen(payload));
    print_tcp_packet(buffer, iph, tcph, size);  

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = tcph -> dest;
    dest_addr.sin_addr.s_addr = iph -> daddr;

    if (sendto (s, buffer, ntohs(iph -> tot_len),  0, (struct sockaddr *) &dest_addr, sizeof (dest_addr)) < 0)
    {
        perror("sendto failed");
    }
    else
    {
        printf ("Packet Send. Length : %d \n" , ntohs(iph -> tot_len));
    }
}

int main(int argc, const char * argv[]) {
    if(argc < 2){
        printf("arguments missing");
        exit(-2); 
    }
    memset(dest_ip, 0, 32);
    strcpy(dest_ip, argv[1]);
    if(argc > 2){
      dest_port = strtol(argv[2], NULL, 10);
    }
    printf("main start \n");
    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s == -1)
    {
        perror("Failed to create socket");
    }
    int one = 1;
    const int *val = &one;
    struct sockaddr_in serverProxy;
    serverProxy.sin_family = AF_INET;
    serverProxy.sin_addr.s_addr = inet_addr(PROXY_IP);
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
    }

    while(1) {
        u_char raw_Buffer[8064];
        memset (raw_Buffer, 0, 8064);
        int saddr_size = sizeof serverProxy;
        int data_size = recvfrom(s , raw_Buffer , 8064, 0 , (struct sockaddr *)&serverProxy , &saddr_size);

        if(data_size < 0)
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        ProcessPacket(raw_Buffer , data_size, s);
    }
}



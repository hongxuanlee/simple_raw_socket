#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "print.c"

#define SOURCE_IP "11.164.8.106"

#define PROXY_IP "100.69.167.224"

#define DEST_IP "30.8.70.185"

#define DEST_PORT 3000

struct pseudoHeader
{
    u_int32_t  ip_src;
    u_int32_t  ip_dst;
    u_int8_t zero;   //always zero
    u_int8_t protocol;  //for tcp
    u_int16_t tcp_len;
};

int ip_match(u_int32_t addr1, u_int32_t addr2)
{
    int res = !(addr1 ^ addr2);
    return res;
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
    int iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
    struct sockaddr_in src, dst;
    src.sin_addr.s_addr = iph->saddr;
    dst.sin_addr.s_addr = iph->daddr; 
    u_int32_t source = iph -> saddr;      
    u_int32_t dest = iph -> daddr;
    if(ip_match(source, inet_addr(SOURCE_IP)))
    {
        iph -> saddr = inet_addr(PROXY_IP); 
        iph -> daddr = inet_addr(DEST_IP); 
        tcph -> dest = htons(3000); 
    }else if(ip_match(source, inet_addr(DEST_IP)) && 22 != ntohs(tcph->dest))
    {
        printf("___recieve back!!!\n");
        iph -> daddr = inet_addr(SOURCE_IP); 
        iph -> saddr = inet_addr(PROXY_IP); 
        tcph -> source = htons(8877);
    }else
    {
        return;
    }
    printf("Source IP        : %s\n",inet_ntoa(src.sin_addr));
    printf("Destination IP   : %s\n",inet_ntoa(dst.sin_addr));

    iph -> check = ipCheckSum(iph, tcph, buffer, size);              
    unsigned short tcphdrlen = tcph->doff*4;
    tcph -> check = tcpCheckSum(iph, tcph, buffer + iphdrlen + tcphdrlen, (size - iphdrlen - tcphdrlen));
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
    serverProxy.sin_port = htons(DEST_PORT);
    serverProxy.sin_addr.s_addr = inet_addr(PROXY_IP);
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
    }
    // bind port
      bind(s, (struct sockaddr *)&serverProxy, sizeof(serverProxy));

    while(1) {
        u_char buffer[1024];

        u_char raw_Buffer[1024];
        int saddr_size = sizeof serverProxy;
        int data_size = recvfrom(s , raw_Buffer , 1024, 0 , (struct sockaddr *)&serverProxy , &saddr_size);

        if(data_size < 0)
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        ProcessPacket(raw_Buffer , data_size, s);
    }
}



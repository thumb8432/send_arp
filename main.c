#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

struct arp_addr
{
    struct ether_addr   sha;
    struct in_addr      sip;
    struct ether_addr   tha;
    struct in_addr      tip;
};

int getMyHwAddr(struct ether_addr *myha, char *interface)
{
    int             fd;
    struct ifreq    ifr;
    int             idx;

    if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))==-1)
    {
        fprintf(stderr, "Couldn't open socket\n");
        return 0;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, interface);
    if(ioctl(fd, SIOCGIFHWADDR, &ifr)!=0)
    {
        fprintf(stderr, "ioctl failed\n");
        return 0;
    }

    for(idx=0; idx<ETH_ALEN; idx++)
    {
        myha->ether_addr_octet[idx] = ifr.ifr_addr.sa_data[idx];
    }

    close(fd);

    return 1;
}

int getMyIpAddr(struct in_addr *myip, char *interface)
{
    int             fd;
    struct ifreq    ifr;
    int             idx;

    if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))==-1)
    {
        fprintf(stderr, "Couldn't open socket\n");
        return 0;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, interface);
    if(ioctl(fd, SIOCGIFADDR, &ifr)!=0)
    {
        fprintf(stderr, "ioctl failed\n");
        return 0;
    }

    myip->s_addr = *(unsigned long *)(ifr.ifr_addr.sa_data + 2);

    close(fd);

    return 1;
}

void makeARPPacket(char *packet, struct ether_addr sha, struct ether_addr tha, struct in_addr sip, struct in_addr tip, uint16_t oper)
{   
    struct ether_header     *eth_hdr;
    struct arphdr           *arp_hdr;
    struct arp_addr         *arp_addr;
    int                     idx;

    eth_hdr = (struct ether_header *) packet;
    for(idx=0; idx<ETH_ALEN; idx++)
    {
        eth_hdr->ether_shost[idx] = sha.ether_addr_octet[idx];
        eth_hdr->ether_dhost[idx] = tha.ether_addr_octet[idx];
    }
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    arp_hdr = (struct arphdr *) (packet + sizeof(struct ether_header));
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ar_hln = ETH_ALEN;
    arp_hdr->ar_pln = sizeof(struct in_addr);
    arp_hdr->ar_op  = htons(oper);

    arp_addr = (struct arp_addr *) (packet + sizeof(struct ether_header) + sizeof(struct arp_addr));
    arp_addr->sha = sha;
    arp_addr->sip = sip;
    arp_addr->tha = tha;
    arp_addr->tip = tip;
}

int main(int argc, char **argv)
{
    pcap_t              *handle;
    char                *interface;
    char                errbuf[PCAP_ERRBUF_SIZE];
    struct ether_addr   attacker_ha;
    struct ether_addr   victim_ha;
    struct in_addr      attacker_ip;
    struct in_addr      victim_ip;
    struct in_addr      target_ip;
    char                packet[sizeof(struct ether_header) + sizeof(arp_addr) + sizeof(arp_addr)];

    if(argc != 4)
    {
        printf("Usage : %s <interface> <sender ip> <target ip>", argv[0]);
        return -1;
    }

    interface = argv[1];
    inet_aton(argv[2], &victim_ip);
    inet_aton(argv[3], &target_ip);

    if(getMyHwAddr(&myha, interface)==0)
    {
        fprintf(stderr, "getMyHwAddr failed\n");
        return -1;
    }

    if(getMyIpAddr(&myip, interface)==0)
    {
        fprintf(stderr, "getMyIpAddr failed\n");
        return -1;
    }

    if((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return -1;
    }

    pcap_close(handle);

    return 0;
}
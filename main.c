#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>

struct arp_addr
{
    struct ether_addr   sha;
    struct in_addr      sip;
    struct ether_addr   tha;
    struct in_addr      tip;
};

void makeARPPacket(uint8_t *packet, struct ether_addr sha, struct ether_addr tha, struct in_addr sip, struct in_addr tip, uint16_t oper)
{   
    struct ether_header     *eth_hdr;
    struct arphdr           *arp_hdr;
    struct arp_addr         *arp_addr;
    uint8_t                 idx;

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
    arp_hdr->ar_op  = oper;

    arp_addr = (struct arp_addr *) (packet + sizeof(struct ether_header) + sizeof(struct arp_addr));
    arp_addr->sha = sha;
    arp_addr->sip = sip;
    arp_addr->tha = tha;
    arp_addr->tip = tip;
}

int main()
{
    return 0;
}
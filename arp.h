#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <linux/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};

#define ETH_HDRLEN 14
#define IP4_HDRLEN 20
#define ARP_HDRLEN 28
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

void print_ipv4 (uint32_t ipv4)
{
    for (int i = 0; i < 3; i ++)
        printf("%d.", (ipv4 >> (i * 8)) & 0xff);
    printf("%d\n", (ipv4 >> 24) & 0xff);
}

uint32_t get_ipv4 (int sd, struct ifreq* ifr)
{
    struct sockaddr_in* ipv4;
    uint32_t ret;
    ioctl (sd, SIOCGIFADDR, ifr); // get src ip
    ipv4 = (struct sockaddr_in *)&ifr->ifr_addr;
    memcpy (&ret, &ipv4->sin_addr, 4);
    return ret;
}

void print_mac (uint8_t* mac)
{
    for (int i = 0; i < 5; i ++)
        printf("%02x:", mac[i]);
    printf("%02x\n", mac[5]);
}

void get_hwaddr (int sd, struct ifreq* ifr, uint8_t* mac)
{
    ioctl (sd, SIOCGIFHWADDR, ifr); // get src mac
    memcpy (mac, ifr->ifr_hwaddr.sa_data, 6);
}

uint32_t get_ipv4_net_mask (int sd, struct ifreq* ifr)
{
    uint8_t net_mask[4];
    ioctl (sd, SIOCGIFNETMASK, ifr); // get net mask
    for (int i = 0; i < 4; i ++)
        memcpy (net_mask + i, ifr->ifr_netmask.sa_data + 4 - i, 1);
    return *(uint32_t*)net_mask;
}

int get_ipv4_mask_num (int sd, struct ifreq* ifr)
{
    int num = 0;
    uint8_t net_mask[4];
    ioctl (sd, SIOCGIFNETMASK, ifr);
    memcpy (net_mask, ifr->ifr_netmask.sa_data + 1, 4);
    for(int i = 0; i < 4; i ++){
        net_mask[i] = ~net_mask[i];
        while (net_mask[i] != 0){
            net_mask[i] >>= 1;
            num ++;
        }
    }
    return num;
}

void set_gratuitous_arphdr (arp_hdr* arphdr, uint8_t* mac_src, uint32_t* ip_src)
{
    arphdr->htype = htons (1);
    arphdr->ptype = htons (ETH_P_IP);
    arphdr->hlen = 6;
    arphdr->plen = 4;
    arphdr->opcode = htons (ARPOP_REQUEST);
    memcpy (&arphdr->sender_mac, mac_src, 6);
    memcpy (&arphdr->sender_ip, ip_src, 4);
    memset (&arphdr->target_mac, 0, 6);
    memcpy (&arphdr->target_ip, ip_src, 4);
}

void set_request_arphdr (arp_hdr* arphdr, uint8_t* mac_src, uint32_t* ip_src, uint32_t* ip_dst)
{
    arphdr->htype = htons (1);
    arphdr->ptype = htons (ETH_P_IP);
    arphdr->hlen = 6;
    arphdr->plen = 4;
    arphdr->opcode = htons (ARPOP_REQUEST);
    memcpy (&arphdr->sender_mac, mac_src, 6);
    memcpy (&arphdr->sender_ip, ip_src, 4);
    memset (&arphdr->target_mac, 0, 6);
    memcpy (&arphdr->target_ip, ip_dst, 4);
}

void set_broadcast_eth (uint8_t* ether_frame, arp_hdr* arphdr, uint8_t* mac_src)
{
    memset (ether_frame, 0xff, 6);
    memcpy (ether_frame + 6, mac_src, 6);
    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;
    memcpy (ether_frame + ETH_HDRLEN, arphdr, ARP_HDRLEN);
}

void send_ether_frame (uint8_t* ether_frame, int frame_length, struct sockaddr_ll device)
{
    int sd, bytes;
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed");
        exit (EXIT_FAILURE);
    }
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        perror ("sendto() failed");
        exit (EXIT_FAILURE);
    }
    close (sd);
}

int get_host_num(uint32_t net_mask)
{
    int num = 1;
    uint32_t temp = ~net_mask;
    while (temp != 0){
        temp <<= 1;
        num <<= 1;
    }
    return num;
}

void next_ip(uint8_t* ip)
{
    ip[3] += 1;
    if(ip[3] == 0){
        ip[2] += 1;
        if(ip[2] == 0){
            ip[1] += 1;
            if(ip[1] == 0)
                ip[0] += 1;
        }
    }
}

uint32_t get_start_ip (uint32_t ip_src, uint32_t net_mask)
{
    return ip_src & net_mask;
}

uint32_t array2ip (uint8_t* ip){
    uint32_t ret = 0;
    for (int i = 0; i < 4; i ++)
        ret |= ((uint32_t)ip[i]) << (8 * i);
    return ret;
}

void get_rand_mac (uint8_t* mac){
    srand (time (NULL));
    int seg1 = rand(), seg2 = rand();
    memcpy (mac, &seg1, 4);
    memcpy (mac + 4, &seg2, 2);
}
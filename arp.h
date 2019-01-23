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

void print_ipv4 (uint8_t* ipv4)
{
    for (int i = 0; i < 3; i ++)
        printf("%d.", ipv4[i]);
    printf("%d\n", ipv4[3]);
}

void get_ipv4 (int sd, struct ifreq* ifr, uint8_t* add)
{
    struct sockaddr_in* ipv4;
    ioctl (sd, SIOCGIFADDR, ifr); // get src ip
    ipv4 = (struct sockaddr_in *)&ifr->ifr_addr;
    memcpy (add, &ipv4->sin_addr, 4);
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

void get_net_mask (int sd, struct ifreq* ifr, uint8_t* net_mask)
{
    ioctl (sd, SIOCGIFNETMASK, ifr); // get net mask
    for (int i = 0; i < 4; i ++)
        net_mask[i] = ifr->ifr_netmask.sa_data[3-i];
}

void set_gratuitous_arphdr (arp_hdr* arphdr, uint8_t* mac_src, uint8_t* ip_src)
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

void set_request_arphdr (arp_hdr* arphdr, uint8_t* mac_src, uint8_t* ip_src, uint8_t* ip_dst)
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
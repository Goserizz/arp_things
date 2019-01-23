#include "arp.h"

int main(int argc, char **argv)
{
    int sd;
    uint8_t mac_src[6], ip_src[4], mac_dst[6], ether_frame[IP_MAXPACKET], net_mask[4];
    struct sockaddr_in *ipv4;
    struct sockaddr_ll device;
    struct ifreq ifr;
    char *interface = "wlp3s0";
    arp_hdr arphdr;

    if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl()");
        exit (EXIT_FAILURE);
    }

    snprintf (ifr.ifr_name, sizeof(ifr.ifr_name), interface);
    get_ipv4 (sd, &ifr, ip_src);
    print_ipv4(ip_src);

    get_hwaddr (sd, &ifr, mac_src);
    print_mac (mac_src);

    get_net_mask (sd, &ifr, net_mask);
    print_ipv4 (net_mask);

    close(sd);

    if((device.sll_ifindex = if_nametoindex (interface)) == 0){
        printf("Somthing went wrong while getting index of the interface.\n");
        exit(1);
    }
    printf("Index: %i\n", device.sll_ifindex);

    device.sll_family = AF_PACKET;
    memset(device.sll_addr, 0xff, 6);
    device.sll_halen = htons (6);
    
    // arp header
    // set_gratuitous_arphdr (&arphdr, mac_src, ip_src);
    uint8_t ip_dst[4] = {192, 168, 0 ,110};
    // print_ipv4 (ip_dst);
    set_request_arphdr (&arphdr, mac_src, ip_src, ip_dst);

    // ether frame
    int frame_length = 6 + 6 + 2 + ARP_HDRLEN;
    set_broadcast_eth (ether_frame, &arphdr, mac_src);

    //send ether frame
    send_ether_frame (ether_frame, frame_length, device);
    
    printf("success.\n");
    for (int i = 0; i < frame_length; i ++)
        printf("%x ", ether_frame[i]);
    return 0;
}
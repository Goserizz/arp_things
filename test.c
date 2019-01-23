#include "arp.h"

int main(int argc, char **argv)
{
    int sd;
    uint8_t mac_src[6], ip_src[4], mac_dst[6], ip_dst[4], ether_frame[IP_MAXPACKET], net_mask[4];
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

    memset (mac_dst, 0xff, 6 * sizeof (uint8_t));
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, mac_dst, 6);
    device.sll_halen = htons (6);
    
    // arp header
    set_gratuitous_arphdr (&arphdr, mac_src, ip_src);

    // ether frame
    int frame_length = 6 + 6 + 2 + ARP_HDRLEN;
    memcpy (ether_frame, mac_dst, 6);
    memcpy (ether_frame + 6, mac_src, 6);
    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;
    memcpy (ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN);

    //send ether frame
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed");
        exit (EXIT_FAILURE);
    }
    int bytes;
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        perror ("sendto() failed");
        exit (EXIT_FAILURE);
    }
    close (sd);
    printf("success.\n");
    return 0;
}
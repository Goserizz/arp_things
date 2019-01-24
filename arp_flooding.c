#include "arp.h"

int main(){
    int sd;
    char* interface = "wlp3s0";
    struct sockaddr_ll device;
    uint8_t mac_src[6], ether_frame[IP_MAXPACKET];
    uint8_t ip_src_array[4] = {192, 168, 0, 255}, ip_dst_array[4] = {192, 168, 0, 1};
    uint32_t ip_src = array2ip(ip_src_array), ip_dst = array2ip(ip_dst_array);
    arp_hdr arphdr;
    print_ipv4 (ip_src);
    get_rand_mac (mac_src);
    print_mac (mac_src);

    device.sll_ifindex = if_nametoindex (interface);
    device.sll_family = AF_PACKET;
    memset(device.sll_addr, 0xff, 6);
    device.sll_halen = htons (6);

    if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl()");
        exit (EXIT_FAILURE);
    }

    set_request_arphdr (&arphdr, mac_src, &ip_src, &ip_dst);
    set_broadcast_eth (ether_frame, &arphdr, mac_src);
    // while(1) never tried this
        send_ether_frame (ether_frame, 42, device);

    close (sd);
}
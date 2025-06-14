#pragma once

#include <pcap.h>
#include <string>

/**
 * @brief Класс Sniffer реализует захват и анализ сетевых пакетов.
 */
class Sniffer {
public:
    /**
     * @brief Конструктор по умолчанию. Инициализирует sniffer.
     */
    Sniffer();

    /**
     * @brief Открывает заданный сетевой интерфейс для захвата пакетов.
     * @param interface Имя интерфейса (например, "eth0")
     * @return true, если интерфейс успешно открыт
     */
    bool open_interface(const std::string& interface);

    /**
     * @brief Запускает захват заданного количества пакетов.
     * @param packet_count Количество пакетов для захвата
     * @return true, если захват прошёл успешно
     */
    bool run_capture(int packet_count);

    /**
     * @brief Применяет BPF-фильтр к открытому интерфейсу.
     * @param filter Строка с фильтром (например, "tcp port 80")
     */
    void apply_filter(const std::string& filter);

    /**
     * @brief Выводит информацию о пакете (Ethernet, IP, TCP/UDP и т.д.).
     * @param header Заголовок pcap пакета
     * @param packet Указатель на данные пакета
     */
    void print_packet_info(const pcap_pkthdr* header, const u_char* packet);

    /**
     * @brief Выводит статистику по типам захваченных пакетов.
     */
    void print_statistics() const;

private:
    /**
     * @brief Внутренняя функция-обработчик пакетов, вызывается pcap_loop().
     * @param user Пользовательские данные (указатель на Sniffer)
     * @param header Заголовок пакета
     * @param packet Данные пакета
     */
    static void packet_handler(u_char* user, const pcap_pkthdr* header, const u_char* packet);

    /// Указатель на дескриптор pcap интерфейса
    pcap_t* handle;

    /// Счётчики пакетов по типам
    int tcp_count = 0;     ///< Количество TCP пакетов
    int udp_count = 0;     ///< Количество UDP пакетов
    int arp_count = 0;     ///< Количество ARP пакетов
    int other_count = 0;   ///< Количество пакетов других типов
};

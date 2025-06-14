#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <string>

#include "doctest.h"
#include "sniffer.h"

// Проверка: открытие существующего интерфейса

TEST_CASE("Sniffer opens a valid interface") {
    Sniffer sniffer;
    CHECK(sniffer.open_interface("lo") == true);
}

// Проверка: ошибка при открытии несуществующего интерфейса

TEST_CASE("Sniffer fails on invalid interface") {
    Sniffer sniffer;
    CHECK(sniffer.open_interface("invalid0") == false);
}

// Проверка: установка валидного фильтра

TEST_CASE("Apply valid filter") {
    Sniffer sniffer;
    REQUIRE(sniffer.open_interface("lo"));
    CHECK_NOTHROW(sniffer.apply_filter("tcp"));
}

// Проверка: установка невалидного фильтра без краша
TEST_CASE("Apply invalid filter safely") {
    Sniffer sniffer;
    REQUIRE(sniffer.open_interface("lo"));
    CHECK_NOTHROW(sniffer.apply_filter("this is not a filter"));
}

// Проверка: безопасный вызов print_packet_info на фейковом пакете
TEST_CASE("Print packet info does not crash") {
    Sniffer sniffer;
    pcap_pkthdr header = {};
    u_char dummy_packet[64] = {};
    header.len = 64;
    sniffer.print_packet_info(&header, dummy_packet);
    CHECK(true);
}

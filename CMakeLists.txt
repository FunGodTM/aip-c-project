cmake_minimum_required(VERSION 3.10)
project(packet_sniffer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Поиск библиотеки pcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Основной исполняемый файл
add_executable(packet_sniffer
    src/main.cpp
    src/sniffer.cpp
)

target_include_directories(packet_sniffer PRIVATE
    ${PCAP_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(packet_sniffer PRIVATE ${PCAP_LIBRARIES})

# Тесты
enable_testing()

add_executable(tests
    tests/test_sniffer.cpp
    src/sniffer.cpp
)

target_include_directories(tests PRIVATE
    ${PCAP_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/extern
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(tests PRIVATE ${PCAP_LIBRARIES})

add_test(NAME SnifferTests COMMAND tests)

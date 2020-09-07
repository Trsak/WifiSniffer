cmake_minimum_required(VERSION 3.16)
project(sniffer)

set(CMAKE_CXX_STANDARD 14)

find_library(PCAP_LIBRARY pcap)
find_library(TINS_LIBRARY tins)

add_executable(sniffer main.cpp sniffer_libtins.cpp sniffer_libtins.h sniffer_libpcap.cpp sniffer_libpcap.h sniffer.h sniffer.cpp)
target_link_libraries(sniffer ${PCAP_LIBRARY} ${TINS_LIBRARY})
cmake_minimum_required(VERSION 3.18)
project(pcap_stats)

set(CMAKE_CXX_STANDARD 17)

add_executable(pcap_stats main.cpp PacketCollector.h PacketCollector.cpp)
include_directories(pcap_stats /s/PcapPlusPlus/Dist/header)
include_directories(pcap_stats /usr/include/netinet)
target_link_libraries(pcap_stats PUBLIC Pcap++ Packet++ Common++ pcap pthread)

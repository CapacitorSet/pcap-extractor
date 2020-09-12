#ifndef PCAP_STATS_PACKETCOLLECTOR_H
#define PCAP_STATS_PACKETCOLLECTOR_H

#include <PcapFileDevice.h>
#include <fstream>

class PacketCollector {
    std::ofstream &tlsFile, &httpFile, &dnsFile;
public:
    PacketCollector(std::ofstream &tlsFile, std::ofstream &httpFile, std::ofstream &dnsFile);
    ~PacketCollector();

    void digest(const pcpp::Packet*);

    uint64_t pktCount;
    uint64_t pktCountDiscardedNoEth;
};

#endif //PCAP_STATS_PACKETCOLLECTOR_H

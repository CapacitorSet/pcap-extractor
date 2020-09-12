#include <Packet.h>
#include <EthLayer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <SSLLayer.h>
#include <HttpLayer.h>
#include <iostream>
#include <DnsLayer.h>
#include "PacketCollector.h"

PacketCollector::PacketCollector(std::ofstream &tlsFile, std::ofstream &httpFile, std::ofstream &dnsFile)
    : tlsFile(tlsFile), httpFile(httpFile), dnsFile(dnsFile), pktCount(0), pktCountDiscardedNoEth(0) {};

PacketCollector::~PacketCollector() = default;

void PacketCollector::digest(const pcpp::Packet *packet) {
    pktCount++;
    auto *ethLayer = packet->getLayerOfType<pcpp::EthLayer>();
    if (ethLayer == nullptr) {
        pktCountDiscardedNoEth++;
        return;
    }
    auto srcMac = ethLayer->getSourceMac();
    auto *rawLayer = packet->getRawPacketReadOnly();
    auto timestamp = rawLayer->getPacketTimeStamp();
    auto *tcpLayer = packet->getLayerOfType<pcpp::TcpLayer>();
    auto *udpLayer = packet->getLayerOfType<pcpp::UdpLayer>();
    // The cast to int is required to print correctly
    int srcPort, dstPort;
    if (tcpLayer != nullptr) {
        auto tcpHeader = tcpLayer->getTcpHeader();
        srcPort = ntohs(tcpHeader->portSrc);
        dstPort = ntohs(tcpHeader->portDst);

        auto httpLayer = packet->getLayerOfType<pcpp::HttpRequestLayer>();
        if (httpLayer != nullptr) {
            auto hostname = httpLayer->getFieldByName("Host")->getFieldValue();
            httpFile << (1000 * timestamp.tv_sec + timestamp.tv_nsec / 1000000) << ";" << srcMac.toString() << ";"
                << hostname << std::endl;
        }

        // go over all SSL messages in this packet
        for (auto* sslLayer = packet->getLayerOfType<pcpp::SSLLayer>();
             sslLayer != nullptr;
             sslLayer = packet->getNextLayerOfType<pcpp::SSLLayer>(sslLayer)) {
            pcpp::SSLRecordType recType = sslLayer->getRecordType();
            if (recType != pcpp::SSL_HANDSHAKE)
                continue;
            auto *handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer *>(sslLayer);
            if (handshakeLayer == nullptr)
                continue;

            auto *clientHelloMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
            if (clientHelloMessage == nullptr)
                continue;

            auto *sniExt = clientHelloMessage->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
            if (sniExt == nullptr)
                continue;

            auto hostname = sniExt->getHostName();
            tlsFile << (1000 * timestamp.tv_sec + timestamp.tv_nsec / 1000000) << ";" << srcMac.toString() << ";"
                << hostname << ";" << dstPort << std::endl;
        }
    } else if (udpLayer != nullptr) {
        auto udpHeader = udpLayer->getUdpHeader();
        srcPort = ntohs(udpHeader->portSrc);
        dstPort = ntohs(udpHeader->portDst);

        auto *dnsLayer = packet->getLayerOfType<pcpp::DnsLayer>();
        if (dnsLayer != nullptr) {
            int isResponse = dnsLayer->getDnsHeader()->queryOrResponse;
            if (!isResponse)
                for (auto query = dnsLayer->getFirstQuery();
                        query != nullptr;
                        query = dnsLayer->getNextQuery(query)) {
                    const auto& hostname = query->getName();
                    if (hostname.find(".ip6.arpa") != std::string::npos)
                        continue;
                    if (hostname.find(".in-addr.arpa") != std::string::npos)
                        continue;
                    // dstPort disambiguates between DNS (53) and mDNS (5353)/LLMNR (5355)
                    dnsFile << (1000 * timestamp.tv_sec + timestamp.tv_nsec / 1000000) << ";" << srcMac.toString() << ";"
                        << hostname << ";" << dstPort << std::endl;
                }
        }
    } else return;
}

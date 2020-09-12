/**
 * SSLAnalyzer application
 * ========================
 * This application analyzes SSL/TLS traffic and presents detailed and diverse information about it. It can operate in live traffic
 * mode where this information is collected on live packets or in file mode where packets are being read from a pcap/pcapng file. The
 * information collected by this application includes:
 * - general data: number of packets, packet rate, amount of traffic, bandwidth
 * - flow data: number of flow, flow rate, average packets per flow, average data per flow
 * - SSL/TLS data: number of client-hello and server-hello messages, number of flows ended with successful handshake,
 *   number of flows ended with SSL alert
 * - hostname map (which hostnames were used and how much. Taken from the server-name-indication extension in the
 *   client-hello message)
 * - cipher-suite map (which cipher-suites were used and how much)
 * - SSL/TLS versions map (which SSL/TLS versions were used and how much)
 * - SSL/TLS ports map (which SSL/TLS TCP ports were used and how much)
 *
 * For more details about modes of operation and parameters run SSLAnalyzer -h
 */

#include <stdlib.h>
#include <string.h>
#if !defined(WIN32) && !defined(WINx64) && !defined(PCAPPP_MINGW_ENV)  //for using ntohl, ntohs, etc.
#include <in.h>
#endif
#include "PcapLiveDeviceList.h"
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "TablePrinter.h"
#include "PlatformSpecificUtils.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "PacketCollector.h"
#include <getopt.h>
#include <SSLLayer.h>
#include <fstream>
#include <cstring>

using namespace pcpp;

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)


#define PRINT_STAT_LINE(description, counter, measurement, type) \
		printf("%-46s %14" type " [%s]\n", description ":", counter,  measurement)

#define PRINT_STAT_LINE_INT(description, counter, measurement) \
		PRINT_STAT_LINE(description, counter, measurement, "d")

#define PRINT_STAT_LINE_DOUBLE(description, counter, measurement) \
		PRINT_STAT_LINE(description, counter, measurement, ".3f")

#define PRINT_STAT_HEADLINE(description) \
		printf("\n" description "\n--------------------\n\n")


#define DEFAULT_CALC_RATES_PERIOD_SEC 2

static struct option SSLAnalyzerOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"input-file",  required_argument, 0, 'f'},
	{"output-file", required_argument, 0, 'o'},
	{"tls-output-file", required_argument, 0, 'T'},
	{"http-output-file", required_argument, 0, 'H'},
	{"dns-output-file", required_argument, 0, 'D'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}
};


/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage: PCAP file mode:\n"
			"----------------------\n"
			"%s [-hv] -f input_file -T tls_output -H http_output -D dns_output\n"
			"\nOptions:\n\n"
			"    -f           : The input pcap/pcapng file to analyze. Required argument for this mode\n"
			"    -T           : The output file for TLS. Will be appended to.\n"
			"    -H           : The output file for HTTP. Will be appended to.\n"
			"    -D           : The output file for DNS. Will be appended to.\n"
			"    -v           : Displays the current version and exists\n"
			"    -h           : Displays this help message and exits\n\n"
			"Usage: Live traffic mode:\n"
			"-------------------------\n"
			"%s [-hv] -i interface\n"
			"\nOptions:\n\n"
			"    -i interface   : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address\n"
			"    -v             : Displays the current version and exists\n"
			"    -h             : Displays this help message and exits\n", AppName::get().c_str(), AppName::get().c_str());
}


/**
 * Print application version
 */
void printAppVersion()
{
	printf("%s %s\n", AppName::get().c_str(), getPcapPlusPlusVersionFull().c_str());
	printf("Built: %s\n", getBuildDateTime().c_str());
	printf("Built from: %s\n", getGitInfo().c_str());
	exit(0);
}

/**
 * packet capture callback - called whenever a packet arrives
 */
void onPacket(RawPacket* packet, PcapLiveDevice* dev, void* cookie)
{
	// parse the packet
	Packet parsedPacket(packet);

    // give the packet to the collector
	static_cast<PacketCollector*>(cookie)->digest(&parsedPacket);

	/*
	// if needed - write the packet to the output pcap file
	if (data->pcapWriter != NULL)
	{
		data->pcapWriter->writePacket(*packet);
	}
	*/
}


/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
}


/**
 * activate SSL/TLS analysis from pcap file
 */
void analyzeSSLFromPcapFile(std::string pcapFileName, std::string tlsOutput, std::string httpOutput, std::string dnsOutput)
{
	// open input file (pcap or pcapng file)
	IFileReaderDevice* reader = IFileReaderDevice::getReader(pcapFileName.c_str());

	if (!reader->open())
		EXIT_WITH_ERROR("Could not open input pcap file");

	std::ofstream tlsFile(tlsOutput, std::ios_base::app); // Open in append mode
    if (tlsFile.fail())
        throw std::ios_base::failure(std::strerror(errno));
    std::ofstream httpFile(httpOutput, std::ios_base::app); // Open in append mode
    if (httpFile.fail())
        throw std::ios_base::failure(std::strerror(errno));
    std::ofstream dnsFile(dnsOutput, std::ios_base::app); // Open in append mode
    if (dnsFile.fail())
        throw std::ios_base::failure(std::strerror(errno));

    // read the input file packet by packet and give it to the SSLStatsCollector for collecting stats
    PacketCollector pc(tlsFile, httpFile, dnsFile);
	RawPacket rawPacket;
	while(reader->getNextPacket(rawPacket))
	{
		Packet parsedPacket(&rawPacket);
		pc.digest(&parsedPacket);
	}

	if (pc.pktCountDiscardedNoEth != 0)
    	printf("%lu packets without Ethernet layer (out of %lu)\n", pc.pktCountDiscardedNoEth, pc.pktCount);

	// close input file
	reader->close();

	// free reader memory
	delete reader;
}


/**
 * activate SSL analysis from live traffic
 */
void analyzeSSLFromLiveTraffic(PcapLiveDevice *dev, std::string tlsOutput, std::string httpOutput, std::string dnsOutput)
{
	// open the device
	if (!dev->open())
		EXIT_WITH_ERROR("Could not open the device");

    std::ofstream tlsFile(tlsOutput, std::ios_base::app); // Open in append mode
    if (tlsFile.fail())
        throw std::ios_base::failure(std::strerror(errno));
    std::ofstream httpFile(httpOutput, std::ios_base::app); // Open in append mode
    if (httpFile.fail())
        throw std::ios_base::failure(std::strerror(errno));
    std::ofstream dnsFile(dnsOutput, std::ios_base::app); // Open in append mode
    if (dnsFile.fail())
        throw std::ios_base::failure(std::strerror(errno));

	// set SSL/TLS ports filter on the live device to capture only SSL/TLS packets
	std::vector<GeneralFilter*> portFilterVec;

	// Detect all ports considered as SSL/TLS traffic and add them to the filter.
	// The check is made for well known ports because currently SSLLayer does not support customizing of ports considered as SSL/TLS.
	for (uint16_t port = 0; port < 1024; ++port)
		if (pcpp::SSLLayer::isSSLPort(port))
			portFilterVec.push_back(new PortFilter(port, pcpp::SRC_OR_DST));

	// make an OR filter out of all port filters
	OrFilter orFilter(portFilterVec);

	// set the filter for the device
	if (!dev->setFilter(orFilter))
	{
		std::string filterAsString;
		orFilter.parseToString(filterAsString);
		EXIT_WITH_ERROR("Couldn't set the filter '%s' for the device", filterAsString.c_str());
	}

	// start capturing packets and collecting stats
	PacketCollector pc(tlsFile, httpFile, dnsFile);
    dev->startCapture(onPacket, &pc);

	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	while(!shouldStop)
	{
		PCAP_SLEEP(DEFAULT_CALC_RATES_PERIOD_SEC);
	}

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();
}

int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	std::string interfaceNameOrIP = "";
    std::string readPacketsFromPcapFileName = "";
    std::string tlsOutput = "", httpOutput = "", dnsOutput = "";


	int optionIndex = 0;
	char opt;

	while((opt = getopt_long (argc, argv, "i:f:T:H:D:hv", SSLAnalyzerOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'i':
				interfaceNameOrIP = optarg;
				break;
			case 'f':
				readPacketsFromPcapFileName = optarg;
				break;
			case 'T':
				tlsOutput = optarg;
				break;
			case 'H':
				httpOutput = optarg;
				break;
			case 'D':
				dnsOutput = optarg;
				break;
			case 'v':
				printAppVersion();
				break;
			case 'h':
				printUsage();
				return 0;
			default:
				printUsage();
				return -1;
		}
	}

	// if no interface nor input pcap file were provided - exit with error
    if (readPacketsFromPcapFileName == "" && interfaceNameOrIP == "")
        EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");

    if (tlsOutput.empty())
        EXIT_WITH_ERROR("No TLS file specified.");
    if (httpOutput.empty())
        EXIT_WITH_ERROR("No HTTP file specified.");
    if (dnsOutput.empty())
        EXIT_WITH_ERROR("No DNS file specified.");

    // analyze in pcap file mode
	if (readPacketsFromPcapFileName != "")
	{
        analyzeSSLFromPcapFile(readPacketsFromPcapFileName, tlsOutput, httpOutput, dnsOutput);
	}
	else // analyze in live traffic mode
	{
		// extract pcap live device by interface name or IP address
		PcapLiveDevice* dev = NULL;
		IPv4Address interfaceIP(interfaceNameOrIP);
		if (interfaceIP.isValid())
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
			if (dev == NULL)
				EXIT_WITH_ERROR("Couldn't find interface by provided IP");
		}
		else
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
			if (dev == NULL)
				EXIT_WITH_ERROR("Couldn't find interface by provided name");
		}

		// start capturing and analyzing traffic
        analyzeSSLFromLiveTraffic(dev, tlsOutput, httpOutput, dnsOutput);
	}
}

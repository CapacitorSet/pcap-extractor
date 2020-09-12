CXXFLAGS=-O2 -Wall -I/s/PcapPlusPlus/Dist/header -I/usr/include/netinet -fmessage-length=0 
LDFLAGS=
DEPS = PacketCollector.h
OBJ = main.o PacketCollector.o

%.o: %.c $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS)

main: $(OBJ)
	$(CXX) -o $@ $^ $(CXXFLAGS) -L/s/PcapPlusPlus/Dist -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread

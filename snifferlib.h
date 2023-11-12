#ifndef SNIFFER_LIB
#define SNIFFER_LIB

#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <vector>
#include <memory>
#include <chrono>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <arpa/inet.h>


const int buffer_size = 65536;

class PacketSniffer
{
public:
    PacketSniffer();

    bool createSocket();

    void processPacket(ssize_t size);

    void startSniffing();

    ~PacketSniffer();

private:
    int raw_socket;
    std::vector<unsigned char> buffer;
    size_t packet_count;
    size_t total_size;
    std::chrono::high_resolution_clock::time_point start_time;
};

#endif //SNIFFER_LIB
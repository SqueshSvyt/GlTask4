#ifndef SNIFERAPP_PACKETLOGGER_H
#define SNIFERAPP_PACKETLOGGER_H

#include <iostream>
#include <cstring>
#include <iomanip>
#include <fstream>
#include <future>
#include <mutex>
#include <vector>

#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

const std::string default_filename = "packet_log_file.txt";

struct PacketCounter{
    long ARP;
    long TCP;
    long UDP;
    long IGMP;
    long ICMP;

    PacketCounter();

    void reset();
};

class PacketLogger {
public:
    PacketLogger();
    PacketLogger(std::string file_name);
    ~PacketLogger();

    void LogPacketAsync(std::vector<unsigned char> buffer, long size);
    void LogPacketToFile(std::vector<unsigned char>& buffer, long size);

    PacketCounter packet_counter;
private:
    void printEthernetHeader(const std::vector<unsigned char>& buffer, long size);
    void printIpHeader(const std::vector<unsigned char>& buffer, long size);
    void printTcpPacket(const std::vector<unsigned char>& buffer, long size);
    void printUdpPacket(const std::vector<unsigned char>& buffer, long size);
    void printIcmpPacket(const std::vector<unsigned char>& buffer, long size);
    void printIgmpPacket(const std::vector<unsigned char>& buffer, long size);
    void printArpPacket(const std::vector<unsigned char>& buffer, long size);
    void printData(const unsigned char* data, long size);

    std::mutex mtx_file_print;
    std::ofstream logfile;
};


#endif //SNIFERAPP_PACKETLOGGER_H

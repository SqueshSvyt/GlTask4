#ifndef SNIFERAPP_FILEPACKETLOGGER_H
#define SNIFERAPP_FILEPACKETLOGGER_H

#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

const std::string default_filename = "packet_log_file.txt";

class PacketLogger {
public:
    PacketLogger();
    ~PacketLogger();

    void LogPacketToFile(const std::vector<unsigned char>& buffer);

private:
    void printEthernetHeader(const std::vector<unsigned char>& buffer);
    void printIpHeader(const std::vector<unsigned char>& buffer);
    void printTcpPacket(const std::vector<unsigned char>& buffer);
    void printUdpPacket(const std::vector<unsigned char>& buffer);
    void printIcmpPacket(const std::vector<unsigned char>& buffer);
    void printData(const std::vector<unsigned char>& buffer, int size);

    std::ofstream logfile;
};


#endif //SNIFERAPP_FILEPACKETLOGGER_H

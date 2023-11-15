#ifndef SNIFFER_LIB
#define SNIFFER_LIB

#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <vector>
#include <cmath>

#include <thread>
#include <future>
#include <chrono>
#include <mutex>
#include <atomic>

#include <memory>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "filepacketlogger.h"

const int buffer_size = 65536;
const std::string default_ip = "127.0.0.1";

struct PacketStatisticInfo{
    unsigned long long total_size;
    unsigned long long total_packet;
    unsigned long long packet_count_PC;
    unsigned long long total_size_PC;
    unsigned long long total_sen_data;
    unsigned long long total_sen_packet;
    unsigned long long total_rec_data;
    unsigned long long total_rec_packet;

    std::atomic<unsigned long long> sen_per_second{};
    std::atomic<unsigned long long> rec_per_second{};
    std::atomic<unsigned long long> _gateway_sen_per_second{};
    std::atomic<unsigned long long> _gateway_rec_per_second{};

    PacketStatisticInfo();
};

class PacketSniffer
{
public:
    PacketSniffer();
    ~PacketSniffer();

    bool createSocket();

    void outputOverallStatistics() const;
    void processPacket(ssize_t size);
    void start();
    void stop();

    void setCurrentIP(std::string arg_ip);

    PacketStatisticInfo pack_stat;
private:
    void startSniffing();
    void updateValue();
    void updateRec(ssize_t size);
    void updateSend(ssize_t size);
    void updateAllSocketGet(ssize_t size);
    void reset();
    static void clearLine(int n);
    static std::string formatBytes(unsigned long long bytes);

    int raw_socket;
    std::string current_ip;
    std::vector<unsigned char> buffer;
    mutable std::mutex mtx_rec;
    mutable std::mutex mtx_print;
    std::thread sniff_thread;
    std::thread ui_thread;
    std::future<void> speed_reset_async;
    std::chrono::high_resolution_clock::time_point start_time;

    PacketLogger packetLogger;
};

#endif //SNIFFER_LIB
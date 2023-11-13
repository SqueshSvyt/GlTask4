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

const int buffer_size = 65536;

struct PacketStatisticInfo{
    unsigned long long packet_count;
    unsigned long long total_size;
    unsigned long long total_sen_data;
    unsigned long long total_sen_packet;
    unsigned long long total_rec_data;
    unsigned long long total_rec_packet;

    std::atomic<unsigned long long> sen_per_second{};
    std::atomic<unsigned long long> rec_per_second{};

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

    static std::string getCurrentIP();

    PacketStatisticInfo pack_stat;
private:
    void startSniffing();
    void updateValue();
    static std::string formatBytes(unsigned long long bytes);

    int raw_socket;
    std::string current_ip;
    std::vector<unsigned char> buffer;
    mutable std::mutex mtx;
    std::thread sniff_thread;
    std::thread ui_thread;
    std::future<void> speed_reset_async;
    std::chrono::high_resolution_clock::time_point start_time;
};

#endif //SNIFFER_LIB
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
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "packetlogger.h"

const int buffer_size = 65536;
const std::string default_ip = "127.0.0.1";

enum Start_type{
    SNIFF_DEFAULT,
    SNIFF_BY_IP
};

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
    void start(int type);
    void stop();

    void setCurrentIP(std::string arg_ip);

    PacketStatisticInfo pack_stat;
    mutable std::mutex mtx_print;
private:
    void startSniffingDefault();
    void startSniffingByIP();
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
    std::atomic<bool> stop_work;
    mutable std::mutex mtx_rec;
    std::thread sniff_thread;
    std::thread ui_thread;
    std::future<void> speed_reset_async;
    std::chrono::high_resolution_clock::time_point start_time;

    PacketLogger packet_Logger;
};

#endif //SNIFFER_LIB
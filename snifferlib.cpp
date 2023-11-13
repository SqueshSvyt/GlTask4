#include "snifferlib.h"

PacketSniffer::PacketSniffer() : raw_socket(-1), buffer(buffer_size), pack_stat() {
    //start_time = std::chrono::high_resolution_clock::now();
    current_ip = getCurrentIP();
}

PacketSniffer::~PacketSniffer(){
    if(sniff_thread.joinable())
        sniff_thread.join();

    if(ui_thread.joinable())
        ui_thread.join();

    if(speed_reset_async.valid())
        speed_reset_async.wait();

    close(raw_socket);
}

std::string PacketSniffer::getCurrentIP() {
    struct ifaddrs* ifAddrStruct = nullptr;
    void* tmpAddrPtr;
    std::string ipAddress;

    if (getifaddrs(&ifAddrStruct) == 0) {
        for (struct ifaddrs* ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET) {
                tmpAddrPtr = &reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                ipAddress = std::string(addressBuffer);
                 // Stop after the first IPv4 address is found
            }
        }
        freeifaddrs(ifAddrStruct);
    }

    return ipAddress;
}

bool PacketSniffer::createSocket(){
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    return raw_socket != -1;
}

void PacketSniffer::processPacket(ssize_t size){
    auto* ip_header = reinterpret_cast<struct iphdr*>(const_cast<unsigned char*>(buffer.data()) + sizeof(struct ethhdr));
    //struct ethhdr* eth = reinterpret_cast<struct ethhdr*>(const_cast<unsigned char*>(buffer.data()));

    // Increment packet count and update total size




    if (ip_header->saddr == inet_addr(current_ip.c_str())) {
        pack_stat.packet_count++;
        pack_stat.total_size += size;
        pack_stat.total_sen_data += size;
        pack_stat.sen_per_second += size;
        pack_stat.total_sen_packet++;
    } else if(ip_header->daddr == inet_addr(current_ip.c_str())){
        pack_stat.packet_count++;
        pack_stat.total_size += size;
        pack_stat.total_rec_data += size;
        pack_stat.rec_per_second += size;
        pack_stat.total_rec_packet++;
    }

    /*switch (ip_header->protocol)
    {
        case IPPROTO_TCP: {
            //auto* tcp_header = reinterpret_cast<struct tcphdr*>(const_cast<unsigned char*>(buffer.data()) + sizeof(struct ethhdr) + sizeof(struct iphdr));
            break;
        }
        case IPPROTO_UDP: {
            //auto* udp_header = reinterpret_cast<struct udphdr*>(const_cast<unsigned char*>(buffer.data()) + sizeof(struct ethhdr) + sizeof(struct iphdr));
            break;
        }
        case IPPROTO_ICMP:
            break;
        case IPPROTO_IGMP:
            break;
        default:
            std::cout << "Unknown packet!" << std::endl;
            break;
    }*/
}

void PacketSniffer::outputOverallStatistics() const{
    while (true) {
        unsigned long long speed_sen = pack_stat.sen_per_second.load();
        unsigned long long speed_rec  = pack_stat.rec_per_second.load();

        std::cout << "-------------------Overall Statistics-------------------" << std::endl;
        std::cout << "Total Packets: " << pack_stat.packet_count << ", Total Size: " << formatBytes(pack_stat.total_size) << " bytes" << std::endl;
        std::cout << "Total Sent Bytes: " << formatBytes(pack_stat.total_sen_data) << ", Total Received Bytes: " << formatBytes(pack_stat.total_rec_data) << std::endl;
        std::cout << "Total Sent Packet: " << pack_stat.total_sen_packet << ", Total Received Packet: " << pack_stat.total_rec_packet << std::endl;
        std::cout << "Sent Speed: " << formatBytes(speed_sen) << ", Received Speed: " << formatBytes(speed_rec) << std::endl;
        std::cout << "---------------------------------------------------------" << std::endl;
        for (int i = 0; i < 6; ++i)
            std::cout << "\x1b[A\x1b[2K"; // Move up one line and clear it
        std::this_thread::sleep_for(std::chrono::milliseconds (1000));
        if(!sniff_thread.joinable())
            return;
    }
}

void PacketSniffer::startSniffing(){
    auto startTime = std::chrono::high_resolution_clock::now();
    ssize_t data_size;
    
    int durationSeconds = 120;
    
    sockaddr saddr{};
    saddr.sa_family = inet_addr(current_ip.c_str());
    socklen_t saddr_size = sizeof(saddr);
    while (true) {

        if(raw_socket == -1){
            perror("Socket error");
            break;
        }

        // Receive a packet into the vector
        mtx.lock();
        data_size = recvfrom(raw_socket, buffer.data() , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        mtx.unlock();

        if (data_size < 0) {
            perror("Recvfrom error");
            break;
        }

        // Process the received packet
        processPacket(data_size);

        auto currentTime = std::chrono::high_resolution_clock::now();
        auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();
        if (elapsedSeconds >= durationSeconds) {
            break;
        }    
    }
}

void PacketSniffer::start() {
    sniff_thread = std::thread(&PacketSniffer::startSniffing, this);
    ui_thread = std::thread(&PacketSniffer::outputOverallStatistics, this);
    speed_reset_async = std::async(std::launch::async, &PacketSniffer::updateValue, this);
}

std::string PacketSniffer::formatBytes(unsigned long long bytes) {
    const int unit = 1024;
    if (bytes < unit) {
        return std::to_string(bytes) + " B";
    }

    int exp = static_cast<int>(std::log(bytes) / std::log(unit));
    char prefix = "KMGTPE"[exp - 1];// 'K' for kilobytes, 'M' for megabytes, etc.

    return std::to_string(bytes / std::pow(unit, exp)) + " " + prefix + "B";
}

void PacketSniffer::updateValue() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        pack_stat.sen_per_second = 0;
        pack_stat.rec_per_second = 0;

        if(!sniff_thread.joinable())
            return;
    }
}

PacketStatisticInfo::PacketStatisticInfo(){
    packet_count=0;
    total_size=0;
    total_rec_data=0;
    total_sen_data=0;
    total_sen_packet=0;
    total_rec_packet=0;
    rec_per_second=0;
    sen_per_second=0;
}
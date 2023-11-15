#include "snifferlib.h"

PacketSniffer::PacketSniffer() : raw_socket(-1), buffer(buffer_size), pack_stat(), packetLogger() {
    current_ip = default_ip;
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

void PacketSniffer::reset() {
    pack_stat.total_packet=0;
    pack_stat.total_size=0;
    pack_stat.packet_count_PC=0;
    pack_stat.total_size_PC=0;
    pack_stat.total_rec_data=0;
    pack_stat.total_sen_data=0;
    pack_stat.total_sen_packet=0;
    pack_stat.total_rec_packet=0;
    pack_stat.rec_per_second=0;
    pack_stat.sen_per_second=0;
    pack_stat._gateway_sen_per_second=0;
    pack_stat._gateway_rec_per_second=0;
}

void PacketSniffer::setCurrentIP(std::string arg_ip){
    current_ip = std::move(arg_ip);
}

void PacketSniffer::clearLine(int n){
    for (int i = 0; i < n; ++i)
        std::cout << "\x1b[A\x1b[2K"; // Move up one line and clear it
}

bool PacketSniffer::createSocket(){
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    return raw_socket != -1;
}

void PacketSniffer::updateSend(ssize_t size) {
    pack_stat.packet_count_PC++;
    pack_stat.total_size_PC += size;
    pack_stat.total_sen_data += size;
    pack_stat.sen_per_second += size;
    pack_stat.total_sen_packet++;
}

void PacketSniffer::updateRec(ssize_t size) {
    pack_stat.packet_count_PC++;
    pack_stat.total_size_PC += size;
    pack_stat.total_rec_data += size;
    pack_stat.rec_per_second += size;
    pack_stat.total_rec_packet++;
}

void PacketSniffer::updateAllSocketGet(ssize_t size){
    pack_stat.total_size += size;
    pack_stat.total_packet++;
}

void PacketSniffer::processPacket(ssize_t size){
    //Ip header for cheak ip
    auto* ip_header = reinterpret_cast<struct iphdr*>(const_cast<unsigned char*>(buffer.data()) + sizeof(struct ethhdr));

    // Increment packet count and update total size
    if (ip_header->saddr == inet_addr(current_ip.c_str()))
        updateSend(size);
    else if(ip_header->daddr == inet_addr(current_ip.c_str()))
        updateRec(size);

    updateAllSocketGet(size);

    //Log info about packet
    packetLogger.LogPacketToFile(buffer);
}

void PacketSniffer::outputOverallStatistics() const{
    while (true) {
        mtx_print.lock();

        unsigned long long speed_sen = pack_stat.sen_per_second.load();
        unsigned long long speed_rec  = pack_stat.rec_per_second.load();

        std::cout << "-------------------Statistics for IP------------------------" << std::endl;
        std::cout << "Total Packets: " << pack_stat.packet_count_PC << ", Total Size: " << formatBytes(pack_stat.total_size_PC) << " bytes" << std::endl;
        std::cout << "Total Sent Bytes: " << formatBytes(pack_stat.total_sen_data) << ", Total Received Bytes: " << formatBytes(pack_stat.total_rec_data) << std::endl;
        std::cout << "Total Sent Packet: " << pack_stat.total_sen_packet << ", Total Received Packet: " << pack_stat.total_rec_packet << std::endl;
        std::cout << "Sent Speed: " << formatBytes(speed_sen) << ", Received Speed: " << formatBytes(speed_rec) << std::endl;

        std::cout << "-------------------Overall Statistics-------------------" << std::endl;
        std::cout << "Total Packets: " << pack_stat.total_packet << ", Total Size: " << formatBytes(pack_stat.total_size) << " bytes" << std::endl;
        std::cout << "----------------------------------------------------------------" << std::endl;
        mtx_print.unlock();

        std::this_thread::sleep_for(std::chrono::milliseconds (1000));

        mtx_print.lock();
        clearLine(8);
        mtx_print.unlock();

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
        mtx_rec.lock();
        data_size = recvfrom(raw_socket, buffer.data() , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        mtx_rec.unlock();

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
    if(current_ip.empty()){
        return;
    }

    sniff_thread = std::thread(&PacketSniffer::startSniffing, this);
    ui_thread = std::thread(&PacketSniffer::outputOverallStatistics, this);
    speed_reset_async = std::async(std::launch::async, &PacketSniffer::updateValue, this);
}

void PacketSniffer::stop() {
    if(sniff_thread.joinable())
        sniff_thread.join();

    if(ui_thread.joinable())
        ui_thread.join();

    if(speed_reset_async.valid())
        speed_reset_async.wait();

    reset();
}

std::string PacketSniffer::formatBytes(unsigned long long bytes) {
    const int unit = 1024;
    if (bytes < unit)
        return std::to_string(bytes) + " B";

    int exp = static_cast<int>(std::log(bytes) / std::log(unit));
    char prefix = "KMGTPE"[exp - 1];

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
    total_packet=0;
    total_size=0;
    packet_count_PC=0;
    total_size_PC=0;
    total_rec_data=0;
    total_sen_data=0;
    total_sen_packet=0;
    total_rec_packet=0;
    rec_per_second=0;
    sen_per_second=0;
    _gateway_sen_per_second=0;
    _gateway_rec_per_second=0;
}
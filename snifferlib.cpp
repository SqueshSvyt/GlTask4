#include "snifferlib.h"

PacketSniffer::PacketSniffer() : raw_socket(-1), buffer(65536), 
                                    packet_count(0), total_size(0) {
    start_time = std::chrono::high_resolution_clock::now();
}

PacketSniffer::~PacketSniffer(){
    close(raw_socket);
}

bool PacketSniffer::createSocket(){
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    return raw_socket != -1;
}

void PacketSniffer::processPacket(ssize_t size){
    // Increment packet count and update total size
    packet_count++;
    total_size += buffer.size();

    // Calculate time elapsed since the start
    auto current_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_seconds = current_time - start_time;

    // Calculate data rate in bytes per second
    double data_rate = total_size / elapsed_seconds.count();

    struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(const_cast<unsigned char*>(buffer.data()) + sizeof(struct ethhdr));
    struct ethhdr* eth = reinterpret_cast<struct ethhdr*>(const_cast<unsigned char*>(buffer.data()));
    
    switch (ip_header->protocol)
    {
        case IPPROTO_TCP: {
            struct tcphdr* tcp_header = reinterpret_cast<struct tcphdr*>(const_cast<unsigned char*>(buffer.data()) + sizeof(struct ethhdr) + sizeof(struct iphdr));
        
            unsigned int source_port  = ntohs(tcp_header->source);
            unsigned int dest_port = ntohs(tcp_header->dest);

            char source_ip[INET_ADDRSTRLEN];
            char dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
            
            std::cout << "-------------------TCP--------------------" << std::endl;
            std::cout << "Packet Count: " << packet_count << ", Total Size: " << total_size << " bytes" << std::endl;
            std::cout << "Data Rate: " << data_rate << " bytes/second" << std::endl;
            std::cout << "Source IP: " << source_ip << ", Destination IP: " << dest_ip << std::endl;
            std::cout << "Source Port: " << source_port << ", Destination Port: " << dest_port << std::endl;
            std::cout << "Protocol: " << eth->h_proto << std::endl;
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr* udp_header = reinterpret_cast<struct udphdr*>(const_cast<unsigned char*>(buffer.data()) + sizeof(struct ethhdr) + sizeof(struct iphdr));

            unsigned int source_port = ntohs(udp_header->source);
            unsigned int dest_port = ntohs(udp_header->dest);

            char source_ip[INET_ADDRSTRLEN];
            char dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);

            std::cout << "-------------------UDP--------------------" << std::endl;
            std::cout << "Packet Count: " << packet_count << ", Total Size: " << total_size << " bytes" << std::endl;
            std::cout << "Data Rate: " << data_rate << " bytes/second" << std::endl;
            std::cout << "Source IP: " << source_ip << ", Destination IP: " << dest_ip << std::endl;
            std::cout << "Source Port: " << source_port << ", Destination Port: " << dest_port << std::endl;
            break;
        }
        default:
            std::cout << "Unknown packet!" << std::endl;
            break;
    }
}

void PacketSniffer::startSniffing(){
    auto startTime = std::chrono::high_resolution_clock::now();
    ssize_t data_size;
    
    int durationSeconds = 120;
    
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);
    while (true) {
        if(raw_socket == -1){
            perror("Socket error");
            break;
        }

        // Receive a packet into the vector
        data_size = recvfrom(raw_socket, buffer.data() , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);

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
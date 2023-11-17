#include "../include/packetlogger.h"

PacketLogger::PacketLogger() : logfile(default_filename) {}

PacketLogger::PacketLogger(std::string file_name) : logfile(file_name) {}

PacketLogger::~PacketLogger() = default;

void PacketLogger::LogPacketAsync(std::vector<unsigned char> buffer, long size) {
    std::future<void> file_print = std::async(&PacketLogger::LogPacketToFile, this, std::ref(buffer), size);

    if(file_print.valid())
        file_print.wait();
}

void PacketLogger::LogPacketToFile(std::vector<unsigned char>& buffer, long size) {
    std::lock_guard<std::mutex> lock(mtx_file_print);
    const auto* ethHeader = reinterpret_cast<const struct ethhdr*>(buffer.data());
    if(ethHeader->h_proto == ETH_P_ARP){
        printArpPacket(buffer, size);
        packet_counter.ARP++;
        return;
    }
    auto* ip_header = reinterpret_cast<struct iphdr*>(const_cast<unsigned char*>(buffer.data()) + sizeof(struct ethhdr));
    switch (ip_header->protocol) //Check the Protocol and do accordingly...
    {
        case IPPROTO_ICMP:  //ICMP Protocol
            printIcmpPacket(buffer, size);
            packet_counter.ICMP++;
            break;

        case IPPROTO_IGMP:  //IGMP Protocol
            printIgmpPacket(buffer, size);
            packet_counter.IGMP++;
            break;

        case IPPROTO_TCP:  //TCP Protocol
            printTcpPacket(buffer, size);
            packet_counter.TCP++;
            break;

        case IPPROTO_UDP: //UDP Protocol
            printUdpPacket(buffer, size);
            packet_counter.UDP++;
            break;

        default:
            break;
    }
}

void PacketLogger::printEthernetHeader(const std::vector<unsigned char>& buffer, long size)
{
    if (buffer.size() < sizeof(struct ether_header)) {
        // Handle the case where the buffer size is smaller than the Ethernet header size
        std::cerr << "Buffer size is too small for an Ethernet header." << std::endl;
        return;
    }

    const auto* eth = reinterpret_cast<const struct ether_header*>(buffer.data());

    logfile << std::endl;
    logfile << "Ethernet Header\n";
    logfile << "   |-Destination Address : " << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(eth->ether_dhost[0]) << "-"
            << static_cast<unsigned>(eth->ether_dhost[1]) << "-"
            << static_cast<unsigned>(eth->ether_dhost[2]) << "-"
            << static_cast<unsigned>(eth->ether_dhost[3]) << "-"
            << static_cast<unsigned>(eth->ether_dhost[4]) << "-"
            << static_cast<unsigned>(eth->ether_dhost[5]) << std::endl;
    logfile << "   |-Source Address      : " << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(eth->ether_shost[0]) << "-"
            << static_cast<unsigned>(eth->ether_shost[1]) << "-"
            << static_cast<unsigned>(eth->ether_shost[2]) << "-"
            << static_cast<unsigned>(eth->ether_shost[3]) << "-"
            << static_cast<unsigned>(eth->ether_shost[4]) << "-"
            << static_cast<unsigned>(eth->ether_shost[5]) << std::endl;
    logfile << "   |-Protocol            : " << ntohs(eth->ether_type) << std::endl;
}

void PacketLogger::printIpHeader(const std::vector<unsigned char>& Buffer, long size)
{
    printEthernetHeader(Buffer, size);

    unsigned short iphdrlen;

    const auto* iph = reinterpret_cast<const struct iphdr*>(Buffer.data() + sizeof(struct ether_header));
    iphdrlen = iph->ihl * 4;

    struct sockaddr_in source{}, dest{}; // Value initialization to zero

    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;

    logfile << std::endl;
    logfile << "IP Header\n" << std::dec;
    logfile << "   |-IP Version        : " << static_cast<unsigned int>(iph->version) << std::endl;
    logfile << "   |-IP Header Length  : " << static_cast<unsigned int>(iph->ihl) << " DWORDS or "
            << static_cast<unsigned int>(iph->ihl) * 4 << " Bytes\n";
    logfile << "   |-Type Of Service   : " << static_cast<unsigned int>(iph->tos) << std::endl;
    logfile << "   |-IP Total Length   : " << ntohs(iph->tot_len) << " Bytes(Size of Packet)\n";
    logfile << "   |-Identification    : " << ntohs(iph->id) << std::endl;
    logfile << "   |-TTL      : " << static_cast<unsigned int>(iph->ttl) << std::endl;
    logfile << "   |-Protocol : " << static_cast<unsigned int>(iph->protocol) << std::endl;
    logfile << "   |-Checksum : " << ntohs(iph->check) << std::endl;
    logfile << "   |-Source IP        : " << inet_ntoa(source.sin_addr) << std::endl;
    logfile << "   |-Destination IP   : " << inet_ntoa(dest.sin_addr) << std::endl;
}

void PacketLogger::printTcpPacket(const std::vector<unsigned char>& Buffer, long size)
{
    const auto* iph = reinterpret_cast<const struct iphdr*>(Buffer.data() + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    const auto* tcph = reinterpret_cast<const struct tcphdr*>(Buffer.data() + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

    logfile << "\n\n***********************TCP Packet*************************\n";

    printIpHeader(Buffer, size);

    logfile << std::endl;
    logfile << "TCP Header\n" << std::dec;
    logfile << "   |-Source Port      : " << ntohs(tcph->source) << std::endl;
    logfile << "   |-Destination Port : " << ntohs(tcph->dest) << std::endl;
    logfile << "   |-Sequence Number    : " << ntohl(tcph->seq) << std::endl;
    logfile << "   |-Acknowledge Number : " << ntohl(tcph->ack_seq) << std::endl;
    logfile << "   |-Header Length      : " << static_cast<unsigned int>(tcph->doff) << " DWORDS or "
            << static_cast<unsigned int>(tcph->doff) * 4 << " BYTES\n";
    logfile << "   |-Urgent Flag          : " << static_cast<unsigned int>(tcph->urg) << std::endl;
    logfile << "   |-Acknowledgement Flag : " << static_cast<unsigned int>(tcph->ack) << std::endl;
    logfile << "   |-Push Flag            : " << static_cast<unsigned int>(tcph->psh) << std::endl;
    logfile << "   |-Reset Flag           : " << static_cast<unsigned int>(tcph->rst) << std::endl;
    logfile << "   |-Synchronise Flag     : " << static_cast<unsigned int>(tcph->syn) << std::endl;
    logfile << "   |-Finish Flag          : " << static_cast<unsigned int>(tcph->fin) << std::endl;
    logfile << "   |-Window         : " << ntohs(tcph->window) << std::endl;
    logfile << "   |-Checksum       : " << ntohs(tcph->check) << std::endl;
    logfile << "   |-Urgent Pointer : " << tcph->urg_ptr << std::endl;
    logfile << std::endl;
    logfile << "                        DATA Dump                         ";
    logfile << std::endl;

    logfile << "IP Header\n";
    printData(Buffer.data(), iphdrlen);

    logfile << "TCP Header\n";
    printData(Buffer.data() + iphdrlen, sizeof(struct udphdr));

    logfile << "Data Payload\n";
    printData(Buffer.data() + header_size , size  - header_size);

    logfile << "\n###########################################################";
}

void PacketLogger::printUdpPacket(const std::vector<unsigned char>& Buffer, long size)
{
    const auto* iph = reinterpret_cast<const struct iphdr*>(Buffer.data() + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    const auto* udph = reinterpret_cast<const struct udphdr*>(Buffer.data() + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);

    logfile << "\n\n***********************UDP Packet*************************\n";
    printIpHeader(Buffer, size);

    logfile << "\nUDP Header\n" << std::dec;
    logfile << "   |-Source Port      : " << ntohs(udph->source) << "\n";
    logfile << "   |-Destination Port : " << ntohs(udph->dest) << "\n";
    logfile << "   |-UDP Length       : " << ntohs(udph->len) << "\n";
    logfile << "   |-UDP Checksum     : " << ntohs(udph->check) << "\n";

    logfile << "\n";
    logfile << "IP Header\n";
    printData(Buffer.data(), iphdrlen);

    logfile << "UDP Header\n";
    printData(Buffer.data() + iphdrlen, sizeof(struct udphdr));

    logfile << "Data Payload\n";
    // Move the pointer ahead and reduce the size of the string
    printData(Buffer.data() + header_size , size - header_size);

    logfile << "\n###########################################################";
}

void PacketLogger::printIcmpPacket(const std::vector<unsigned char>& Buffer, long size)
{
    const auto* iph = reinterpret_cast<const struct iphdr*>(Buffer.data() + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    const auto* icmph = reinterpret_cast<const struct icmphdr*>(Buffer.data() + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);

    logfile << "\n\n***********************ICMP Packet*************************\n";
    printIpHeader(Buffer, size);

    logfile << "\n";
    logfile << "ICMP Header\n";
    logfile << "   |-Type : " << static_cast<unsigned int>(icmph->type) << std::dec;

    if (static_cast<unsigned int>(icmph->type) == 11)
    {
        logfile << "  (TTL Expired)\n";
    }
    else if (static_cast<unsigned int>(icmph->type) == ICMP_ECHOREPLY)
    {
        logfile << "  (ICMP Echo Reply)\n";
    }

    logfile << "   |-Code : " << static_cast<unsigned int>(icmph->code) << "\n";
    logfile << "   |-Checksum : " << ntohs(icmph->checksum) << "\n";
    logfile << "   |-ID       : " << ntohs(icmph->un.echo.id) << "\n";
    logfile << "   |-Sequence : " << ntohs(icmph->un.echo.sequence) << "\n";
    logfile << "\n";

    logfile << "IP Header\n";
    printData(Buffer.data(), iphdrlen);

    logfile << "ICMP Header\n";
    printData(Buffer.data() + iphdrlen, sizeof(struct icmphdr));

    logfile << "Data Payload\n";
    // Move the pointer ahead and reduce the size of the string
    printData(reinterpret_cast<const unsigned char *>(Buffer.data() + iphdrlen + sizeof(*icmph)), size - header_size);

    logfile << "\n###########################################################";
}

void PacketLogger::printIgmpPacket(const std::vector<unsigned char> &Buffer, long size) {
    const auto* iph = reinterpret_cast<const struct iphdr*>(Buffer.data() + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    const auto* igmph = reinterpret_cast<const struct igmp*>(Buffer.data() + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct igmp);

    logfile << "\n\n***********************IGMP Packet*************************\n";
    printIpHeader(Buffer, size);

    logfile << "\n";
    logfile << "IGMP Header\n";
    logfile << "   |-Type : " << static_cast<unsigned int>(igmph->igmp_type) << std::dec;

    // Add more cases if needed for different IGMP types
    if (static_cast<unsigned int>(igmph->igmp_type) == IGMP_MEMBERSHIP_QUERY)
    {
        logfile << "  (Membership Query)\n";
    }
    else if (static_cast<unsigned int>(igmph->igmp_type) == IGMP_V1_MEMBERSHIP_REPORT)
    {
        logfile << "  (Membership Report - Version 1)\n";
    }

    logfile << "   |-Checksum : " << ntohs(igmph->igmp_cksum) << "\n";
    logfile << "   |-Group Address : " << inet_ntoa(igmph->igmp_group) << "\n";
    logfile << "\n";

    logfile << "IP Header\n";
    printData(Buffer.data(), iphdrlen);

    logfile << "IGMP Header\n";
    printData(Buffer.data() + iphdrlen, sizeof(struct igmp));

    logfile << "Data Payload\n";
    // Move the pointer ahead and reduce the size of the string
    printData(reinterpret_cast<const unsigned char*>(Buffer.data() + iphdrlen + sizeof(*igmph)), size - header_size);

    logfile << "\n###########################################################";
}

void PacketLogger::printArpPacket(const std::vector<unsigned char> &Buffer, long size) {
    const auto* arpPacket = reinterpret_cast<const struct ether_arp*>(Buffer.data());

    logfile << "\n\n***********************ARP Packet*************************\n";
    printEthernetHeader(Buffer, size);

    logfile << "\n";
    logfile << "ARP Header\n";
    logfile << "   |-Hardware Type: " << ntohs(arpPacket->ea_hdr.ar_hrd) << "\n";
    logfile << "   |-Protocol Type: " << ntohs(arpPacket->ea_hdr.ar_pro) << "\n";
    logfile << "   |-Hardware Address Length: " << static_cast<unsigned int>(arpPacket->ea_hdr.ar_hln) << "\n";
    logfile << "   |-Protocol Address Length: " << static_cast<unsigned int>(arpPacket->ea_hdr.ar_pln) << "\n";
    logfile << "   |-Operation: " << ntohs(arpPacket->ea_hdr.ar_op) << "\n";

    logfile << "   |-Sender MAC: ";
    for (int i = 0; i < ETH_ALEN; ++i)
        logfile << std::hex << static_cast<unsigned int>(arpPacket->arp_sha[i]) << ' ';

    logfile << "\n   |-Sender IP: ";
    for (int i = 0; i < 4; ++i)
        logfile << static_cast<unsigned int>(arpPacket->arp_spa[i]) << ' ';

    logfile << "\n   |-Target MAC: ";
    for (int i = 0; i < ETH_ALEN; ++i)
        logfile << std::hex << static_cast<unsigned int>(arpPacket->arp_tha[i]) << ' ';

    logfile << "\n   |-Target IP: ";
    for (int i = 0; i < 4; ++i)
        logfile << static_cast<unsigned int>(arpPacket->arp_tpa[i]) << ' ';

    logfile << "\n";

    logfile << "ARP Header\n";
    printData(Buffer.data() + sizeof(struct ether_arp), sizeof(struct ether_arp));

    logfile << "Data Payload\n";
    // Move the pointer ahead and reduce the size of the buffer
    printData(Buffer.data() + sizeof(struct ether_arp), size - sizeof(struct ether_arp));

    logfile << "\n###########################################################";
}

void PacketLogger::printData(const unsigned char* data, long Size)
{
    int i, j;
    for (i = 0; i < Size; i++)
    {
        if (i != 0 && i % 16 == 0)   // if one line of hex printing is complete...
        {
            logfile << "         ";
            for (j = i - 16; j < i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                    logfile << static_cast<char>(data[j]);  // if it's a number or alphabet
                else
                    logfile << ".";  // otherwise print a dot
            }
            logfile << "\n";
        }

        if (i % 16 == 0)
            logfile << "   ";
        logfile << " " << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned int>(data[i]);

        if (i == Size - 1)  // print the last spaces
        {
            for (j = 0; j < 15 - i % 16; j++)
            {
                logfile << "   ";  // extra spaces
            }

            logfile << "         ";

            for (j = i - i % 16; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                {
                    logfile << static_cast<char>(data[j]);
                }
                else
                {
                    logfile << ".";
                }
            }

            logfile << "\n";
        }
    }
}

PacketCounter::PacketCounter(){
    ARP=0;
    TCP=0;
    UDP=0;
    IGMP=0;
    ICMP=0;
};

void PacketCounter::reset() {
    ARP=0;
    TCP=0;
    UDP=0;
    IGMP=0;
    ICMP=0;
}
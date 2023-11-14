#include "filepacketlogger.h"

PacketLogger::PacketLogger() : logfile(default_filename) {}

PacketLogger::~PacketLogger() {}

void PacketLogger::LogPacketToFile(const std::vector<unsigned char>& buffer) {
    auto* ip_header = reinterpret_cast<struct iphdr*>(const_cast<unsigned char*>(buffer.data()) + sizeof(struct ethhdr));
    switch (ip_header->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            printIcmpPacket(buffer);
            break;

        case 2:  //IGMP Protocol

            break;

        case 6:  //TCP Protocol
            printTcpPacket(buffer);
            break;

        case 17: //UDP Protocol
            printUdpPacket(buffer);
            break;

        default: //Some Other Protocol like ARP etc.
            break;
    }
}

void PacketLogger::printEthernetHeader(const std::vector<unsigned char>& buffer)
{
    if (buffer.size() < sizeof(struct ether_header)) {
        // Handle the case where the buffer size is smaller than the Ethernet header size
        std::cerr << "Buffer size is too small for an Ethernet header." << std::endl;
        return;
    }

    const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(buffer.data());

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

void PacketLogger::printIpHeader(const std::vector<unsigned char>& Buffer)
{
    printEthernetHeader(Buffer);

    unsigned short iphdrlen;

    const struct iphdr* iph = reinterpret_cast<const struct iphdr*>(Buffer.data() + sizeof(struct ether_header));
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

void PacketLogger::printTcpPacket(const std::vector<unsigned char>& Buffer)
{
    const struct iphdr* iph = reinterpret_cast<const struct iphdr*>(Buffer.data() + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    const struct tcphdr* tcph = reinterpret_cast<const struct tcphdr*>(Buffer.data() + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

    logfile << "\n\n***********************TCP Packet*************************\n";

    printIpHeader(Buffer);

    logfile << std::endl;
    logfile << "TCP Header\n" << std::dec;;
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
    printData(Buffer, iphdrlen);

    logfile << "TCP Header\n";
    printData(Buffer, tcph->doff * 4);

    logfile << "Data Payload\n";
    printData(Buffer, Buffer.size() - header_size);

    logfile << "\n###########################################################";
}

void PacketLogger::printUdpPacket(const std::vector<unsigned char>& Buffer)
{
    const struct iphdr* iph = reinterpret_cast<const struct iphdr*>(Buffer.data() + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    const struct udphdr* udph = reinterpret_cast<const struct udphdr*>(Buffer.data() + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);

    logfile << "\n\n***********************UDP Packet*************************\n";

    printIpHeader(Buffer);

    logfile << "\nUDP Header\n" << std::dec;;
    logfile << "   |-Source Port      : " << ntohs(udph->source) << "\n";
    logfile << "   |-Destination Port : " << ntohs(udph->dest) << "\n";
    logfile << "   |-UDP Length       : " << ntohs(udph->len) << "\n";
    logfile << "   |-UDP Checksum     : " << ntohs(udph->check) << "\n";

    logfile << "\n";
    logfile << "IP Header\n";
    printData(Buffer, iphdrlen);

    logfile << "UDP Header\n";
    printData(Buffer, sizeof(struct udphdr));

    logfile << "Data Payload\n";
    // Move the pointer ahead and reduce the size of the string
    printData(Buffer, Buffer.size() - header_size);

    logfile << "\n###########################################################";
}

void PacketLogger::printIcmpPacket(const std::vector<unsigned char>& Buffer)
{
    const struct iphdr* iph = reinterpret_cast<const struct iphdr*>(Buffer.data() + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    const struct icmphdr* icmph = reinterpret_cast<const struct icmphdr*>(Buffer.data() + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);

    logfile << "\n\n***********************ICMP Packet*************************\n";
    printIpHeader(Buffer);

    logfile << "\n";
    logfile << "ICMP Header\n";
    logfile << "   |-Type : " << static_cast<unsigned int>(icmph->type) << std::dec;;

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
    printData(Buffer, iphdrlen);

    logfile << "ICMP Header\n";
    printData(Buffer, sizeof(struct icmphdr));

    logfile << "Data Payload\n";
    // Move the pointer ahead and reduce the size of the string
    printData(Buffer, Buffer.size() - header_size);

    logfile << "\n###########################################################";
}

void PacketLogger::printData(const std::vector<unsigned char>& data, int size)
{
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 16 == 0)   // if one line of hex printing is complete...
        {
            logfile << "         ";
            for (int j = i - 16; j < i; j++)
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

        if (i == size - 1)  // print the last spaces
        {
            for (int j = 0; j < 15 - i % 16; j++)
            {
                logfile << "   ";  // extra spaces
            }

            logfile << "         ";

            for (int j = i - i % 16; j <= i; j++)
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
#include <iostream>
#include <fcntl.h>
#include <linux/input.h>

#include "../include/snifferlib.h"
#include "../include/MainInterface.h"

using namespace NetworkInterface;

int main(){
    PacketSniffer sniffer;

    const char* inputDevice = "/dev/input/by-path/platform-i8042-serio-0-event-kbd";  // Replace with the appropriate device file (eventX)
    struct input_event ev;
    ssize_t n;

    int fd = open(inputDevice, O_RDONLY);

    if (fd == -1) {
        std::cerr << "Error opening input device\n";
        return 1;
    }

    int option;
    printHeader();
    printMenu();

    if(!sniffer.createSocket()){
        std::cerr << "Cant open soket!" << std::endl;
        return -1;
    }

    while(true){
        n = read(fd, &ev, sizeof(ev));

        if (n != sizeof(ev) || ev.type != EV_KEY && ev.value != 1)
            continue;

        option = ev.code - 2;

        switch (option) {
            case Sniffer_default:{
                sniffer.start(Start_type::SNIFF_DEFAULT);
                break;
            }
            case Sniffer_IP: {
                sniffer.stop();
                std::string ipenter;
                std::cout << "Enter ip: ";
                std::cin >> ipenter;
                deleteLine(1);
                sniffer.setCurrentIP(ipenter);
                sniffer.start(Start_type::SNIFF_BY_IP);
                break;
            }
            case Sniffer_PC:
                sniffer.setCurrentIP(getIP());
                sniffer.start(Start_type::SNIFF_BY_IP);
                break;
            case Stop_Sniff:
                sniffer.stop();
                break;
            case Network_Info:
                printNetworkInfo();
                n = read(fd, &ev, sizeof(ev));
                deleteLine(4);
                break;
            case Exit_Sniff:
                sniffer.stop();
                std::cout << "Exit...";
                return 0;
        }
    }
}
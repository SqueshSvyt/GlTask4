#include<iostream>

#include "snifferlib.h"
#include "NetworkInterface.h"

using namespace NetworkInterface;

enum Menu_choose{
    Start,
    Stop,
    SnifferdefaultIP,
    SniffergatewayIP,
    Exit
};

int main(){
    PacketSniffer sniffer;
    int option;
    std::cout << "***********************PACKETSNIFFER***********************" << std::endl;
    std::cout << "Choose option you want to do!" << std::endl;
    std::cout << "Start (Enter 0): " << std::endl <<
                 "Stop: (Enter 1): " << std::endl <<
                 "SnifferdefaultIP: (Enter 2)" << std::endl <<
                 "SniffergatewayIP: (Enter 3)" << std::endl <<
                 "Exit: (Enter 4)" << std::endl;

    while(true){
        std::cout << "Enter your option: ";
        std::cin >> option;
        std::cout << std::endl << std::endl;
        switch (option) {
            case Menu_choose::Start:{
                if(!sniffer.createSocket()){
                    std::cerr << "Cant open soket!" << std::endl;
                    return -1;
                }
                sniffer.start();
          t      break;
            }
            case Menu_choose::Stop:
                sniffer.stop();
                break;
            case Menu_choose::SnifferdefaultIP:
                sniffer.setCurrentIP(getIP());
                break;
            case Menu_choose::SniffergatewayIP:
                sniffer.setCurrentIP(getGatewayIp());
                break;
            case Menu_choose::Exit:
                std::cout << "Exit...";
                return 0;
            default:
                return 0;
        }
    }
}
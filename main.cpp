#include<iostream>

#include "snifferlib.h"

int main(){
    PacketSniffer sniffer;
    int option;
    std::cout << "***********************PACKETSNIFFER***********************" << std::endl;
    std::cout << "Choose option you want to do!" << std::endl;
    std::cout << "Start (Enter 1): \nExit: (Enter 2)" << std::endl;
    std::cout << "Choose: "; std::cin >> option; std::cout << std::endl;
    switch (option) {
        case 1:{
            if(!sniffer.createSocket()){
                std::cerr << "Cant open soket!" << std::endl;
                return -1;
            }

            sniffer.start();
            break;
        }
        case 2:
            std::cout << "Exit..." << std::endl;
            return 0;
        default:
            return 0;
    }
}
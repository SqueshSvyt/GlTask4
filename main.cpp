#include<iostream>

#include "snifferlib.h"

int main(){
    PacketSniffer sniffer;

    if(!sniffer.createSocket()){
        std::cerr << "Cant open soket!" << std::endl;
        return -1;
    }

    sniffer.startSniffing();

    return 0;
}
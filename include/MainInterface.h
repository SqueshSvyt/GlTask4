//
// Created by sviatsop on 15.11.23.
//

#ifndef SNIFERAPP_MAININTERFACE_H
#define SNIFERAPP_MAININTERFACE_H

#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <algorithm>
#include <termios.h>
#include <iomanip>

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

enum Menu_choose{
    Sniffer_default,
    Sniffer_PC,
    Sniffer_IP,
    Stop_Sniff,
    Exit_Sniff
};

namespace NetworkInterface {
    std::string getIP();
    std::string getGatewayIp();
    void printNetworkInfo();
};

int convertToOption(int n);
void printHeader();
void printMenu();
void deleteLine(int n);
void restoreInputBuffering();
void disableInputBuffering();

#endif //SNIFERAPP_MAININTERFACE_H

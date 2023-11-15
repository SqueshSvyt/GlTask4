//
// Created by sviatsop on 15.11.23.
//

#ifndef SNIFERAPP_NETWORKINTERFACE_H
#define SNIFERAPP_NETWORKINTERFACE_H

#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <arpa/inet.h>

namespace NetworkInterface {
    std::string getIP();
    std::string getGatewayIp();
};


#endif //SNIFERAPP_NETWORKINTERFACE_H

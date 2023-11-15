#include "NetworkInterface.h"

std::string NetworkInterface::getIP() {
    std::string result;
    char command[256];
    char buffer[256];

    snprintf(command, sizeof(command), "ip addr | grep -oE 'inet ([0-9]+\\.){3}[0-9]+' | cut -d ' ' -f 2");

    FILE* pipe = popen(command, "r");
    if (!pipe) {
        perror("Error opening pipe");
        exit(EXIT_FAILURE);
    }

    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        if (strncmp(buffer, "127.0.0.1", strlen("127.0.0.1")) != 0 && strncmp(buffer, "::1", strlen("::1")) != 0) {
            result += buffer;
        }
    }

    if (pclose(pipe) == -1) {
        perror("Error closing pipe");
        exit(EXIT_FAILURE);
    }

    return result;
}

std::string NetworkInterface::getGatewayIp() {
    FILE* fp = popen("ip route show | grep default | awk '{print $3}'", "r");

    if (fp == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    std::string result_ip;
    char gateway_ip[INET_ADDRSTRLEN];
    if (fgets(gateway_ip, sizeof(gateway_ip), fp) != NULL) {
        gateway_ip[strcspn(gateway_ip, "\n")] = '\0';
        result_ip = gateway_ip;
    } else {
        perror("fgets");
    }
    pclose(fp);

    return gateway_ip;
}
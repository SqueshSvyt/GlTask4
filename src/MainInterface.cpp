#include <unistd.h>
#include "../include/MainInterface.h"

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
            result[strcspn(result.c_str(), "\n")];
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


void NetworkInterface::printNetworkInfo() {
    std::cout << "*********************************Network info********************************" << std::endl;
    std::cout << "Your Ip: " << getIP();
    std::cout << "Your gatewayip: " << getGatewayIp() << std::flush << std::endl;
    std::cout << std::setw(77) << std::setfill('*') << "" << std::endl;
}

void printHeader() {
    std::cout << std::setw(77) << std::setfill('*') << "" << std::endl;
    std::cout << "*******************************PACKET SNIFFER********************************" << std::endl;
    std::cout << "Sniffed packets can be found in packet_log_file.txt" << std::endl;
}

void printMenu() {
    std::cout << std::setw(77) << std::setfill('*') << "" << std::endl;
    std::cout << "Choose an option(Press key same as number in part of the menu15):" << std::endl;
    std::cout << std::setfill(' ')  << "1. Start Default (Without connection to IP)"  << std::endl;
    std::cout << std::setfill(' ')  << "2. Start Sniffing on your current PC" << std::endl;
    std::cout << std::setfill(' ') << "3. Start Sniffing by IP" << std::endl;
    std::cout << std::setfill(' ') << "4. Stop Sniffing" << std::endl;
    std::cout << std::setfill(' ') << "5. Network info" << std::endl;
    std::cout << std::setfill(' ') << "6. Exit" << std::endl;
    std::cout << std::internal << std::setw(77) << std::setfill('*')  << "" << std::endl;
}

void deleteLine(int n){
    for (int i = 0; i < n; ++i)
        std::cout << "\x1b[A\x1b[2K";
}

void disableInputBuffering() {
    struct termios t;
    tcgetattr(STDIN_FILENO, &t);
    t.c_lflag &= ~ICANON;  // Turn off canonical mode
    t.c_lflag &= ~ECHO;    // Turn off echoing
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

void restoreInputBuffering() {
    struct termios t;
    tcgetattr(STDIN_FILENO, &t);
    t.c_lflag |= ICANON;  // Turn on canonical mode
    t.c_lflag |= ECHO;    // Turn on echoing
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
}
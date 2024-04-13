#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include "unistd.h"

#define CONFIG_FILE_PATH "/sys/kernel/firewall_config/group/ip_addresses"

uint ip_to_int(std::string ip_address) {
    uint result = 0;
    uint part = 0;
    for (char c : ip_address) {
        if (c == '.') {
            result = (result << 8) + part;
            part = 0;
        } else {
            part = part * 10 + (c - '0');
        }
    }
    result = (result << 8) + part;

    return result;
}

std::string int_to_ip(uint ip_int) {
    std::string first = std::to_string((ip_int >> 24) & 0xFF);
    std::string second = std::to_string((ip_int >> 16) & 0xFF);
    std::string third = std::to_string((ip_int >> 8) & 0xFF);
    std::string fourth = std::to_string(ip_int & 0xFF);
    return first + "." + second + "." + third + "." + fourth;
}

void add_ip_address_to_config_file(std::string ip_address) {
    std::ofstream config_file;
    config_file.open(CONFIG_FILE_PATH, std::ios_base::openmode::_S_app);
    config_file << ip_to_int(ip_address) << "\n";
    config_file.close();
}

void print_string(std::string s) {
    for (int i = 0; i < s.size(); i++) {
        std::cout << "(" << i << ", " << s[i] << ")";
    }
    std::cout << "\n";
}

void remove_ip_address_from_config_file(std::string ip_address) {
    std::ofstream config_file;
    config_file.open(CONFIG_FILE_PATH);
    config_file << "D";
    config_file << ip_to_int(ip_address);
    config_file.close();
}

void print_usage() {
    std::cout << "Usage:\n";
    std::cout << std::left << std::setw(25) << "fw -l";
    std::cout << "list all ip addresses blocked by the firewall\n";
    std::cout << std::left << std::setw(25) << "fw -a ip_address";
    std::cout << "adds the provided ip address to the firewall\n";
    std::cout << std::left << std::setw(25) << "fw -d ip_address";
    std::cout << "removes the provided ip address from the firewall\n";
}

bool validate_octet(const std::string& octet) {
    if (octet[0] == '0' && octet.size() > 1) return false;
    if (octet.size() > 3) return false;
    if (std::stoi(octet) > 255 || std::stoi(octet) < 0) return false;
    return true;
}

bool validate_ip_address(std::string ip_address) {
    std::string cur;
    int num_dots = 0;
    for (char c : ip_address) {
        if (c == '.') {
            num_dots++;
            if (!validate_octet(cur)) return false;
            cur = "";
        }
        else {
            cur.push_back(c);
        }
    }
    if (!validate_octet(cur)) return false;
    if (num_dots != 3) return false;
    return true;
}

int main(int argc, char* argv[]) {
    uid_t uid = getuid();
    if (argc == 2 && argv[1] == std::string("-l")) {
        std::ifstream config_file;
        config_file.open(CONFIG_FILE_PATH);
        std::string line;
        while (getline(config_file, line)) {
            std::cout << int_to_ip(static_cast<uint>(std::stoi(line))) << std::endl;
        }
        config_file.close();
    }
    else if (argc == 3 && argv[1] == std::string("-a")) {
        if (uid != 0) {
            std::cout << "Root permissions are required to run this command.\n";
            return 0;
        }
        std::string ip_address = argv[2];
        bool is_valid = validate_ip_address(ip_address);
        if (!is_valid) {
            std::cout << "Invalid IPv4 IP Address\n";
        } else {
            add_ip_address_to_config_file(ip_address);
        }
    } else if (argc == 3 && argv[1] == std::string("-d")) {
        if (uid != 0) {
            std::cout << "Root permissions are required to run this command.\n";
        }
        std::string ip_address = argv[2];
        bool is_valid = validate_ip_address(ip_address);
        if (!is_valid) {
            std::cout << "Invalid IPv4 IP Address";
        } else { 
            remove_ip_address_from_config_file(ip_address);
        }
    } else {
        print_usage();
    }

    return 0;
}




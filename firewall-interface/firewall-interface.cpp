#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include "unistd.h"

#define CONFIG_FILE_PATH "/.firewallconfig"

void add_ip_address_to_config_file(std::string ip_address) {
    std::ofstream config_file;
    config_file.open(CONFIG_FILE_PATH, std::ios_base::openmode::_S_app);
    config_file << ip_address << "\n";
    config_file.close();
}

void print_string(std::string s) {
    for (int i = 0; i < s.size(); i++) {
        std::cout << "(" << i << ", " << s[i] << ")";
    }
    std::cout << "\n";
}

void remove_ip_address_from_config_file(std::string ip_address) {
    std::string temp_file_name = std::string(CONFIG_FILE_PATH) + "_temp";

    std::ifstream config_file;
    config_file.open(CONFIG_FILE_PATH);

    std::ofstream temp_file(temp_file_name);

    std::string line;
    while (getline(config_file, line)) {
        if (line != ip_address) {
            temp_file << line << "\n";
        } 
    }

    config_file.close();
    temp_file.close();

    remove(CONFIG_FILE_PATH);
    rename(temp_file_name.c_str(), CONFIG_FILE_PATH);
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
            std::cout << line << std::endl;
        }
        config_file.close();
    }
    else if (argc == 3 && argv[1] == std::string("-a")) {
        if (uid != 0) {
            std::cout << "Root permissions are required to run this command.\n";
        }
        std::string ip_address = argv[2];
        bool is_valid = validate_ip_address(ip_address);
        if (!is_valid) {
            std::cout << "Invalid IPv4 IP Address";
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




#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>

#define CONFIG_FILE_PATH "/.firewallconfig"

void add_line_to_config_file(std::string ip_address) {
    std::ofstream config_file;
    config_file.open(CONFIG_FILE_PATH, std::ios_base::openmode::_S_app);
    config_file << ip_address << "\n";
    config_file.close();
}

void print_usage() {
    std::cout << "Usage:\n";
    std::cout << std::left << std::setw(25) << "fw -s";
    std::cout << "show all ip addresses blocked by the firewall\n";
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
    if (argc == 2 && argv[1] == std::string("-s")) {
        std::ifstream config_file;
        config_file.open(CONFIG_FILE_PATH);
        std::string line;
        while (getline(config_file, line)) {
            std::cout << line << std::endl;
        }
    }
    else if (argc == 3 && argv[1] == std::string("-a")) {
        std::string ip_address = argv[2];
        bool is_valid = validate_ip_address(ip_address);
        std::cout << (is_valid ? "valid" : "invalid") << std::endl;
        // std::cout << "adding ip address " << ip_address << std::endl;
    } else if (argc == 3 && argv[1] == std::string("-d")) {
        std::string ip_address = argv[2];
        std::cout << "deleting ip address " << ip_address << std::endl;
    } else {
        print_usage();
    }

    return 0;
}




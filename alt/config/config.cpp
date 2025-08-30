#include "config/config.h"
#include "utils.h"

#include <iostream>
#include <fstream>
#include <sstream>

std::optional<Config> parseConfig(std::string filename)
{
    Config config;

    std::ifstream file(filename);

    if (!file) {
        std::cerr << "Failed to open file.\n";
        return std::nullopt;
    }
    
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key, value;

        iss >> key >> value;

        if(key == "virtualnic")
        {
            bool virtualnic = value == "true" ? true : false;
            config.virtualNIC = virtualnic;
        }
        else if(key == "myip")
        {
            uint32_t ip = parse_ipv4(value);
            config.myIP = ip;
        }
        else if(key == "routerip")
        {
            uint32_t ip = parse_ipv4(value);
            config.routerIP = ip;
        }
        else if(key == "subnet")
        {
            uint32_t subnet = std::stoi(value);
            config.subnetDecimal = subnet;
        }
        else
        {
            printf("Invalid line in config file: %s\n", line.c_str());
            return std::nullopt;
        }
    }

    file.close();

    return config;
}

void printConfig(Config config)
{
    printf("Virtual NIC: %s\n", config.virtualNIC ? "true" : "false");
    printf("My IP: %s\n", ip_to_string(config.myIP).c_str());
    printf("Router IP: %s\n", ip_to_string(config.routerIP).c_str());
    printf("Subnet: /%i\n", config.subnetDecimal);
}

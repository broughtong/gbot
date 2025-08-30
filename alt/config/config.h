#pragma once

#include <stdint.h>
#include <string>
#include <optional>

struct Config
{
    bool virtualNIC;
    uint32_t myIP;
    uint32_t routerIP;
    uint32_t subnetDecimal; //ie "24"
};

std::optional<Config> parseConfig(std::string filename);
void printConfig(Config config);

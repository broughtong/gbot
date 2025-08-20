#pragma once
#include <iostream>
#include <sstream>
#include <cstdint>
#include <string>

uint32_t parse_ipv4(const std::string& ip_str)
{
    std::istringstream iss(ip_str);
    uint32_t a, b, c, d;
    char dot;

    if (!(iss >> a >> dot >> b >> dot >> c >> dot >> d)) {
        throw std::runtime_error("Invalid IP format");
    }

    return (a << 24) | (b << 16) | (c << 8) | d;
}

std::string ip_to_string(uint32_t ip)
{
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

#include "config/config.h"
#include "dpdk/dpdk.h"
#include "sentinel.hpp"
#include "rx.hpp"
#include "tx.hpp"

#include <rte_eal.h>
#include <iostream>

#include <print>
#include <chrono>
#include <thread>

int main(int argc, char **argv)
{
    std::print("Reading config file...\n");

    std::optional<Config> configOptional = parseConfig("config.txt");
    if(!configOptional.has_value())
    {
        std::print("Unable to read config file\n");
        return -1;
    }
    Config config = *configOptional;
    printConfig(config);
    
    printf("Starting DPDK...\n");
    dpdkOpenDevice(config);

    // check cores are enabled
    if (!rte_lcore_is_enabled(1) || !rte_lcore_is_enabled(2)) {
        printf("Chosen core is not enabled\n");
        return -1;
    }

    std::print("Starting RX thread\n");
    rte_eal_remote_launch(rx_thread, NULL, 1);
    std::print("Starting TX thread\n");
    rte_eal_remote_launch(tx_thread, NULL, 2);

    // Wait for all remote lcores to finish (they won't in this infinite loop example)
    rte_eal_wait_lcore(1);
    rte_eal_wait_lcore(2);
    
    dpdkCloseDevice(config);
    
    return 0;
}


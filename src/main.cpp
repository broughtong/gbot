#include "config/config.h"
#include "dpdk/dpdk.h"
#include <rte_eal.h>
#include <iostream>


int main(int argc, char **argv)
{
    printf("Reading config file...\n");

    std::optional<Config> configOptional = parseConfig("config.txt");
    if(!configOptional.has_value())
    {
        return -1;
    }
    Config config = *configOptional;
    printConfig(config);

    printf("Starting DPDK...\n");
    dpdkInitEAL(config, argc, argv);

    
    




   // std::cout << "DPDK initialized on " << ret << " cores\n";
    
    return 0;
}


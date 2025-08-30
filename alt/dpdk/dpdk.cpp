#include "dpdk/dpdk.h"
#include "utils.h"
#include <cstdlib>

bool dpdkOpenDevice(Config config)
{
    std::vector<std::string> args;
    args.push_back("myProgram");

    if(config.virtualNIC)
    {
        args.push_back("--vdev=net_tap,iface=gbot");
        args.push_back("--no-huge");
    }

    std::vector<char*> argv;
    for (auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }

    int argc = static_cast<int>(argv.size());

    rte_eal_init(argc, argv.data());
    rte_vect_set_max_simd_bitwidth(RTE_VECT_SIMD_512);

    if (rte_eth_dev_count_avail() == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet devices found\n");

    // Create mbuf pool
    // N = 2047 (2**n - 1)
    const int N = 1024;
    const int cache = 256;

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
        N, cache, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());

    
    // Configure NIC
    struct rte_eth_conf port_conf = {
        .rxmode = { .mq_mode = RTE_ETH_MQ_RX_NONE },
        .txmode = { .mq_mode = RTE_ETH_MQ_TX_NONE },
    };

    int ret = rte_eth_dev_configure(PORT_ID, 1, 1, &port_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to configure device\n");

    // RX queue
    ret = rte_eth_rx_queue_setup(PORT_ID, 0, RX_RING_SIZE,
                                 rte_eth_dev_socket_id(PORT_ID),
                                 NULL, mbuf_pool);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "RX queue setup failed\n");

    // TX queue
    ret = rte_eth_tx_queue_setup(PORT_ID, 0, TX_RING_SIZE,
                                 rte_eth_dev_socket_id(PORT_ID),
                                 NULL);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "TX queue setup failed\n");

    ret = rte_eth_dev_start(PORT_ID);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to start port\n");

    rte_eth_promiscuous_enable(PORT_ID);

    if(config.virtualNIC)
    {
        std::string ipConfig("ip addr add ");
        ipConfig += ip_to_string(config.myIP);
        ipConfig += "/";
        ipConfig += std::to_string(config.subnetDecimal);
        ipConfig += " dev gbot";

        if(system(ipConfig.c_str()) != 0) //"ip addr add 192.168.1.2/24 dev gbot") != 0)
        {
            rte_exit(EXIT_FAILURE, "Failed to set ip\n");
        }
        if(system("ip link set gbot up") != 0)
        {
            rte_exit(EXIT_FAILURE, "Failed to up link\n");
        }
    }

    return true;
}

void dpdkCloseDevice(Config config)
{
    rte_eth_dev_stop(PORT_ID);
    rte_eth_dev_close(PORT_ID);
    rte_eal_cleanup();
}

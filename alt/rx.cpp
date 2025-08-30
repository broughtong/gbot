#include "rx.hpp"
#include <rte_eal.h>
#include <rte_lcore.h>
#include <unistd.h> // for sleep()
#include <print>

constexpr int burstSize = 32;

int rx_thread(void *arg) {
    
    unsigned lcore_id = rte_lcore_id();
    const char *name = "RX";

    std::print("Worker {} running on core {}\n", name, lcore_id);

    struct rte_mbuf *bufs[BURST_SIZE];

    while(1)
    {
        // Rare exit: sentinel is true
        if (force_quit.load(std::memory_order_relaxed) [[unlikely]])
            break;

        // Poll a burst of packets (hot path)
        const uint16_t nb_rx = rte_eth_rx_burst(port_id, queue_id, bufs, burstSize);
        if (nb_rx == 0) [[unlikely]]
            continue;
        
        // Process packets
        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *pkt = bufs[i];

            // Example: print packet length
            printf("Received packet of length %u\n", rte_pktmbuf_pkt_len(pkt));

            // Free the mbuf when done
            rte_pktmbuf_free(pkt);
        }

    }

    return 0;
}

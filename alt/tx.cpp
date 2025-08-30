#include "tx.hpp"
#include <rte_eal.h>
#include <rte_lcore.h>
#include <print>

int tx_thread(void *arg)
{
    unsigned lcore_id = rte_lcore_id();
    const char *name = "TX";

    std::print("Worker {} running on core {}\n", name, lcore_id);

    while (1) {
        // Rare exit: sentinel is true
        if (force_quit.load(std::memory_order_relaxed) [[unlikely]])
            break;

    }

    return 0;
}

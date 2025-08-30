#pragma once

#include "config/config.h"

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_ring.h>

#include <vector>

#define PORT_ID 0
#define RX_RING_SIZE  1024
#define TX_RING_SIZE  1024

static struct rte_mempool *mbuf_pool;

bool dpdkOpenDevice(Config config);
void dpdkCloseDevice(Config config);

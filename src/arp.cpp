#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <rte_byteorder.h>

#include <map>

std::unordered_map<uint32_t, char[6]> arpCache;

void addRecord(uint32_t addr, char[6] mac)
{
    arpCache[addr] = mac;
}

char[6] getRecord(uint32_t addr)
{
    auto it = map.find(addr);
    if (it != map.end())
    {
        return it->second;
    }
    return 0;
}

void handleIncomingArp(struct rte_mbuf* mbuf)
{
    struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
        return;

    struct rte_arp_hdr* arp_hdr = (struct rte_arp_hdr*)(eth_hdr + 1);
    
    if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
        char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &arp_hdr->arp_data.arp_sip, sender_ip, sizeof(sender_ip));
        inet_ntop(AF_INET, &arp_hdr->arp_data.arp_tip, target_ip, sizeof(target_ip));

        printf("ARP Request: Who has %s? Tell %s\n", target_ip, sender_ip);
    } else if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &arp_hdr->arp_data.arp_sip, sender_ip, sizeof(sender_ip));
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
            arp_hdr->arp_data.arp_sha.addr_bytes[0],
            arp_hdr->arp_data.arp_sha.addr_bytes[1],
            arp_hdr->arp_data.arp_sha.addr_bytes[2],
            arp_hdr->arp_data.arp_sha.addr_bytes[3],
            arp_hdr->arp_data.arp_sha.addr_bytes[4],
            arp_hdr->arp_data.arp_sha.addr_bytes[5]);
        
        printf("ARP Reply: %s is at %s\n", sender_ip, mac);
    }
}

void send_arp_request(uint16_t port_id, struct rte_mempool *mbuf_pool,
                      struct ether_addr *src_mac, uint32_t src_ip,
                      uint32_t gateway_ip) {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) return;

    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    struct arp_hdr *arp = (struct arp_hdr *)(eth + 1);

    mbuf->data_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
    mbuf->pkt_len = mbuf->data_len;

    // Ethernet header
    ether_addr_copy(src_mac, &eth->s_addr);
    ether_addr_copy(&ether_broadcast, &eth->d_addr);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

    // ARP request
    arp->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
    arp->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    arp->arp_hln = ETHER_ADDR_LEN;
    arp->arp_pln = 4;
    arp->arp_op  = rte_cpu_to_be_16(ARP_OP_REQUEST);

    ether_addr_copy(src_mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = src_ip;
    memset(&arp->arp_data.arp_tha, 0, ETHER_ADDR_LEN);
    arp->arp_data.arp_tip = gateway_ip;

    rte_eth_tx_burst(port_id, 0, &mbuf, 1);
}

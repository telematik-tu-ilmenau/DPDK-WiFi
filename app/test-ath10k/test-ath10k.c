#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_timer.h>
#include <rte_hexdump.h>
#include <rte_ether.h>
#include <rte_ethdev.h>

#include <rte_ieee80211dev.h>
#include <rte_wifi.h>

#define NUM_MBUFS 16383
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 64

#define RX_RING_SIZE 512
#define TX_RING_SIZE 512

int port_init(uint8_t port, struct rte_mempool* mbuf_pool) {
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));

    port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
    port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
    port_conf.rxmode.max_rx_pkt_len = 2000;
    port_conf.rxmode.jumbo_frame = 1;
    port_conf.rxmode.hw_ip_checksum = 1;
    port_conf.rxmode.hw_strip_crc = 1;

    const uint16_t rx_rings = 1, tx_rings = 1;
    int            retval;
    uint16_t       q;

    if(port >= rte_eth_dev_count())
        return -1;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if(retval != 0) {
        // LOG(ERROR) << "configure of port " << port << " failed";
        return retval;
    }

    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for(q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL,
                                        mbuf_pool);
        if(retval < 0) {
            return retval;
        }
    }

    /* Allocate and set up 1 TX queue per Ethernet port. */
    for(q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
        if(retval < 0) {
            return retval;
        }
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if(retval < 0) {
        // LOG(ERROR) << "start of port " << port << " failed";
        return retval;
    }

    /* Display the port MAC address. */
    struct ether_addr addr;
    rte_eth_macaddr_get(port, &addr);

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           "\n",
           (unsigned)port, addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
           addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    return 0;
}


void initPorts(struct rte_mempool* mbuf_pool) {
	uint8_t nb_ports = rte_eth_dev_count();
    uint8_t portid;

    /* Initialize all ports. */
    for(portid = 0; portid < nb_ports; portid++)
        if(port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %d\n", portid);

   
    /* init 802.11 part */
    for(int portId = 0; portId < nb_ports; ++portId) {
        if(!rte_wifi_is_wifi_port(portId)) {
            continue;
        }
        int resRTEDevInit = rte_ieee80211_dev_init(portId);
        assert(resRTEDevInit == 0);
        rte_wifi_enable_polling(portId);
    }

}

void wifi_mgmt_callback(unsigned port_id, struct rte_mbuf *m,  uint64_t mactime, void *userdata) {
	// handle adding peers and parsing beacons here

	// --> int rte_wifi_add_peer(unsigned port_id, struct rte_wifi_peer *peer);

	// --> int rte_wifi_delete_peer(unsigned port_id, struct rte_wifi_peer *peer);
}

int main(int argc, char** argv) {
	int ret = rte_eal_init(argc, argv);
	if(ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	rte_wifi_subsystem_init();

	struct rte_mempool* mbuf_pool =
		rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, 4096, SOCKET_ID_ANY);

	initPorts(mbuf_pool);

	rte_wifi_mgmt_callback_register(wifi_mgmt_callback, NULL);

	uint8_t nb_ports = rte_eth_dev_count();
	while(1) {
		for(uint8_t i = 0; i < nb_ports; ++i) {
			struct rte_mbuf rx_pkts[16];

			// rx some frames
			uint16_t nb_pkts = rte_eth_rx_burst(i, 0, &rx_pkts, 16);

			if(rte_wifi_is_wifi_port(i)) {
				// do something with wifi frames
			} else {
				// do something with ethernet frames
			}

			// send frames out again
			rte_eth_tx_burst(i, 0, &rx_pkts, 16);
		}
	}

	return 0;
}

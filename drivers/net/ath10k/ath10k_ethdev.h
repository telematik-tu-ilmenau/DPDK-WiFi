#ifndef ATH10K_ETHDEV
#define ATH10K_ETHDEV

#include <rte_ethdev.h>
#include <rte_cfg80211.h>

#define WIPHY_IDX_INVALID   -1


/*
 * IS_ENABLED(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y' or 'm',
 * 0 otherwise.
 */
#define IS_ENABLED(option) __or(IS_BUILTIN(option), IS_MODULE(option))

extern const struct ieee80211_ops eth_ath10k_80211_ops;

struct ieee80211_hw;
struct ieee80211_ops;


int eth_ath10k_rx_queue_setup(struct rte_eth_dev *dev,
        uint16_t queue_idx,
        uint16_t nb_desc,
        unsigned int socket_id,
        const struct rte_eth_rxconf *rx_conf,
        struct rte_mempool *mp);

int eth_ath10k_tx_queue_setup(struct rte_eth_dev *dev,
        uint16_t queue_idx,
        uint16_t nb_desc,
        unsigned int socket_id,
        const struct rte_eth_txconf *tx_conf);

uint16_t eth_ath10k_rx(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
uint16_t eth_ath10k_tx(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
uint16_t eth_ath10k_prepare_tx(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);

#endif /* ATH10K_ETHDEV */

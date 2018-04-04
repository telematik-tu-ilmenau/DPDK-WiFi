#ifndef RTE_WIFI_H
#define RTE_WIFI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_mbuf.h>
#include <rte_ieee80211dev.h>

typedef void (*rte_wifi_mgmt_cb)(unsigned port_id, struct rte_mbuf *m,  uint64_t mactime, void *userdata);

void rte_wifi_subsystem_init();

void rte_wifi_subsystem_free();

int rte_wifi_mgmt_callback_register(rte_wifi_mgmt_cb cb, void *userdata);

int rte_wifi_mgmt_callback_unregister(rte_wifi_mgmt_cb cb);

bool rte_wifi_is_wifi_port(int port_id);

int rte_wifi_add_peer(unsigned port_id, struct rte_wifi_peer *peer);

int rte_wifi_delete_peer(unsigned port_id, struct rte_wifi_peer *peer);

void rte_wifi_enable_polling(unsigned port_id);

void rte_wifi_disable_polling(unsigned port_id);

int rte_wifi_offset_tsf(unsigned port_id, int64_t timestamp_adj);

int rte_wifi_adj_tsf(unsigned port_id, uint64_t timestamp_orig);

void rte_wifi_set_bssid(unsigned port_id, uint8_t *bssid);

int rte_wifi_send_addba(unsigned port_id, const uint8_t *mac, uint32_t tid, uint32_t buf_size);
int rte_wifi_addba_set_resp(unsigned port_id, const uint8_t *mac, uint32_t tid, uint32_t status);

int rte_wifi_vdev_up(unsigned port_id);
int rte_wifi_vdev_down(unsigned port_id);

int rte_wifi_get_pdev_temperature(unsigned port_id);

/* called from applications */
void rte_wifi_mgmt_tx(unsigned port_id, struct rte_mbuf *m);

/* called from drivers */
void rte_wifi_mgmt_rx(unsigned port_id, struct rte_mbuf *m, uint64_t mactime);

#ifdef __cplusplus
}
#endif

#endif // RTE_WIFI_H

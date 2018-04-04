#include "rte_wifi.h"
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <pthread.h>
#include <stdbool.h>
#include <rte_byteorder.h>
#include <assert.h>
#include <stdio.h>
#include <sys/queue.h>
#include <rte_ieee80211_i.h>
#include <stdint.h>

static pthread_t wifi_thread = {0};
static pthread_mutex_t wifi_mutex;
static pthread_cond_t wifi_cond;
static int last_aid = 0;
static struct rte_mempool *wifi_mpool;
static bool should_stop = false;

struct wifi_mgmt_rx_entry {
    unsigned port_id;
    struct rte_mbuf *mbuf;
    uint64_t mactime;
    TAILQ_ENTRY(wifi_mgmt_rx_entry) entries;
};
static TAILQ_HEAD(wifi_mgmt_rx_head, wifi_mgmt_rx_entry) wifi_mgmt_rx_list = TAILQ_HEAD_INITIALIZER(wifi_mgmt_rx_list);

struct wifi_mgmt_subscriber_entry {
    rte_wifi_mgmt_cb cb;
    void *userdata;
    TAILQ_ENTRY(wifi_mgmt_subscriber_entry) entries;
};
static TAILQ_HEAD(wifi_mgmt_subscriber_head, wifi_mgmt_subscriber_entry) wifi_mgmt_subscriber_list = TAILQ_HEAD_INITIALIZER(wifi_mgmt_subscriber_list);

static void *wifi_thread_fn(void * arg);

void rte_wifi_subsystem_init() {
    char thread_name[RTE_MAX_THREAD_NAME_LEN];
    int ret;
    pthread_kill(&wifi_thread);

    pthread_mutex_init(&wifi_mutex, NULL);
    pthread_cond_init(&wifi_cond, NULL);
    TAILQ_INIT(&wifi_mgmt_rx_list);
    TAILQ_INIT(&wifi_mgmt_subscriber_list);
    pthread_create(&wifi_thread, NULL, wifi_thread_fn, NULL);

    wifi_mpool = rte_pktmbuf_pool_create("MBUF_POOL_WIFI", 4096, 128, 0, 4096, SOCKET_ID_ANY);
    assert(wifi_mpool != NULL);

    /* Set thread_name for aid in debugging. */
    snprintf(thread_name, RTE_MAX_THREAD_NAME_LEN,
    "eal-wifi-thread");
    ret = rte_thread_setname(wifi_thread, thread_name);
    if (ret != 0) {
        RTE_LOG(DEBUG, EAL,
        "Failed to set thread name for wifi handling\n");
    }
}

void rte_wifi_subsystem_free() {
    should_stop = true;
    pthread_mutex_lock(&wifi_mutex);
    while(!TAILQ_EMPTY(&wifi_mgmt_rx_list)) {
        struct wifi_mgmt_rx_entry *rx_arg = TAILQ_LAST(&wifi_mgmt_rx_list, wifi_mgmt_rx_head);
        TAILQ_REMOVE(&wifi_mgmt_rx_list, rx_arg, entries);
        rte_pktmbuf_free(rx_arg->mbuf);
        rte_free(rx_arg);
    }
    while(!TAILQ_EMPTY(&wifi_mgmt_rx_list)) {
        struct wifi_mgmt_subscriber_entry *sub_arg = TAILQ_LAST(&wifi_mgmt_rx_list, wifi_mgmt_rx_head);
        rte_wifi_mgmt_callback_unregister(sub_arg->cb);
    }
    if(wifi_mpool != NULL) {
        rte_mempool_free(wifi_mpool);
        wifi_mpool = NULL;
    }
    pthread_mutex_unlock(&wifi_mutex);
}

static struct wifi_mgmt_subscriber_entry * rte_wifi_mgmt_callback_find(rte_wifi_mgmt_cb cb) {
    struct wifi_mgmt_subscriber_entry *entry = NULL;
    struct wifi_mgmt_subscriber_entry *np;
    TAILQ_FOREACH(np, &wifi_mgmt_subscriber_list, entries) {
        if(np->cb == cb)
            entry = np;
    }
    return entry;
}

int rte_wifi_mgmt_callback_register(rte_wifi_mgmt_cb cb, void *userdata) {
    assert(rte_wifi_mgmt_callback_find(cb) == NULL);
    struct wifi_mgmt_subscriber_entry *arg = rte_malloc(NULL, sizeof(struct wifi_mgmt_subscriber_entry), 0);
    assert(arg != NULL);
    arg->cb = cb;
    arg->userdata = userdata;
    TAILQ_INSERT_TAIL(&wifi_mgmt_subscriber_list, arg, entries);
}

int rte_wifi_mgmt_callback_unregister(rte_wifi_mgmt_cb cb) {
    struct wifi_mgmt_subscriber_entry *entry = rte_wifi_mgmt_callback_find(cb);
    assert(entry != NULL);
    TAILQ_REMOVE(&wifi_mgmt_subscriber_list, entry, entries);
    rte_free(entry);
}

bool rte_wifi_is_wifi_port(int port_id) {
    return rte_eth_dev_get_wifi_ctx(port_id) != NULL;
}


/* only lock ring insert with mutex and may sleep on mutex,
 * no lock for multiple mgmt msgs which are processed
 */

static void *wifi_thread_fn(void * arg) {
    while(!should_stop) {
        pthread_mutex_lock(&wifi_mutex);
        if(TAILQ_EMPTY(&wifi_mgmt_rx_list)) {
            struct timeval now;
            struct timespec ts;
            gettimeofday(&now, NULL);

            ts.tv_sec = now.tv_sec + 1;
            ts.tv_nsec = now.tv_usec * 1000;
            if(pthread_cond_timedwait(&wifi_cond, &wifi_mutex, &ts) != 0) {
                pthread_mutex_unlock(&wifi_mutex);
                continue;
            }
        }

        struct wifi_mgmt_rx_entry *rx_arg = TAILQ_LAST(&wifi_mgmt_rx_list, wifi_mgmt_rx_head);
        TAILQ_REMOVE(&wifi_mgmt_rx_list, rx_arg, entries);
        pthread_mutex_unlock(&wifi_mutex);

        struct wifi_mgmt_subscriber_entry *np;
        TAILQ_FOREACH(np, &wifi_mgmt_subscriber_list, entries) {
            np->cb(rx_arg->port_id, rx_arg->mbuf, rx_arg->mactime, np->userdata);
        }
        
        rte_pktmbuf_free(rx_arg->mbuf);
        rte_free(rx_arg);
    }

    return NULL;
}

void rte_wifi_mgmt_rx(unsigned port_id, struct rte_mbuf *mbuf, uint64_t mactime) {
    pthread_mutex_lock(&wifi_mutex);

    struct wifi_mgmt_rx_entry *arg = rte_malloc(NULL, sizeof(struct wifi_mgmt_rx_entry), 0);
    arg->port_id = port_id;
    arg->mbuf = rte_pktmbuf_alloc(wifi_mpool);
    assert(arg->mbuf != NULL);
    if(arg->mbuf == NULL) {
    rte_pktmbuf_free(mbuf);
        goto err_free;
    }
    rte_pktmbuf_append(arg->mbuf, rte_pktmbuf_pkt_len(mbuf));
    rte_memcpy(rte_pktmbuf_mtod(arg->mbuf, void*), rte_pktmbuf_mtod(mbuf, void*),
               rte_pktmbuf_data_len(mbuf));
    arg->mactime = mactime;
    TAILQ_INSERT_TAIL(&wifi_mgmt_rx_list, arg, entries);

err_free:
    rte_pktmbuf_free(mbuf);
    pthread_cond_signal(&wifi_cond);
    pthread_mutex_unlock(&wifi_mutex);
}

int rte_wifi_add_peer(unsigned port_id, struct rte_wifi_peer *peer) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return -1;
    return ctx->ops->add_peer(ctx, peer);
}

int rte_wifi_delete_peer(unsigned port_id, struct rte_wifi_peer *peer) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return -1;
    return ctx->ops->delete_peer(ctx, peer);
}

void rte_wifi_enable_polling(unsigned port_id) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return;
    ctx->ops->enable_polling(ctx);
}

void rte_wifi_disable_polling(unsigned port_id) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return;
    ctx->ops->disable_polling(ctx);
}

int rte_wifi_offset_tsf(unsigned port_id, int64_t timestamp_adj) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return -1;
    return ctx->ops->offset_tsf(ctx, timestamp_adj);
}

int rte_wifi_adj_tsf(unsigned port_id, uint64_t timestamp_orig) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return -1;
    ctx->ops->set_tsf(ctx, timestamp_orig);
    return 0;
    
    // struct ieee80211_sub_if_data *sdata = ctx->sdata;
    // struct ieee80211_if_ibss *ifibss = &sdata->u.ibss;
    // struct ieee80211_mgmt* beacon = ifibss->presp->head;
    // if(!beacon)
    //     return -1;
    // beacon->u.beacon.timestamp = rte_cpu_to_le_64(timestamp_orig);
    // // beacon->u.beacon.beacon_int = 0xabcd;

    // return 0;
}

void rte_wifi_set_bssid(unsigned port_id, uint8_t *bssid) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return;
    struct ieee80211_sub_if_data *sdata = ctx->sdata;
    struct ieee80211_if_ibss *ifibss = &sdata->u.ibss;
    struct ieee80211_mgmt* beacon = ifibss->presp;
    if(!beacon)
        return;

    memcpy(beacon->bssid, bssid, 6);
}

int rte_wifi_vdev_up(unsigned port_id) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return -1;
    return ctx->ops->up(ctx);
}

int rte_wifi_vdev_down(unsigned port_id) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return -1;
    return ctx->ops->down(ctx);
}

int rte_wifi_send_addba(unsigned port_id, const uint8_t *mac, uint32_t tid, uint32_t buf_size) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return -1;
    return ctx->ops->send_addba(ctx, mac, tid, buf_size);
}

int rte_wifi_addba_set_resp(unsigned port_id, const uint8_t *mac, uint32_t tid, uint32_t status) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return -1;
    return ctx->ops->addba_set_resp(ctx, mac, tid, status);
}

int rte_wifi_get_pdev_temperature(unsigned port_id) {
    struct rte_wireless_ctx* ctx = rte_eth_dev_get_wifi_ctx(port_id);
    if(ctx == NULL)
        return -1;
    return ctx->ops->get_pdev_temperature(ctx);
}

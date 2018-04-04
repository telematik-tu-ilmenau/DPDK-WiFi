#ifndef _RTE_IEEE80211DEV_H_
#define _RTE_IEEE80211DEV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "rte_cfg80211.h"

#include "rte_general.h"

struct ieee80211_ops;
struct ieee80211_hw;
struct ieee80211_vif;
struct ieee80211_sub_if_data;

struct cfg80211_internal_bss {
    // struct list_head list;
    LIST_ENTRY(cfg80211_internal_bss) pointers;
    struct list_head hidden_list;
    // struct rb_node rbn;
    uint64_t ts_boottime;
    unsigned long ts;
    unsigned long refcount;
    atomic_t hold;

    /* time at the start of the reception of the first octet of the
     * timestamp field of the last beacon/probe received for this BSS.
     * The time is the TSF of the BSS specified by %parent_bssid.
     */
    uint64_t parent_tsf;

    /* the BSS according to which %parent_tsf is set. This is set to
     * the BSS that the interface that requested the scan was connected to
     * when the beacon/probe was received.
     */
    uint8_t parent_bssid[ETH_ALEN] __aligned(2);

    /* must be last because of priv member */
    struct cfg80211_bss pub;
};

struct cfg80211_registered_device {
    const struct cfg80211_ops *ops;
//    struct list_head list;
//
//    /* rfkill support */
//    struct rfkill_ops rfkill_ops;
//    struct rfkill *rfkill;
//    struct work_struct rfkill_sync;
//
//    /* ISO / IEC 3166 alpha2 for which this device is receiving
//     * country IEs on, this can help disregard country IEs from APs
//     * on the same alpha2 quickly. The alpha2 may differ from
//     * cfg80211_regdomain's alpha2 when an intersection has occurred.
//     * If the AP is reconfigured this can also be used to tell us if
//     * the country on the country IE changed. */
//    char country_ie_alpha2[2];
//
//    /*
//     * the driver requests the regulatory core to set this regulatory
//     * domain as the wiphy's. Only used for %REGULATORY_WIPHY_SELF_MANAGED
//     * devices using the regulatory_set_wiphy_regd() API
//     */
//    const struct ieee80211_regdomain *requested_regd;
//
//    /* If a Country IE has been received this tells us the environment
//     * which its telling us its in. This defaults to ENVIRON_ANY */
//    enum environment_cap env;
//
//    /* wiphy index, internal only */
    int wiphy_idx;
//
//    /* protected by RTNL */
//    int devlist_generation, wdev_id;
//    int opencount;
//    wait_queue_head_t dev_wait;
//
//    struct list_head beacon_registrations;
//    spinlock_t beacon_registrations_lock;
//
//    struct list_head mlme_unreg;
//    spinlock_t mlme_unreg_lock;
//    struct work_struct mlme_unreg_wk;
//
//    /* protected by RTNL only */
//    int num_running_ifaces;
//    int num_running_monitor_ifaces;
//
//    /* BSSes/scanning */
//    spinlock_t bss_lock;
//    struct list_head bss_list;
    LIST_HEAD(cfg80211_internal_bss_list, cfg80211_internal_bss) bss_list;
//    struct rb_root bss_tree;
//    u32 bss_generation;
//    u32 bss_entries;
//    struct cfg80211_scan_request *scan_req; /* protected by RTNL */
//    struct sk_buff *scan_msg;
//    struct list_head sched_scan_req_list;
//    unsigned long suspend_at;
//    struct work_struct scan_done_wk;
//
//    struct genl_info *cur_cmd_info;
//
//    struct work_struct conn_work;
//    struct work_struct event_work;
//
//    struct delayed_work dfs_update_channels_wk;
//
//    /* netlink port which started critical protocol (0 means not started) */
//    u32 crit_proto_nlportid;
//
//    struct cfg80211_coalesce *coalesce;
//
//    struct work_struct destroy_work;
//    struct work_struct sched_scan_stop_wk;
//    struct work_struct sched_scan_res_wk;
//
//    struct cfg80211_chan_def radar_chandef;
//    struct work_struct propagate_radar_detect_wk;
//
//    struct cfg80211_chan_def cac_done_chandef;
//    struct work_struct propagate_cac_done_wk;

    /* must be last because of the way we do wiphy_priv(),
     * and it should at least be aligned to NETDEV_ALIGN = 32 */
    struct wiphy wiphy __attribute__((aligned(32)));
};

struct rte_wifi_peer {
    struct ether_addr addr;
    int peer_aid;
};

// TODO: move to librte_wifi later
struct rte_wireless_ops {
    int (*add_peer)(struct rte_wireless_ctx*, struct rte_wifi_peer* peer);
    int (*delete_peer)(struct rte_wireless_ctx*, struct rte_wifi_peer* peer);
    void (*enable_polling)(struct rte_wireless_ctx*);
    void (*disable_polling)(struct rte_wireless_ctx*);
    int (*set_tsf)(struct rte_wireless_ctx*, uint64_t tsf);
    int (*offset_tsf)(struct rte_wireless_ctx*, int64_t tsfadj);
    int (*up)(struct rte_wireless_ctx*);
    int (*down)(struct rte_wireless_ctx*);
    int (*send_addba)(struct rte_wireless_ctx* ctx, const uint8_t *mac, uint32_t tid, uint32_t buf_size);
    int (*addba_set_resp)(struct rte_wireless_ctx* ctx, const uint8_t *mac, uint32_t tid, uint32_t status);
    int (*get_pdev_temperature)(struct rte_wireless_ctx* ctx);
};

/**
 * struct rte_wireless_ctx; - wireless device / device state
 **/

struct rte_wireless_ctx {
    struct ieee80211_local* local;
    struct ieee80211_ops *dev_ops;
    struct ieee80211_hw* hw;
    struct ieee80211_vif* vif;
    struct ieee80211_sub_if_data* sdata;
    struct rte_wireless_ops *ops;
};

struct ieee80211_vif* get_vif_template(struct rte_wireless_ctx* wdev, uint8_t rte_ethdev_port_id);
struct ieee80211_chanctx_conf* get_ctx_template(void);
struct ieee80211_hw* ieee80211_alloc_hw_nm(size_t priv_data_len, const struct ieee80211_ops *ops, const char *requested_name);
void get_mac_addr(struct rte_wireless_ctx* wdev, uint8_t rte_ethdev_port_id, struct vif_params* params);

/**
 * Initializes a new wireless device with our default channel configuration
 *
 * @param port_id
 *  The port identifier of the device to initialize.
 * @return
 *  0 on success, indifferent on error
 */
int rte_ieee80211_dev_init(uint8_t port_id);

int test_bcn_stuff(uint8_t port_id);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_IEEE80211DEV_H_ */

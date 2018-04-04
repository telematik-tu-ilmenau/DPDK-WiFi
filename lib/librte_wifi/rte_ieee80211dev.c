
#include "rte_ieee80211dev.h"
#include "rte_ieee80211_i.h"
#include "rte_cfg80211.h"
#include "rte_ieee80211_radiotap.h"
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <rte_malloc.h>
#include "rte_general.h"
#include "netdevice.h"

static const struct ieee80211_txrx_stypes
ieee80211_default_mgmt_stypes[NUM_NL80211_IFTYPES] = {
    [NL80211_IFTYPE_ADHOC] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
            BIT(IEEE80211_STYPE_AUTH >> 4) |
            BIT(IEEE80211_STYPE_DEAUTH >> 4) |
            BIT(IEEE80211_STYPE_PROBE_REQ >> 4),
    },
    [NL80211_IFTYPE_STATION] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
            BIT(IEEE80211_STYPE_PROBE_REQ >> 4),
    },
    [NL80211_IFTYPE_AP] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
            BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
            BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
            BIT(IEEE80211_STYPE_DISASSOC >> 4) |
            BIT(IEEE80211_STYPE_AUTH >> 4) |
            BIT(IEEE80211_STYPE_DEAUTH >> 4) |
            BIT(IEEE80211_STYPE_ACTION >> 4),
    },
    [NL80211_IFTYPE_AP_VLAN] = {
        /* copy AP */
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
            BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
            BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
            BIT(IEEE80211_STYPE_DISASSOC >> 4) |
            BIT(IEEE80211_STYPE_AUTH >> 4) |
            BIT(IEEE80211_STYPE_DEAUTH >> 4) |
            BIT(IEEE80211_STYPE_ACTION >> 4),
    },
    [NL80211_IFTYPE_P2P_CLIENT] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
            BIT(IEEE80211_STYPE_PROBE_REQ >> 4),
    },
    [NL80211_IFTYPE_P2P_GO] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
            BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
            BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
            BIT(IEEE80211_STYPE_DISASSOC >> 4) |
            BIT(IEEE80211_STYPE_AUTH >> 4) |
            BIT(IEEE80211_STYPE_DEAUTH >> 4) |
            BIT(IEEE80211_STYPE_ACTION >> 4),
    },
    [NL80211_IFTYPE_MESH_POINT] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
            BIT(IEEE80211_STYPE_AUTH >> 4) |
            BIT(IEEE80211_STYPE_DEAUTH >> 4),
    },
    [NL80211_IFTYPE_P2P_DEVICE] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
            BIT(IEEE80211_STYPE_PROBE_REQ >> 4),
    },
};

static const struct ieee80211_ht_cap mac80211_ht_capa_mod_mask = {
    .ampdu_params_info = IEEE80211_HT_AMPDU_PARM_FACTOR |
                 IEEE80211_HT_AMPDU_PARM_DENSITY,

    .cap_info = rte_cpu_to_le_16(IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
                IEEE80211_HT_CAP_MAX_AMSDU |
                IEEE80211_HT_CAP_SGI_20 |
                IEEE80211_HT_CAP_SGI_40 |
                IEEE80211_HT_CAP_LDPC_CODING |
                IEEE80211_HT_CAP_40MHZ_INTOLERANT),
    .mcs = {
        .rx_mask = { 0xff, 0xff, 0xff, 0xff, 0xff,
                 0xff, 0xff, 0xff, 0xff, 0xff, },
    },
};

static const struct ieee80211_vht_cap mac80211_vht_capa_mod_mask = {
    .vht_cap_info =
            rte_cpu_to_le_32(IEEE80211_VHT_CAP_RXLDPC |
                IEEE80211_VHT_CAP_SHORT_GI_80 |
                IEEE80211_VHT_CAP_SHORT_GI_160 |
                IEEE80211_VHT_CAP_RXSTBC_1 |
                IEEE80211_VHT_CAP_RXSTBC_2 |
                IEEE80211_VHT_CAP_RXSTBC_3 |
                IEEE80211_VHT_CAP_RXSTBC_4 |
                IEEE80211_VHT_CAP_TXSTBC |
                IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE |
                IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE |
                IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN |
                IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN |
                IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK),
    .supp_mcs = {
        .rx_mcs_map = rte_cpu_to_le_16(~0),
        .tx_mcs_map = rte_cpu_to_le_16(~0),
    },
};

struct wiphy *wiphy_new_nm(const struct cfg80211_ops *ops, int sizeof_priv, const char *requested_name)
{
    static atomic_t wiphy_counter;
    atomic_set(&wiphy_counter, 0);

    struct cfg80211_registered_device *rdev;
    int alloc_size;

//    WARN_ON(ops->add_key && (!ops->del_key || !ops->set_default_key));
//    WARN_ON(ops->auth && (!ops->assoc || !ops->deauth || !ops->disassoc));
//    WARN_ON(ops->connect && !ops->disconnect);
//    WARN_ON(ops->join_ibss && !ops->leave_ibss);
//    WARN_ON(ops->add_virtual_intf && !ops->del_virtual_intf);
//    WARN_ON(ops->add_station && !ops->del_station);
//    WARN_ON(ops->add_mpath && !ops->del_mpath);
//    WARN_ON(ops->join_mesh && !ops->leave_mesh);
//    WARN_ON(ops->start_p2p_device && !ops->stop_p2p_device);
//    WARN_ON(ops->start_ap && !ops->stop_ap);
//    WARN_ON(ops->join_ocb && !ops->leave_ocb);
//    WARN_ON(ops->suspend && !ops->resume);
//    WARN_ON(ops->sched_scan_start && !ops->sched_scan_stop);
//    WARN_ON(ops->remain_on_channel && !ops->cancel_remain_on_channel);
//    WARN_ON(ops->tdls_channel_switch && !ops->tdls_cancel_channel_switch);
//    WARN_ON(ops->add_tx_ts && !ops->del_tx_ts);

    alloc_size = sizeof(*rdev) + sizeof_priv;

    // rdev = kzalloc(alloc_size, GFP_KERNEL);
    rdev = rte_zmalloc("cfg80211_registered_device", alloc_size, 0);
    if (!rdev)
        return NULL;

    rdev->ops = ops;

    rdev->wiphy_idx = atomic_inc_return(&wiphy_counter);

    if (unlikely(rdev->wiphy_idx < 0)) {
        /* ugh, wrapped! */
        atomic_dec(&wiphy_counter);
        rte_free(rdev);
        return NULL;
    }

    /* atomic_inc_return makes it start at 1, make it start at 0 */
    rdev->wiphy_idx--;

    /* give it a proper name */
//    if (requested_name && requested_name[0]) {
//        int rv = -1;
//
//        // rtnl_lock();
//        // rv = cfg80211_dev_check_name(rdev, requested_name);
//
//        if (rv < 0) {
//            // rtnl_unlock();
//            goto use_default_name;
//        }
//
//        rv = dev_set_name(&rdev->wiphy.dev, "%s", requested_name);
//        // rtnl_unlock();
//        if (rv)
//            goto use_default_name;
//    } else {
//use_default_name:
//        /* NOTE:  This is *probably* safe w/out holding rtnl because of
//         * the restrictions on phy names.  Probably this call could
//         * fail if some other part of the kernel (re)named a device
//         * phyX.  But, might should add some locking and check return
//         * value, and use a different name if this one exists?
//         */
//        dev_set_name(&rdev->wiphy.dev, PHY_NAME "%d", rdev->wiphy_idx);
//    }
    rdev->wiphy.dev.init_name = NULL;

//    INIT_LIST_HEAD(&rdev->wiphy.wdev_list);
//    INIT_LIST_HEAD(&rdev->beacon_registrations);
//    spin_lock_init(&rdev->beacon_registrations_lock);
//    spin_lock_init(&rdev->bss_lock);
//    INIT_LIST_HEAD(&rdev->bss_list);
//    INIT_LIST_HEAD(&rdev->sched_scan_req_list);
//    INIT_WORK(&rdev->scan_done_wk, __cfg80211_scan_done);
//    INIT_LIST_HEAD(&rdev->mlme_unreg);
//    spin_lock_init(&rdev->mlme_unreg_lock);
//    INIT_WORK(&rdev->mlme_unreg_wk, cfg80211_mlme_unreg_wk);
//    INIT_DELAYED_WORK(&rdev->dfs_update_channels_wk,
//              cfg80211_dfs_channels_update_work);
//#ifdef CONFIG_CFG80211_WEXT
//    rdev->wiphy.wext = &cfg80211_wext_handler;
//#endif

//    device_initialize(&rdev->wiphy.dev);
//    rdev->wiphy.dev.class = &ieee80211_class;
    rdev->wiphy.dev.platform_data = rdev;
//    device_enable_async_suspend(&rdev->wiphy.dev);

//    INIT_WORK(&rdev->destroy_work, cfg80211_destroy_iface_wk);
//    INIT_WORK(&rdev->sched_scan_stop_wk, cfg80211_sched_scan_stop_wk);
//    INIT_WORK(&rdev->sched_scan_res_wk, cfg80211_sched_scan_results_wk);
//    INIT_WORK(&rdev->propagate_radar_detect_wk,
//          cfg80211_propagate_radar_detect_wk);
//    INIT_WORK(&rdev->propagate_cac_done_wk, cfg80211_propagate_cac_done_wk);

//#ifdef CONFIG_CFG80211_DEFAULT_PS
//    rdev->wiphy.flags |= WIPHY_FLAG_PS_ON_BY_DEFAULT;
//#endif

//    wiphy_net_set(&rdev->wiphy, &init_net);

//    rdev->rfkill_ops.set_block = cfg80211_rfkill_set_block;
//    rdev->rfkill = rfkill_alloc(dev_name(&rdev->wiphy.dev),
//                   &rdev->wiphy.dev, RFKILL_TYPE_WLAN,
//                   &rdev->rfkill_ops, rdev);

//    if (!rdev->rfkill) {
//        kfree(rdev);
//        return NULL;
//    }

//    INIT_WORK(&rdev->rfkill_sync, cfg80211_rfkill_sync_work);
//    INIT_WORK(&rdev->conn_work, cfg80211_conn_work);
//    INIT_WORK(&rdev->event_work, cfg80211_event_work);

//    init_waitqueue_head(&rdev->dev_wait);

    /*
     * Initialize wiphy parameters to IEEE 802.11 MIB default values.
     * Fragmentation and RTS threshold are disabled by default with the
     * special -1 value.
     */
    rdev->wiphy.retry_short = 7;
    rdev->wiphy.retry_long = 4;
    rdev->wiphy.frag_threshold = (uint32_t) -1;
    rdev->wiphy.rts_threshold = (uint32_t) -1;
    rdev->wiphy.coverage_class = 0;

    rdev->wiphy.max_num_csa_counters = 1;

    rdev->wiphy.max_sched_scan_plans = 1;
    rdev->wiphy.max_sched_scan_plan_interval = U32_MAX;

    return &rdev->wiphy;
}

int sta_info_init(struct ieee80211_local *local)
{
// // FIXME leave out hashtable for now
//    int err;
//
//    err = rhltable_init(&local->sta_hash, &sta_rht_params);
//    if (err)
//        return err;

    // spin_lock_init(&local->tim_lock);
    // mutex_init(&local->sta_mtx);
    LIST_INIT(&local->sta_list);

//    setup_timer(&local->sta_cleanup, sta_info_cleanup, (unsigned long)local); // TODO check relevance of that timer
    return 0;
}

struct ieee80211_hw* ieee80211_alloc_hw_nm(size_t priv_data_len, const struct ieee80211_ops *ops, const char *requested_name)
{
    struct ieee80211_local *local;
    int priv_size, i;
    struct wiphy *wiphy;
    bool use_chanctx;

//    if (WARN_ON(!ops->tx || !ops->start || !ops->stop || !ops->config ||
//            !ops->add_interface || !ops->remove_interface ||
//            !ops->configure_filter))
//        return NULL;

//    if (WARN_ON(ops->sta_state && (ops->sta_add || ops->sta_remove)))
//        return NULL;

    /* check all or no channel context operations exist */
//    i = !!ops->add_chanctx + !!ops->remove_chanctx +
//        !!ops->change_chanctx + !!ops->assign_vif_chanctx +
//        !!ops->unassign_vif_chanctx;
//    if (WARN_ON(i != 0 && i != 5))
//        return NULL;
//    use_chanctx = i == 5;

    use_chanctx = 1;

    /* Ensure 32-byte alignment of our private data and hw private data.
     * We use the wiphy priv data for both our ieee80211_local and for
     * the driver's private data
     *
     * In memory it'll be like this:
     *
     * +-------------------------+
     * | struct wiphy       |
     * +-------------------------+
     * | struct ieee80211_local  |
     * +-------------------------+
     * | driver's private data   |
     * +-------------------------+
     *
     */
    priv_size = ALIGN(sizeof(*local), 32) + priv_data_len;

    wiphy = wiphy_new_nm(&mac80211_config_ops, priv_size, requested_name);

    if (!wiphy)
        return NULL;

    wiphy->mgmt_stypes = ieee80211_default_mgmt_stypes;

    wiphy->privid = mac80211_wiphy_privid;

    wiphy->flags |= WIPHY_FLAG_NETNS_OK |
            WIPHY_FLAG_4ADDR_AP |
            WIPHY_FLAG_4ADDR_STATION |
            WIPHY_FLAG_REPORTS_OBSS |
            WIPHY_FLAG_OFFCHAN_TX;

//    if (ops->remain_on_channel)
//        wiphy->flags |= WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL;

    wiphy->features |= NL80211_FEATURE_SK_TX_STATUS |
               NL80211_FEATURE_SAE |
               NL80211_FEATURE_HT_IBSS |
               NL80211_FEATURE_VIF_TXPOWER |
               NL80211_FEATURE_MAC_ON_CREATE |
               NL80211_FEATURE_USERSPACE_MPM |
               NL80211_FEATURE_FULL_AP_CLIENT_STATE;
    wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_FILS_STA);
    wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_VHT_IBSS);
//    if (!ops->hw_scan)
//        wiphy->features |= NL80211_FEATURE_LOW_PRIORITY_SCAN |
//                   NL80211_FEATURE_AP_SCAN;


//    if (!ops->set_key)
//        wiphy->flags |= WIPHY_FLAG_IBSS_RSN;

    wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_RRM);

    wiphy->bss_priv_size = sizeof(struct ieee80211_bss);

    local = wiphy_priv(wiphy);

    if (sta_info_init(local))
        goto err_free;

    local->hw.wiphy = wiphy;

    // local->hw.priv = (char *)local + ALIGN(sizeof(*local), 32);

    local->ops = ops;
    local->use_chanctx = use_chanctx;

    /* set up some defaults */
    local->hw.queues = 1;
    local->hw.max_rates = 1;
    local->hw.max_report_rates = 0;
    local->hw.max_rx_aggregation_subframes = IEEE80211_MAX_AMPDU_BUF;
    local->hw.max_tx_aggregation_subframes = IEEE80211_MAX_AMPDU_BUF;
    local->hw.offchannel_tx_hw_queue = IEEE80211_INVAL_HW_QUEUE;
    local->hw.conf.long_frame_max_tx_count = wiphy->retry_long;
    local->hw.conf.short_frame_max_tx_count = wiphy->retry_short;
    local->hw.radiotap_mcs_details = IEEE80211_RADIOTAP_MCS_HAVE_MCS |
                     IEEE80211_RADIOTAP_MCS_HAVE_GI |
                     IEEE80211_RADIOTAP_MCS_HAVE_BW;
    local->hw.radiotap_vht_details = IEEE80211_RADIOTAP_VHT_KNOWN_GI |
                     IEEE80211_RADIOTAP_VHT_KNOWN_BANDWIDTH;
    local->hw.uapsd_queues = IEEE80211_DEFAULT_UAPSD_QUEUES;
    local->hw.uapsd_max_sp_len = IEEE80211_DEFAULT_MAX_SP_LEN;
    local->user_power_level = IEEE80211_UNSET_POWER_LEVEL;
    wiphy->ht_capa_mod_mask = &mac80211_ht_capa_mod_mask;
    wiphy->vht_capa_mod_mask = &mac80211_vht_capa_mod_mask;

    local->ext_capa[7] = WLAN_EXT_CAPA8_OPMODE_NOTIF;

    wiphy->extended_capabilities = local->ext_capa;
    wiphy->extended_capabilities_mask = local->ext_capa;
    wiphy->extended_capabilities_len = ARRAY_SIZE(local->ext_capa);

    LIST_INIT(&local->interfaces);
//    INIT_LIST_HEAD(&local->mon_list);

//    __hw_addr_init(&local->mc_list);
//
//    mutex_init(&local->iflist_mtx);
//    mutex_init(&local->mtx);

//    mutex_init(&local->key_mtx);
//    spin_lock_init(&local->filter_lock);
//    spin_lock_init(&local->rx_path_lock);
//    spin_lock_init(&local->queue_stop_reason_lock);

    LIST_INIT(&local->chanctx_list);
//    mutex_init(&local->chanctx_mtx);

//    INIT_DELAYED_WORK(&local->scan_work, ieee80211_scan_work);

//    INIT_WORK(&local->restart_work, ieee80211_restart_work);

//    INIT_WORK(&local->radar_detected_work,
//          ieee80211_dfs_radar_detected_work);

//    INIT_WORK(&local->reconfig_filter, ieee80211_reconfig_filter);
//    local->smps_mode = IEEE80211_SMPS_OFF;

//    INIT_WORK(&local->dynamic_ps_enable_work,
//          ieee80211_dynamic_ps_enable_work);
//    INIT_WORK(&local->dynamic_ps_disable_work,
//          ieee80211_dynamic_ps_disable_work);
//    setup_timer(&local->dynamic_ps_timer,
//            ieee80211_dynamic_ps_timer, (unsigned long) local);

//    INIT_WORK(&local->sched_scan_stopped_work,
//          ieee80211_sched_scan_stopped_work);

//    INIT_WORK(&local->tdls_chsw_work, ieee80211_tdls_chsw_work);

//    spin_lock_init(&local->ack_status_lock);
//    idr_init(&local->ack_status_frames);

    for (i = 0; i < IEEE80211_MAX_QUEUES; i++) {
        LIST_INIT(&local->pending[i]);
        atomic_set(&local->agg_queue_stop[i], 0);
    }
//    tasklet_init(&local->tx_pending_tasklet, ieee80211_tx_pending,
//             (unsigned long)local);

//    tasklet_init(&local->tasklet,
//             ieee80211_tasklet_handler,
//             (unsigned long) local);

//    skb_queue_head_init(&local->skb_queue);
//    skb_queue_head_init(&local->skb_queue_unreliable);
//    skb_queue_head_init(&local->skb_queue_tdls_chsw);
//
//    ieee80211_alloc_led_names(local);
//
//    ieee80211_roc_setup(local);

    local->hw.radiotap_timestamp.units_pos = -1;
    local->hw.radiotap_timestamp.accuracy = -1;

    return &local->hw;
 err_free:
    // wiphy_free(wiphy); // TODO: check free of wiphy
    return NULL;
}

struct ieee80211_vif* get_vif_template(struct rte_wireless_ctx * wdev, uint8_t rte_ethdev_port_id) {
    struct ieee80211_vif *vif = rte_zmalloc("ieee80211_vif template", sizeof(struct ieee80211_vif), 0);

    wdev->dev_ops->init_vif_priv(vif, rte_eth_devices[rte_ethdev_port_id].data->dev_private);
    vif->type = NL80211_IFTYPE_MESH_POINT;
    // const char *ssid = "NFV_MESH";
    // strcpy(vif->bss_confbss_conf.ssid, ssid);
    // vif->bss_conf.ssid_len = strlen(ssid);
    return vif;
}

void complete_vif_template(struct rte_wireless_ctx * wdev, uint8_t rte_ethdev_port_id) {
    wdev->dev_ops->init_vif_priv(wdev->vif, rte_eth_devices[rte_ethdev_port_id].data->dev_private);
    wdev->vif->type = NL80211_IFTYPE_MESH_POINT;
    // const char *ssid = "NFV_MESH";
    // strcpy(wdev->vif->bss_conf.ssid, ssid);
    // wdev->vif->bss_conf.ssid_len = strlen(ssid);
    wdev->vif->bss_conf.dtim_period = 0;
    wdev->vif->bss_conf.beacon_int = 1000;
}

void get_mac_addr(struct rte_wireless_ctx * wdev, uint8_t rte_ethdev_port_id, struct vif_params* params) {
    wdev->dev_ops->get_mac_addr(params, rte_eth_devices[rte_ethdev_port_id].data->dev_private);
}

struct ieee80211_chanctx_conf* get_ctx_template() {
    struct ieee80211_chanctx_conf *ctx = rte_zmalloc("ieee80211_chanctx_conf template", sizeof(struct ieee80211_chanctx_conf), 0);

    ctx->def.chan = rte_zmalloc("ieee80211_channel template", sizeof(struct ieee80211_channel), 0);

    // {
    //     ctx->def.width = NL80211_CHAN_WIDTH_20;
    //     ctx->def.center_freq1 = 5180;
    //     ctx->def.center_freq2 = 0;
    //     ctx->def.chan->center_freq = 5180;
    // }

    /*
    {
        ctx->def.width = NL80211_CHAN_WIDTH_40;
        ctx->def.center_freq1 = 5190;
        ctx->def.center_freq2 = 0;
        ctx->def.chan->center_freq = 5180;
    }
    */

    {
         ctx->def.width = NL80211_CHAN_WIDTH_80;
         ctx->def.center_freq1 = 5210;
         ctx->def.chan->center_freq = 5180;
        // ctx->def.center_freq1 = 5775;
        // ctx->def.chan->center_freq = 5775;
    }

    ctx->def.chan->band = NL80211_BAND_5GHZ;
    ctx->def.chan->max_power = 17;
    ctx->def.chan->max_reg_power = 17;
    ctx->def.chan->max_antenna_gain = 0;

    return ctx;
}

int rte_ieee80211_dev_init(uint8_t port_id) {
    if (rte_eth_dev_get_wifi_ctx(port_id) == NULL) {
        RTE_LOG(ERR, 80211, "calling 80211 functions on non 80211 device\n");
        return -1;
    }

    struct rte_wireless_ctx * wdev = rte_eth_dev_get_wifi_ctx(port_id);

    wdev->hw = ieee80211_alloc_hw_nm(0, wdev->dev_ops, NULL);
    wdev->local = wiphy_priv(wdev->hw->wiphy);

    struct wireless_dev* new_wdev[1] = { NULL };
    struct vif_params params = { 0 };
    get_mac_addr(wdev, port_id, &params);
    params.use_4addr = true;
    ieee80211_if_add(wdev->local, "NFVMESHIF", 0, new_wdev, NL80211_IFTYPE_MESH_POINT, &params);
    wdev->sdata = netdev_priv(new_wdev[0]->netdev);
    // wdev->sdata = LIST_FIRST(&wdev->local->interfaces); // same
    // wdev->sdata = IEEE80211_WDEV_TO_SUB_IF(wdev); // that one causes trouble :(

    // wdev->vif = get_vif_template(wdev, port_id);
    wdev->vif = &wdev->sdata->vif;
    complete_vif_template(wdev, port_id);
    ether_addr_copy(wdev->vif->addr, wdev->hw->wiphy->perm_addr);
    wdev->vif->bss_conf.bssid = wdev->hw->wiphy->perm_addr;
    wdev->vif->bss_conf.txpower = 23;
    wdev->dev_ops->set_hw_ptrs(wdev->hw, rte_eth_devices[port_id].data->dev_private);

    wdev->dev_ops->mac_register(rte_eth_devices[port_id].data->dev_private);

    ieee80211_do_open(&wdev->sdata->wdev, true);

    int resAddIF = wdev->dev_ops->add_interface(wdev->hw, wdev->vif);
    if (resAddIF != 0) {
        RTE_LOG(ERR, 80211, "Cannot add interface, error code: %d\n", resAddIF);
        return -1;
    }

    wdev->vif->chanctx_conf = get_ctx_template();
    int resAssignCtx = wdev->dev_ops->assign_vif_chanctx(wdev->hw, wdev->vif, wdev->vif->chanctx_conf);
    if (resAssignCtx != 0) {
        RTE_LOG(ERR, 80211, "Cannot add ctx to vif, error code: %d\n", resAssignCtx);
        return -1;
    }

    struct cfg80211_bss cbss = {0};

    // TODO add basic rates
    cbss.beacon_interval = 1000;
    cbss.channel = wdev->vif->chanctx_conf->def.chan;
    // rte_memcpy(cbss.bssid, wdev->vif->bss_conf.ssid, ETH_ALEN);
    // strcpy(wdev->sdata->u.ibss.ssid, wdev->vif->bss_conf.ssid);
    // wdev->sdata->u.ibss.ssid_len = (uint8_t) strlen(wdev->vif->bss_conf.ssid);
    cbss.capability = 0x2;
    ieee80211_prep_connection(wdev->sdata, &cbss, false, false);
    // wdev->sdata->u.ibss.basic_rates = 0x10101;
    // wdev->sdata->u.ibss.chandef = wdev->vif->chanctx_conf->def;
    // ieee80211_sta_create_ibss(wdev->sdata);

    wdev->vif->bss_conf.enable_beacon = false;
    wdev->sdata->flags |= IEEE80211_SDATA_IN_DRIVER;


    int flags = BSS_CHANGED_BEACON;
    flags |= BSS_CHANGED_BASIC_RATES;
    flags |= BSS_CHANGED_BEACON;
    flags |= BSS_CHANGED_BEACON_INFO;
    flags |= BSS_CHANGED_BEACON_INT;
    flags |= BSS_CHANGED_HT;
    // flags |= BSS_CHANGED_SSID;
    flags |= BSS_CHANGED_ERP_SLOT;
    flags |= BSS_CHANGED_ERP_PREAMBLE;
    flags |= BSS_CHANGED_ERP_CTS_PROT;
    wdev->dev_ops->bss_info_changed(wdev->hw, wdev->vif, &wdev->vif->bss_conf, flags);

    printf("Enable beaconing");
    wdev->vif->bss_conf.enable_beacon = true;
    flags = BSS_CHANGED_BEACON;
    flags |= BSS_CHANGED_BEACON_ENABLED;
    wdev->dev_ops->bss_info_changed(wdev->hw, wdev->vif, &wdev->vif->bss_conf, flags);
    printf("Enable beaconing finished");
    return 0;
}

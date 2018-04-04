/* Main file of the driver. */

#include <stdbool.h>
#include <unistd.h>

#include "ath10k_ethdev.h"

#include <rte_pci.h>
#include <rte_ethdev_pci.h>
#include <rte_ethdev.h>

#include "base/pci.h"
#include "base/ath10k_osdep.h"
#include "base/core.h"
#include "base/mac.h"
#include "base/hw.h"
#include "base/wmi-ops.h"
#include "base/dma.h"
#include "base/taskqueue.h"

#include <rte_mac80211.h>
#include <rte_ieee80211.h>
#include <rte_ieee80211dev.h>
#include <rte_ieee80211_i.h>
#include <rte_ieee80211_radiotap.h>

#include <rte_ether.h>
#include <rte_mbuf.h>

#include <sys/queue.h>

#include <rte_vdev.h>

#define PCI_VENDOR_ID_ATHEROS	0x168c

/* The supported vendor IDs. */
static const struct rte_pci_id pci_id_ath10k_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_ATHEROS, QCA988X_2_0_DEVICE_ID) }, /* PCI-E QCA988X V2 */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_ATHEROS, QCA6164_2_1_DEVICE_ID) }, /* PCI-E QCA6164 V2.1 */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_ATHEROS, QCA6174_2_1_DEVICE_ID) }, /* PCI-E QCA6174 V2.1 */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_ATHEROS, QCA99X0_2_0_DEVICE_ID) }, /* PCI-E QCA99X0 V2 */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_ATHEROS, QCA9888_2_0_DEVICE_ID) }, /* PCI-E QCA9888 V2 */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_ATHEROS, QCA9984_1_0_DEVICE_ID) }, /* PCI-E QCA9984 V1 */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_ATHEROS, QCA9377_1_0_DEVICE_ID) }, /* PCI-E QCA9377 V1 */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_ATHEROS, QCA9887_1_0_DEVICE_ID) }, /* PCI-E QCA9887 */
	{ }
};

static int eth_ath10k_dev_init(struct rte_eth_dev *dev);
static int eth_ath10k_dev_uninit(struct rte_eth_dev *dev);

static int __ath10k_set_antenna(struct ath10k *ar, u32 tx_ant, u32 rx_ant);

static int eth_ath10k_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
		sizeof(struct ath10k_adapter), eth_ath10k_dev_init);
}

static int eth_ath10k_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, eth_ath10k_dev_uninit);
}

/* Structure with information about the PMD driver. */
static struct rte_pci_driver rte_ath10k_pmd = {
	.id_table = pci_id_ath10k_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = eth_ath10k_pci_probe,
	.remove = eth_ath10k_pci_remove
};

static void eth_ath10k_infos_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info) {
	struct ath10k_hw *hw = ATH10K_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	dev_info->min_rx_bufsize = 256; /* See BSIZE field of RCTL register. */
	dev_info->max_rx_pktlen = 0x2412; // em_get_max_pktlen(hw);
	dev_info->max_mac_addrs = hw->mac.rar_entry_count; // <- this is the Recieve Address Register count
	// see e1000_defines.h for explanation

	dev_info->max_rx_queues = 1;
	dev_info->max_tx_queues = 1;

	dev_info->rx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = ATH10K_MAX_RING_DESC,
			.nb_min = ATH10K_MIN_RING_DESC,
			.nb_align = ATH10K_RXD_ALIGN,
	};

	dev_info->tx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = ATH10K_MAX_RING_DESC,
			.nb_min = ATH10K_MIN_RING_DESC,
			.nb_align = ATH10K_TXD_ALIGN,
	};

	dev_info->speed_capa = ETH_LINK_SPEED_10M_HD | ETH_LINK_SPEED_10M |
		ETH_LINK_SPEED_100M_HD | ETH_LINK_SPEED_100M |
		ETH_LINK_SPEED_1G;

	dev_info->pci_dev = RTE_DEV_TO_PCI(dev->device);
}

static int eth_ath10k_configure(struct rte_eth_dev *dev)
{
	/*
	   struct e1000_interrupt *intr =
	   E1000_DEV_PRIVATE_TO_INTR(dev->data->dev_private);

	   PMD_INIT_FUNC_TRACE();
	   intr->flags |= E1000_FLAG_NEED_LINK_UPDATE;
	   PMD_INIT_FUNC_TRACE();
	   */
	return 0;
}

int eth_ath10k_rx_queue_setup(struct rte_eth_dev *dev,
		uint16_t queue_idx,
		uint16_t nb_desc,
		unsigned int socket_id,
		const struct rte_eth_rxconf *rx_conf,
		struct rte_mempool *mp) {
    RTE_LOG(DEBUG, PMD, "DRIVER: Setting up rx queue.\n");
    assert(queue_idx == 0);

    struct ath10k_adapter* adapter = ATH10K_DEV_PRIVATE(dev->data->dev_private);
    struct ath10k_htt* htt = &adapter->ar->htt;
    int ret;

    dev->data->rx_queues[queue_idx] = htt; // we may need a pointer to htt only

    return 0;
}

int eth_ath10k_tx_queue_setup(struct rte_eth_dev *dev,
		uint16_t queue_idx,
		uint16_t nb_desc,
		unsigned int socket_id,
		const struct rte_eth_txconf *tx_conf) {
    RTE_LOG(DEBUG, PMD, "DRIVER: Setting up tx queue.\n");
    assert(queue_idx == 0);

    struct ath10k_adapter* adapter = ATH10K_DEV_PRIVATE(dev->data->dev_private);
    struct ath10k_htt* htt = &adapter->ar->htt;
    int ret;

    struct ath10k_txq *txq;

    if ((txq = rte_zmalloc("ethdev TX queue", sizeof(*txq), RTE_CACHE_LINE_SIZE)) == NULL)
        return -ENOMEM;

    txq->htt = &adapter->ar->htt;

    dev->data->tx_queues[queue_idx] = txq;
	return 0;
}

static int eth_ath10k_link_update(struct rte_eth_dev *dev, int wait_to_complete) {
	return 0;
}

///**************/
///* Regulatory */
///**************/
//
//static int ath10k_update_channel_list(struct ath10k *ar)
//{
//    struct ieee80211_hw *hw = ar->hw;
//    struct ieee80211_supported_band **bands;
//    enum nl80211_band band;
//    struct ieee80211_channel *channel;
//    struct wmi_scan_chan_list_arg arg = {0};
//    struct wmi_channel_arg *ch;
//    bool passive;
//    int len;
//    int ret;
//    int i;
//
//    // lockdep_assert_held(&ar->conf_lock);
//
//    bands = hw->wiphy->bands;
//    for (band = 0; band < NUM_NL80211_BANDS; band++) {
//        if (!bands[band])
//            continue;
//
//        for (i = 0; i < bands[band]->n_channels; i++) {
//            if (bands[band]->channels[i].flags &
//                IEEE80211_CHAN_DISABLED)
//                continue;
//
//            arg.n_channels++;
//        }
//    }
//
//    len = sizeof(struct wmi_channel_arg) * arg.n_channels;
//    arg.channels = kzalloc(len, GFP_KERNEL);
//    if (!arg.channels)
//        return -ENOMEM;
//
//    ch = arg.channels;
//    for (band = 0; band < NUM_NL80211_BANDS; band++) {
//        if (!bands[band])
//            continue;
//
//        for (i = 0; i < bands[band]->n_channels; i++) {
//            channel = &bands[band]->channels[i];
//
//            if (channel->flags & IEEE80211_CHAN_DISABLED)
//                continue;
//
//            ch->allow_ht = true;
//
//            /* FIXME: when should we really allow VHT? */
//            ch->allow_vht = true;
//
//            ch->allow_ibss =
//                !(channel->flags & IEEE80211_CHAN_NO_IR);
//
//            ch->ht40plus =
//                !(channel->flags & IEEE80211_CHAN_NO_HT40PLUS);
//
//            ch->chan_radar =
//                !!(channel->flags & IEEE80211_CHAN_RADAR);
//
//            passive = channel->flags & IEEE80211_CHAN_NO_IR;
//            ch->passive = passive;
//
//            ch->freq = channel->center_freq;
//            ch->band_center_freq1 = channel->center_freq;
//            ch->min_power = 0;
//            ch->max_power = channel->max_power * 2;
//            ch->max_reg_power = channel->max_reg_power * 2;
//            ch->max_antenna_gain = channel->max_antenna_gain * 2;
//            ch->reg_class_id = 0; /* FIXME */
//
//            /* FIXME: why use only legacy modes, why not any
//             * HT/VHT modes? Would that even make any
//             * difference? */
//            if (channel->band == NL80211_BAND_2GHZ)
//                ch->mode = MODE_11G;
//            else
//                ch->mode = MODE_11A;
//
//            if (WARN_ON_ONCE(ch->mode == MODE_UNKNOWN))
//                continue;
//
//            ath10k_dbg(ar, ATH10K_DBG_WMI,
//                   "mac channel [%zd/%d] freq %d maxpower %d regpower %d antenna %d mode %d\n",
//                    ch - arg.channels, arg.n_channels,
//                   ch->freq, ch->max_power, ch->max_reg_power,
//                   ch->max_antenna_gain, ch->mode);
//
//            ch++;
//        }
//    }
//
//    ret = ath10k_wmi_scan_chan_list(ar, &arg);
//    kfree(arg.channels);
//
//    return ret;
//}
//
//static enum wmi_dfs_region
//ath10k_mac_get_dfs_region(enum nl80211_dfs_regions dfs_region)
//{
//    switch (dfs_region) {
//    case NL80211_DFS_UNSET:
//        return WMI_UNINIT_DFS_DOMAIN;
//    case NL80211_DFS_FCC:
//        return WMI_FCC_DFS_DOMAIN;
//    case NL80211_DFS_ETSI:
//        return WMI_ETSI_DFS_DOMAIN;
//    case NL80211_DFS_JP:
//        return WMI_MKK4_DFS_DOMAIN;
//    }
//    return WMI_UNINIT_DFS_DOMAIN;
//}
//
//static void ath10k_regd_update(struct ath10k *ar)
//{
//    struct reg_dmn_pair_mapping *regpair;
//    int ret;
//    enum wmi_dfs_region wmi_dfs_reg;
//    enum nl80211_dfs_regions nl_dfs_reg;
//
//    // lockdep_assert_held(&ar->conf_lock);
//
//    ret = ath10k_update_channel_list(ar);
//    if (ret)
//        ath10k_warn(ar, "failed to update channel list: %d\n", ret);
//
//    regpair = ar->ath_common.regulatory.regpair;
//
//    if (IS_ENABLED(CONFIG_ATH10K_DFS_CERTIFIED) && ar->dfs_detector) {
//        nl_dfs_reg = ar->dfs_detector->region;
//        wmi_dfs_reg = ath10k_mac_get_dfs_region(nl_dfs_reg);
//    } else {
//        wmi_dfs_reg = WMI_UNINIT_DFS_DOMAIN;
//    }
//
//    /* Target allows setting up per-band regdomain but ath_common provides
//     * a combined one only */
//    ret = ath10k_wmi_pdev_set_regdomain(ar,
//                        regpair->reg_domain,
//                        regpair->reg_domain, /* 2ghz */
//                        regpair->reg_domain, /* 5ghz */
//                        regpair->reg_2ghz_ctl,
//                        regpair->reg_5ghz_ctl,
//                        wmi_dfs_reg);
//    if (ret)
//        ath10k_warn(ar, "failed to set pdev regdomain: %d\n", ret);
//}
//
//static void ath10k_reg_notifier(struct wiphy *wiphy,
//                struct regulatory_request *request)
//{
//    struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
//    struct ath10k *ar = hw->priv;
//    bool result;
//
//    ath_reg_notifier_apply(wiphy, request, &ar->ath_common.regulatory);
//
//    if (IS_ENABLED(CONFIG_ATH10K_DFS_CERTIFIED) && ar->dfs_detector) {
//        ath10k_dbg(ar, ATH10K_DBG_REGULATORY, "dfs region 0x%x\n",
//               request->dfs_region);
//        result = ar->dfs_detector->set_dfs_domain(ar->dfs_detector,
//                              request->dfs_region);
//        if (!result)
//            ath10k_warn(ar, "DFS region 0x%X not supported, will trigger radar for every pulse\n",
//                    request->dfs_region);
//    }
//
//    // rte_spinlock_lock(&ar->conf_lock);
//    if (ar->state == ATH10K_STATE_ON)
//        ath10k_regd_update(ar);
//    // rte_spinlock_unlock(&ar->conf_lock);

//  if (ar->phy_capability & WHAL_WLAN_11A_CAPABILITY)
//       ath10k_mac_update_channel_list(ar,
//                          ar->hw->wiphy->bands[NL80211_BAND_5GHZ]);
//}

static int ath10k_update_channel_list(struct ath10k *ar) {
    struct ieee80211_hw *hw = ar->hw;
    struct ieee80211_supported_band **bands;
    enum nl80211_band band;
    struct ieee80211_channel *channel;
    struct wmi_scan_chan_list_arg arg = {0};
    struct wmi_channel_arg *ch;
    bool passive;
    int len;
    int ret;
    int i;

    // lockdep_assert_held(&ar->conf_lock);

    bands = hw->wiphy->bands;
    for (band = 0; band < NUM_NL80211_BANDS; band++) {
      if (!bands[band])
          continue;

      for (i = 0; i < bands[band]->n_channels; i++) {
          if (bands[band]->channels[i].flags &
              IEEE80211_CHAN_DISABLED)
              continue;

          arg.n_channels++;
      }
    }

    len = sizeof(struct wmi_channel_arg) * arg.n_channels;
    arg.channels = kzalloc(len, GFP_KERNEL);
    if (!arg.channels)
      return -ENOMEM;

    ch = arg.channels;
    for (band = 0; band < NUM_NL80211_BANDS; band++) {
      if (!bands[band])
          continue;

      for (i = 0; i < bands[band]->n_channels; i++) {
          channel = &bands[band]->channels[i];

          if (channel->flags & IEEE80211_CHAN_DISABLED)
              continue;

          ch->allow_ht = true;

          /* FIXME: when should we really allow VHT? */
          ch->allow_vht = true;

          ch->allow_ibss =
              !(channel->flags & IEEE80211_CHAN_NO_IR);

          ch->ht40plus =
              !(channel->flags & IEEE80211_CHAN_NO_HT40PLUS);

          ch->chan_radar =
              !!(channel->flags & IEEE80211_CHAN_RADAR);

          passive = channel->flags & IEEE80211_CHAN_NO_IR;
          ch->passive = passive;

          ch->freq = channel->center_freq;
          ch->band_center_freq1 = channel->center_freq;
          ch->min_power = 0;
          ch->max_power = channel->max_power * 2;
          ch->max_reg_power = channel->max_reg_power * 2;
          ch->max_antenna_gain = channel->max_antenna_gain * 2;
          ch->reg_class_id = 0; /* FIXME */

          /* FIXME: why use only legacy modes, why not any
           * HT/VHT modes? Would that even make any
           * difference? */
          if (channel->band == NL80211_BAND_2GHZ)
              ch->mode = MODE_11G;
          else
              ch->mode = MODE_11A;

          if (WARN_ON_ONCE(ch->mode == MODE_UNKNOWN))
              continue;

          ath10k_dbg(ar, ATH10K_DBG_WMI,
                 "mac channel [%zd/%d] freq %d maxpower %d regpower %d antenna %d mode %d\n",
                  ch - arg.channels, arg.n_channels,
                 ch->freq, ch->max_power, ch->max_reg_power,
                 ch->max_antenna_gain, ch->mode);

          ch++;
      }
    }

    ret = ath10k_wmi_scan_chan_list(ar, &arg);
    kfree(arg.channels);

    return ret;
}

static void ath10k_regd_update(struct ath10k *ar) {
    struct reg_dmn_pair_mapping *regpair;
    int ret;
    enum wmi_dfs_region wmi_dfs_reg;
    enum nl80211_dfs_regions nl_dfs_reg;

    // lockdep_assert_held(&ar->conf_lock);

    ret = ath10k_update_channel_list(ar);
    if(ret)
      ath10k_warn(ar, "failed to update channel list: %d\n", ret);

    regpair = ar->ath_common.regulatory.regpair;

//    if(IS_ENABLED(CONFIG_ATH10K_DFS_CERTIFIED) && ar->dfs_detector) {
//      nl_dfs_reg = ar->dfs_detector->region;
//      wmi_dfs_reg = ath10k_mac_get_dfs_region(nl_dfs_reg);
//    } else {
//      wmi_dfs_reg = WMI_UNINIT_DFS_DOMAIN;
//    }

    wmi_dfs_reg = WMI_UNINIT_DFS_DOMAIN;

    /* Target allows setting up per-band regdomain but ath_common provides
    * a combined one only */
    ret = ath10k_wmi_pdev_set_regdomain(ar,
                      regpair->reg_domain,
                      regpair->reg_domain, /* 2ghz */
                      regpair->reg_domain, /* 5ghz */
                      regpair->reg_2ghz_ctl,
                      regpair->reg_5ghz_ctl,
                      wmi_dfs_reg);
    if(ret)
      ath10k_warn(ar, "failed to set pdev regdomain: %d\n", ret);
}

static int eth_ath10k_start(struct rte_eth_dev *dev) {
	// ATTENTION: The following code was stolen from mac.c. There is more in the corresponding function there
	int ret = 0;
	struct ath10k_adapter *adapter = ATH10K_DEV_PRIVATE(dev->data->dev_private);
	struct ath10k *ar = adapter->ar;
  u32 param;

  RTE_LOG(INFO, PMD, "start ath10k on port %" PRIu16 "\n", dev->data->port_id);

  /*
   * This makes sense only when restarting hw. It is harmless to call
   * unconditionally. This is necessary to make sure no HTT/WMI tx
   * commands will be submitted while restarting.
   */
  // take care of that drain_tx when restarting
  assert(ar->state != ATH10K_STATE_RESTARTING);
  // ath10k_drain_tx(ar);

	switch (ar->state) {
		case ATH10K_STATE_OFF:
			ar->state = ATH10K_STATE_ON;
			break;
		case ATH10K_STATE_RESTARTING:
			ar->state = ATH10K_STATE_RESTARTED;
			break;
		case ATH10K_STATE_ON:
		case ATH10K_STATE_RESTARTED:
		case ATH10K_STATE_WEDGED:
			RTE_LOG(WARNING, PMD, "DRIVER: got ATH10K_STATE_WEDGED in eth_ath10k_start\n");
			ret = -EINVAL;
			goto err;
		case ATH10K_STATE_UTF:
			ret = -EBUSY;
			goto err;
	}

	ret = ath10k_hif_power_up(ar);
	if (ret) {
		RTE_LOG(ERR, PMD, "Could not power up hif: %d\n", ret);
		return -1;
	}
	RTE_LOG(DEBUG, PMD, "DRIVER: hif power up complete.\n");

	rte_spinlock_lock(&ar->conf_lock);
	ret = ath10k_core_start(ar, ATH10K_FIRMWARE_MODE_NORMAL, &ar->normal_mode_fw);
	rte_spinlock_unlock(&ar->conf_lock);
	if (ret) {
		RTE_LOG(ERR, PMD, "Could not init core: %d\n", ret);
		return -1;
	}
	RTE_LOG(DEBUG, PMD, "DRIVER: core start complete.\n");

    param = ar->wmi.pdev_param->pmf_qos;
    ret = ath10k_wmi_pdev_set_param(ar, param, 1);
    if (ret) {
        ath10k_warn(ar, "failed to enable PMF QOS: %d\n", ret);
        goto err;
    }

    param = ar->wmi.pdev_param->dynamic_bw;
    ret = ath10k_wmi_pdev_set_param(ar, param, 1);
    if (ret) {
        ath10k_warn(ar, "failed to enable dynamic BW: %d\n", ret);
        goto err;
    }

    if (test_bit(WMI_SERVICE_ADAPTIVE_OCS, ar->wmi.svc_map)) {
        ret = ath10k_wmi_adaptive_qcs(ar, true);
        if (ret) {
            ath10k_warn(ar, "failed to enable adaptive qcs: %d\n", ret);
            goto err;
        }
    }

    if (test_bit(WMI_SERVICE_BURST, ar->wmi.svc_map)) {
        param = ar->wmi.pdev_param->burst_enable;
        ret = ath10k_wmi_pdev_set_param(ar, param, 0);
        if (ret) {
            ath10k_warn(ar, "failed to disable burst: %d\n", ret);
            goto err;
        }
    }

    // ?
    __ath10k_set_antenna(ar, ar->cfg_tx_chainmask, ar->cfg_rx_chainmask);

    /*
    * By default FW set ARP frames ac to voice (6). In that case ARP
    * exchange is not working properly for UAPSD enabled AP. ARP requests
    * which arrives with access category 0 are processed by network stack
    * and send back with access category 0, but FW changes access category
    * to 6. Set ARP frames access category to best effort (0) solves
    * this problem.
    */

    param = ar->wmi.pdev_param->arp_ac_override;
    ret = ath10k_wmi_pdev_set_param(ar, param, 0);
    if (ret) {
        ath10k_warn(ar, "failed to set arp ac override parameter: %d\n", ret);
        goto err;
    }

    if (test_bit(ATH10K_FW_FEATURE_SUPPORTS_ADAPTIVE_CCA, ar->running_fw->fw_file.fw_features)) {
        ret = ath10k_wmi_pdev_enable_adaptive_cca(ar, 1, WMI_CCA_DETECT_LEVEL_AUTO, WMI_CCA_DETECT_MARGIN_AUTO);
        if (ret) {
            ath10k_warn(ar, "failed to enable adaptive cca: %d\n", ret);
            goto err;
        }
    }

    param = ar->wmi.pdev_param->ani_enable;
    ret = ath10k_wmi_pdev_set_param(ar, param, 1);
    if (ret) {
        ath10k_warn(ar, "failed to enable ani by default: %d\n", ret);
        goto err;
    }

    ar->ani_enabled = true;

    // param = ar->wmi.pdev_param->pdev_stats_update_period;
    // ret = ath10k_wmi_pdev_set_param(ar, param,
    //                 PDEV_DEFAULT_STATS_UPDATE_PERIOD);
    // if(ret) {
    //     ath10k_warn(ar, "failed to set pdev stats period : %d\n", ret);
    //     goto err;
    // }

    // param = ar->wmi.pdev_param->vdev_stats_update_period;
    // ret = ath10k_wmi_pdev_set_param(ar, param,
    //                 VDEV_DEFAULT_STATS_UPDATE_PERIOD);

    // if(ret) {
    //     ath10k_warn(ar, "failed to set vdev stats period : %d\n", ret);
    //     goto err;
    // }

    // param = ar->wmi.pdev_param->peer_stats_update_period;
    // ret = ath10k_wmi_pdev_set_param(ar, param,
    //                 PEER_DEFAULT_STATS_UPDATE_PERIOD);
    // if(ret) {
    //     ath10k_warn(ar, "failed to set peer stats period : %d\n", ret);
    //     goto err;
    // }


    param = ar->wmi.pdev_param->enable_btcoex;
    if (test_bit(WMI_SERVICE_COEX_GPIO, ar->wmi.svc_map) && test_bit(ATH10K_FW_FEATURE_BTCOEX_PARAM, ar->running_fw->fw_file.fw_features)) {
        ret = ath10k_wmi_pdev_set_param(ar, param, 0);
        if (ret) {
            ath10k_warn(ar, "failed to set btcoex param: %d\n", ret);
            goto err;
        }
        clear_bit(ATH10K_FLAG_BTCOEX, &ar->dev_flags);
    }

    // TODO does that suffice to configure beacon offloading? .. maybe explicit sending is necessary
   param = ar->wmi.pdev_param->beacon_gen_mode;
   ret = ath10k_wmi_pdev_set_param(ar, param, 0);
   if (ret) {
       ath10k_warn(ar, "failed to set beacon_gen_mode: %d\n", ret);
       goto err;
   }

    ar->num_started_vdevs = 0;

    // quick fix of regdomain issue, FIXME: this should be done triggered differently
    ret = ath10k_wmi_pdev_set_regdomain(ar, 0x3a, 0x3a, 0x3a, 0x10, 0x10, WMI_UNINIT_DFS_DOMAIN);
    if (ret) {
        ath10k_warn(ar, "failed to set regdomain (hotfix)\n", ret);
        goto err;
    }

//
//    ath10k_spectral_start(ar);
//    ath10k_thermal_set_throttling(ar);
    u32 period, duration, enabled;
    period = 100;
    duration = (period * 0) / 100;
    enabled = duration ? 1 : 0;
    const u32 quiet_start_offset = 10;

    // instead of ath10k_thermal_set_throttling
    ret = ath10k_wmi_pdev_set_quiet_mode(ar, period, duration,
                         quiet_start_offset,
                         enabled);

    RTE_LOG(DEBUG, PMD, "DRIVER: copy mac address\n");
    // Copy the permanent MAC address
    struct ath10k_hw *hw = ATH10K_DEV_PRIVATE_TO_HW(dev->data->dev_private);
    ether_addr_copy((struct ether_addr *) ar->mac_addr, dev->data->mac_addrs);
    ether_addr_copy((struct ether_addr *) ar->mac_addr, (struct ether_addr *)hw->mac.addr);

    ar->state = ATH10K_STATE_ON;
    // moved that up a little
    // __ath10k_set_antenna(ar, ar->cfg_tx_chainmask, ar->cfg_rx_chainmask);

    RTE_LOG(INFO, PMD, "ath10k started on port %" PRIu16 "\n", dev->data->port_id);

    return 0;

err:
  return -1;
}

static int eth_ath10k_rar_set(struct rte_eth_dev *dev,
		struct ether_addr *mac_addr,
		uint32_t index, __rte_unused uint32_t pool)
{
	RTE_LOG(DEBUG, PMD, "DRIVER: add Mac addr\n");
	return 0;
}



static void eth_ath10k_stats_reset(struct rte_eth_dev *dev) {
	RTE_LOG(DEBUG, PMD, "DRIVER: stats reset\n");
}

static void eth_ath10k_stop(struct rte_eth_dev *dev) {
	RTE_LOG(DEBUG, PMD, "DRIVER: stop\n");

    struct ath10k_adapter *adapter = ATH10K_DEV_PRIVATE(dev->data->dev_private);
	struct ath10k *ar = adapter->ar;

    //ath10k_drain_tx(ar);

	//rte_spinlock_lock(&ar->conf_lock);
	if (ar->state != ATH10K_STATE_OFF) {
		ath10k_halt(ar);
		ar->state = ATH10K_STATE_OFF;
	}
	//rte_spinlock_unlock(&ar->conf_lock);

	//cancel_work_sync(&ar->set_coverage_class_work);
	//cancel_delayed_work_sync(&ar->scan.timeout);
	//cancel_work_sync(&ar->restart_work);
    RTE_LOG(DEBUG, PMD, "DRIVER: stopped\n");

}

static void eth_ath10k_close(struct rte_eth_dev *dev) {
	RTE_LOG(DEBUG, PMD, "DRIVER: close\n");
}

static void eth_ath10k_promiscuous_enable(struct rte_eth_dev *dev) {
}

static void eth_ath10k_promiscuous_disable(struct rte_eth_dev *dev) {
}

static void eth_ath10k_allmulticast_enable(struct rte_eth_dev *dev) {
}

static void eth_ath10k_allmulticast_disable(struct rte_eth_dev *dev) {
}

static int eth_ath10k_mtu_set(struct rte_eth_dev *dev, uint16_t mtu) {
    return -1;
}

static void eth_ath10k_rx_queue_release(void *queue) {
}

static void eth_ath10k_tx_queue_release(void *queue) {
}

static void eth_ath10k_rar_clear(struct rte_eth_dev *dev, uint32_t index) {
}

static const struct eth_dev_ops eth_ath10k_ops = {
	.dev_configure        = eth_ath10k_configure,
	.dev_start            = eth_ath10k_start,
	.dev_stop             = eth_ath10k_stop,
	.dev_close            = eth_ath10k_close,
	.promiscuous_enable   = eth_ath10k_promiscuous_enable,
	.promiscuous_disable  = eth_ath10k_promiscuous_disable,
	.allmulticast_enable  = eth_ath10k_allmulticast_enable,
	.allmulticast_disable = eth_ath10k_allmulticast_disable,
	.link_update          = eth_ath10k_link_update,
	.dev_infos_get        = eth_ath10k_infos_get,
	.mtu_set              = eth_ath10k_mtu_set,
	.rx_queue_setup       = eth_ath10k_rx_queue_setup,
	.rx_queue_release     = eth_ath10k_rx_queue_release,
	.tx_queue_setup       = eth_ath10k_tx_queue_setup,
	.tx_queue_release     = eth_ath10k_tx_queue_release,
	.mac_addr_add         = eth_ath10k_rar_set,
	.mac_addr_remove      = eth_ath10k_rar_clear,
};

uint16_t eth_ath10k_rx(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts) {
    struct ath10k_htt *htt = (struct ath10k_htt *)rx_queue;
    struct ath10k *ar = htt->ar;
    int num_rx;
    struct rte_mbuf* rx_bulk_driver[nb_pkts];
    const size_t mesh_hdr_size = 18;
    uint16_t num_rx_ok = 0;
    struct rte_mbuf *rx_pkt;
    u8 da[ETH_ALEN];
    u8 sa[ETH_ALEN];
    size_t offset;
    struct ieee80211_hdr* ieee80211;
    struct rfc1042_hdr* snap;
    uint16_t eth_type;
    struct ether_hdr * eth_hdr;

    if(!ar->powered_up)
        return 0;

    if(ar->polling_enabled) {
        int ret = ath10k_hif_poll(ar);
        if(ret == -1)
            return 0;
    }

    num_rx = ath10k_htt_rx_handle_amsdu_dpdk(htt, rx_bulk_driver, nb_pkts);
    assert(num_rx <= nb_pkts);

    // TODO: deal with retransmits in all frame type cases

    const uint16_t qos_fctl = rte_cpu_to_le_16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA | IEEE80211_FCTL_FROMDS | IEEE80211_FCTL_TODS);

    for(int i = 0; i < num_rx; ++i) {
        rx_pkt = rx_bulk_driver[i];
        assert(rx_pkt != NULL);

        offset = 0;

        ieee80211 = rte_pktmbuf_mtod(rx_pkt, struct ieee80211_hdr *);
        offset += sizeof(struct ieee80211_hdr);
        if(rte_pktmbuf_pkt_len(rx_pkt) < sizeof(struct ieee80211_hdr) + sizeof(struct rfc1042_hdr)) {
            continue;
        }

        if(ieee80211->frame_control == rte_cpu_to_le_16(IEEE80211_FTYPE_DATA | IEEE80211_FCTL_FROMDS | IEEE80211_FCTL_TODS)) {
            ether_addr_copy(ieee80211_get_DA(ieee80211), da);
            ether_addr_copy(ieee80211_get_SA(ieee80211), sa);

            snap = rte_pktmbuf_mtod_offset(rx_pkt, struct rfc1042_hdr*, offset);
            eth_type = snap->snap_type;
            offset += sizeof(struct rfc1042_hdr);

            rte_pktmbuf_adj(rx_pkt, offset);
            rte_pktmbuf_prepend(rx_pkt, sizeof(struct ether_hdr));

            eth_hdr = rte_pktmbuf_mtod(rx_pkt, struct ether_hdr*);
            ether_addr_copy(da, &eth_hdr->d_addr);
            ether_addr_copy(sa, &eth_hdr->s_addr);
            eth_hdr->ether_type = eth_type;
        } else if((ieee80211->frame_control & qos_fctl) == qos_fctl) {
            ether_addr_copy(ieee80211_get_DA(ieee80211), da);
            ether_addr_copy(ieee80211_get_SA(ieee80211), sa);

            offset += sizeof(uint16_t); // QoS Control
            offset += mesh_hdr_size;
            snap = rte_pktmbuf_mtod_offset(rx_pkt, struct rfc1042_hdr*, offset);
            eth_type = snap->snap_type;
            offset += sizeof(struct rfc1042_hdr);

            rte_pktmbuf_adj(rx_pkt, offset);
            rte_pktmbuf_prepend(rx_pkt, sizeof(struct ether_hdr));

            eth_hdr = rte_pktmbuf_mtod(rx_pkt, struct ether_hdr*);
            ether_addr_copy(da, &eth_hdr->d_addr);
            ether_addr_copy(sa, &eth_hdr->s_addr);
            eth_hdr->ether_type = eth_type;
        } else {
            // printf("Unknown frame type\n");
            rte_pktmbuf_free(rx_pkt);
            continue;
        }

        rx_pkts[num_rx_ok] = rx_pkt;
        ++num_rx_ok;
    }

    return num_rx_ok;
}

struct mesh_hdr {
    uint8_t flags;
    uint8_t ttl;
    uint32_t sequence_nr;
    struct ether_addr mesh_addr_05;
    struct ether_addr mesh_addr_06;
} __attribute__((__packed__));

uint16_t eth_ath10k_prepare_tx(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
    uint16_t nb_tx;
    struct rte_mbuf *tx_pkt;
    struct ath10k_txq *txq = tx_queue;
    struct ether_hdr* eth1;
    struct ether_hdr* eth2;
    const size_t mesh_hdr_size = 18;
    const unsigned int bytesToPrepend = sizeof(struct ieee80211_hdr) + sizeof(uint16_t) + mesh_hdr_size + sizeof(struct rfc1042_hdr) - 2 * sizeof(struct ether_hdr);
    size_t offset;
    char* ret;
    struct ieee80211_hdr* ieee80211;
    uint16_t* qos_control;
    struct rfc1042_hdr* snap;
    uint16_t eth_type;
    struct ieee80211_tx_info *info;
    u8 destination_address[ETH_ALEN];
    u8 source_address[ETH_ALEN];

    u8 sender_address[ETH_ALEN];
    u8 receiver_address[ETH_ALEN];

    struct mesh_hdr* mhdr;
    struct ath10k_vif* vif = LIST_FIRST(&txq->htt->ar->arvifs);

    for(nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
        tx_pkt = tx_pkts[nb_tx];

        // try to change to ieee80211 header
        eth1 = rte_pktmbuf_mtod(tx_pkt, struct ether_hdr *);
        eth2 = rte_pktmbuf_mtod_offset(tx_pkt, struct ether_hdr *, sizeof(struct ether_hdr));

        ret = rte_pktmbuf_prepend(tx_pkt, bytesToPrepend);
        assert(ret != NULL);
        offset = 0;

        ieee80211 = rte_pktmbuf_mtod_offset(tx_pkt, struct ieee80211_hdr*, offset);
        offset += sizeof(struct ieee80211_hdr);
        qos_control = rte_pktmbuf_mtod_offset(tx_pkt, uint16_t*, offset);
        offset += sizeof(uint16_t);
        mhdr = rte_pktmbuf_mtod_offset(tx_pkt, struct mesh_hdr*, offset);
        offset += mesh_hdr_size;
        snap = rte_pktmbuf_mtod_offset(tx_pkt, struct rfc1042_hdr*, offset);
        offset += sizeof(struct rfc1042_hdr);

        ether_addr_copy(&eth1->d_addr, receiver_address);
        ether_addr_copy(&eth1->s_addr, sender_address);
        ether_addr_copy(&eth2->d_addr, destination_address);
        ether_addr_copy(&eth2->s_addr, source_address);
        eth_type = rte_be_to_cpu_16(eth2->ether_type);

        memset(ieee80211, 0, sizeof(struct ieee80211_hdr));
        memset(snap, 0, sizeof(struct rfc1042_hdr));

        ieee80211->frame_control = rte_cpu_to_le_16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA | IEEE80211_FCTL_FROMDS | IEEE80211_FCTL_TODS);
        ether_addr_copy(destination_address, ieee80211_get_DA(ieee80211));
        ether_addr_copy(source_address, ieee80211_get_SA(ieee80211));
        ether_addr_copy(receiver_address, &ieee80211->addr1);
        ether_addr_copy(sender_address, &ieee80211->addr2);

        mhdr->ttl = 0x1f;
        mhdr->flags = 0x02;
        mhdr->sequence_nr = rte_cpu_to_be_32(0x12345);

        // assert(!LIST_EMPTY(&txq->htt->ar->arvifs));
        // unsigned int len = 0;
        // LIST_FOREACH(vif, &txq->htt->ar->arvifs, pointers) {
        //     ++len;
        // }
        // assert(len == 1);

        snap->llc_dsap = 0xaa;
        snap->llc_ssap = 0xaa;
        snap->llc_ctrl = 0x03;
        snap->snap_type = rte_cpu_to_be_16(eth_type);

        info = IEEE80211_SKB_CB(tx_pkt);
        memset(info, 0, sizeof(struct ieee80211_tx_info));
        info->control.vif = vif->vif;
    }

    return nb_tx;
}

uint16_t eth_ath10k_tx(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
    uint16_t nb_tx;
    struct rte_mbuf *tx_pkt;
    struct ath10k_txq *txq = tx_queue;
    struct ath10k *ar = txq->htt->ar;

    if(ar->powered_up == false) {
        return 0;
    }

    for(nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
        tx_pkt = tx_pkts[nb_tx];

        if(ath10k_mac_tx_can_push_ath10k_args(ar, txq) == true) {
            struct ieee80211_tx_control control = {0};
            ath10k_mac_op_tx(ar->hw, &control, tx_pkt, nb_tx < nb_pkts - 1);
        } else {
            break;
        }
    }

    return nb_tx;
}

static inline enum wmi_phy_mode
chan_to_phymode(const struct cfg80211_chan_def *chandef)
{
    enum wmi_phy_mode phymode = MODE_UNKNOWN;

    switch (chandef->chan->band) {
    case NL80211_BAND_2GHZ:
        switch (chandef->width) {
        case NL80211_CHAN_WIDTH_20_NOHT:
            if (chandef->chan->flags & IEEE80211_CHAN_NO_OFDM)
                phymode = MODE_11B;
            else
                phymode = MODE_11G;
            break;
        case NL80211_CHAN_WIDTH_20:
            phymode = MODE_11NG_HT20;
            break;
        case NL80211_CHAN_WIDTH_40:
            phymode = MODE_11NG_HT40;
            break;
        case NL80211_CHAN_WIDTH_5:
        case NL80211_CHAN_WIDTH_10:
        case NL80211_CHAN_WIDTH_80:
        case NL80211_CHAN_WIDTH_80P80:
        case NL80211_CHAN_WIDTH_160:
            phymode = MODE_UNKNOWN;
            break;
        }
        break;
    case NL80211_BAND_5GHZ:
        switch (chandef->width) {
        case NL80211_CHAN_WIDTH_20_NOHT:
            phymode = MODE_11A;
            break;
        case NL80211_CHAN_WIDTH_20:
            phymode = MODE_11NA_HT20;
            break;
        case NL80211_CHAN_WIDTH_40:
            phymode = MODE_11NA_HT40;
            break;
        case NL80211_CHAN_WIDTH_80:
            phymode = MODE_11AC_VHT80;
            break;
        case NL80211_CHAN_WIDTH_160:
            phymode = MODE_11AC_VHT160;
            break;
        case NL80211_CHAN_WIDTH_80P80:
            phymode = MODE_11AC_VHT80_80;
            break;
        case NL80211_CHAN_WIDTH_5:
        case NL80211_CHAN_WIDTH_10:
            phymode = MODE_UNKNOWN;
            break;
        }
        break;
    default:
        break;
    }

    if(phymode == MODE_UNKNOWN)
        RTE_LOG(WARNING, PMD, "DRIVER: MODE_UNKNOWN for chandef->chan->band (enum nl80211_band)\n");
    return phymode;
}

static void ath10k_mac_num_chanctxs_iter(struct ieee80211_hw *hw,
                     struct ieee80211_chanctx_conf *conf,
                     void *data)
{
    int *num = data;

    (*num)++;
}

static int ath10k_mac_num_chanctxs(struct ath10k *ar) {
    int num = 0;

    ieee80211_iter_chan_contexts_atomic(ar->hw, ath10k_mac_num_chanctxs_iter, &num);

    return num;
}

static void ath10k_mac_get_any_chandef_iter(struct ieee80211_hw *hw,
                struct ieee80211_chanctx_conf *conf,
                void *data)
{
    struct cfg80211_chan_def **def = data;

    *def = &conf->def;
}

static void ath10k_mac_update_rx_channel(struct ath10k *ar, struct ieee80211_chanctx_conf *ctx, struct ieee80211_vif_chanctx_switch *vifs, int n_vifs) {
    struct cfg80211_chan_def *def = NULL;

    /* Both locks are required because ar->rx_channel is modified. This
    * allows readers to hold either lock.
    */
    // lockdep_assert_held(&ar->conf_lock);
    // lockdep_assert_held(&ar->data_lock);

    if(ctx && vifs) {
        RTE_LOG(WARNING, PMD, "DRIVER: ctx && vifs\n");
    }
    if(vifs && !n_vifs) {
        RTE_LOG(WARNING, PMD, "DRIVER: vifs && !n_vifs\n");
    }

    /* FIXME: Sort of an optimization and a workaround. Peers and vifs are
    * on a linked list now. Doing a lookup peer -> vif -> chanctx for each
    * ppdu on Rx may reduce performance on low-end systems. It should be
    * possible to make tables/hashmaps to speed the lookup up (be vary of
    * cpu data cache lines though regarding sizes) but to keep the initial
    * implementation simple and less intrusive fallback to the slow lookup
    * only for multi-channel cases. Single-channel cases will remain to
    * use the old channel derival and thus performance should not be
    * affected much.
    */
    // rcu_read_lock();
    if (!ctx && ath10k_mac_num_chanctxs(ar) == 1) {
      ieee80211_iter_chan_contexts_atomic(ar->hw, ath10k_mac_get_any_chandef_iter, &def);

      if (vifs)
          def = &vifs[0].new_ctx->def;

      ar->rx_channel = def->chan;
    } else if ((ctx && ath10k_mac_num_chanctxs(ar) == 0) ||
         (ctx && (ar->state == ATH10K_STATE_RESTARTED))) {
      /* During driver restart due to firmware assert, since mac80211
       * already has valid channel context for given radio, channel
       * context iteration return num_chanctx > 0. So fix rx_channel
       * when restart is in progress.
       */
      ar->rx_channel = ctx->def.chan;
    } else {
      ar->rx_channel = NULL;
    }
    // rcu_read_unlock();
}

static inline int ath10k_vdev_setup_sync(struct ath10k *ar)
{
  unsigned long time_left;

  // lockdep_assert_held(&ar->conf_lock);

  if (test_bit(ATH10K_FLAG_CRASH_FLUSH, &ar->dev_flags))
      return -ESHUTDOWN;

  time_left = wait_for_completion_timeout(&ar->vdev_setup_done, ATH10K_VDEV_SETUP_TIMEOUT_HZ);
  if (time_left == 0)
      return -ETIMEDOUT;

  return 0;
}

static int ath10k_monitor_vdev_stop(struct ath10k *ar)
{
    int ret = 0;

    // lockdep_assert_held(&ar->conf_lock);

    ret = ath10k_wmi_vdev_down(ar, ar->monitor_vdev_id);
    if (ret)
        ath10k_warn(ar, "failed to put down monitor vdev %i: %d\n",
              ar->monitor_vdev_id, ret);

    reinit_completion(&ar->vdev_setup_done);

    ret = ath10k_wmi_vdev_stop(ar, ar->monitor_vdev_id);
    if (ret)
        ath10k_warn(ar, "failed to to request monitor vdev %i stop: %d\n",
              ar->monitor_vdev_id, ret);

    ret = ath10k_vdev_setup_sync(ar);
    if (ret)
        ath10k_warn(ar, "failed to synchronize monitor vdev %i stop: %d\n",
              ar->monitor_vdev_id, ret);

    RTE_LOG(DEBUG, PMD, "DRIVER: mac monitor vdev %i stopped\n", ar->monitor_vdev_id);
    return ret;
}

static int ath10k_monitor_vdev_create(struct ath10k *ar)
{
    int bit, ret = 0;

    // lockdep_assert_held(&ar->conf_lock);

    if (ar->free_vdev_map == 0) {
      ath10k_warn(ar, "failed to find free vdev id for monitor vdev\n");
      return -ENOMEM;
    }

    bit = __ffs64(ar->free_vdev_map);

    ar->monitor_vdev_id = bit;

    ret = ath10k_wmi_vdev_create(ar, ar->monitor_vdev_id,
                   WMI_VDEV_TYPE_MONITOR,
                   0, ar->mac_addr);
    if (ret) {
      ath10k_warn(ar, "failed to request monitor vdev %i creation: %d\n",
              ar->monitor_vdev_id, ret);
      return ret;
    }

    ar->free_vdev_map &= ~(1LL << ar->monitor_vdev_id);
    ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor vdev %d created\n",
         ar->monitor_vdev_id);

    return 0;
}

static int ath10k_monitor_vdev_delete(struct ath10k *ar)
{
    int ret = 0;

    // lockdep_assert_held(&ar->conf_lock);

    ret = ath10k_wmi_vdev_delete(ar, ar->monitor_vdev_id);
    if (ret) {
      ath10k_warn(ar, "failed to request wmi monitor vdev %i removal: %d\n",
              ar->monitor_vdev_id, ret);
      return ret;
    }

    ar->free_vdev_map |= 1LL << ar->monitor_vdev_id;

    ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor vdev %d deleted\n",
         ar->monitor_vdev_id);
    return ret;
}

static int ath10k_monitor_vdev_start(struct ath10k *ar, int vdev_id)
{
    struct cfg80211_chan_def *chandef = NULL;
    struct ieee80211_channel *channel = NULL;
    struct wmi_vdev_start_request_arg arg = {};
    int ret = 0;

    // lockdep_assert_held(&ar->conf_lock);

    ieee80211_iter_chan_contexts_atomic(ar->hw,
                      ath10k_mac_get_any_chandef_iter,
                      &chandef);
    if (WARN_ON_ONCE(!chandef))
      return -ENOENT;

    channel = chandef->chan;

    arg.vdev_id = vdev_id;
    arg.channel.freq = channel->center_freq;
    arg.channel.band_center_freq1 = chandef->center_freq1;
    arg.channel.band_center_freq2 = chandef->center_freq2;

    /* TODO setup this dynamically, what in case we
     don't have any vifs? */
    arg.channel.mode = chan_to_phymode(chandef);
    arg.channel.chan_radar =
          !!(channel->flags & IEEE80211_CHAN_RADAR);

    arg.channel.min_power = 0;
    arg.channel.max_power = channel->max_power * 2;
    arg.channel.max_reg_power = channel->max_reg_power * 2;
    arg.channel.max_antenna_gain = channel->max_antenna_gain * 2;

    reinit_completion(&ar->vdev_setup_done);

    ret = ath10k_wmi_vdev_start(ar, &arg);
    if (ret) {
      ath10k_warn(ar, "failed to request monitor vdev %i start: %d\n",
              vdev_id, ret);
      return ret;
    }

    ret = ath10k_vdev_setup_sync(ar);
    if (ret) {
      ath10k_warn(ar, "failed to synchronize setup for monitor vdev %i start: %d\n",
              vdev_id, ret);
      return ret;
    }

    ret = ath10k_wmi_vdev_up(ar, vdev_id, 0, ar->mac_addr);
    if (ret) {
      ath10k_warn(ar, "failed to put up monitor vdev %i: %d\n",
              vdev_id, ret);
      goto vdev_stop;
    }

    ar->monitor_vdev_id = vdev_id;

    ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor vdev %i started\n",
         ar->monitor_vdev_id);
    return 0;

    vdev_stop:
    ret = ath10k_wmi_vdev_stop(ar, ar->monitor_vdev_id);
    if (ret)
      ath10k_warn(ar, "failed to stop monitor vdev %i after start failure: %d\n",
              ar->monitor_vdev_id, ret);

    return ret;
}

static int ath10k_monitor_start(struct ath10k *ar)
{
    int ret;

    // lockdep_assert_held(&ar->conf_lock);

    ret = ath10k_monitor_vdev_create(ar);
    if (ret) {
      ath10k_warn(ar, "failed to create monitor vdev: %d\n", ret);
      return ret;
    }

    ret = ath10k_monitor_vdev_start(ar, ar->monitor_vdev_id);
    if (ret) {
      ath10k_warn(ar, "failed to start monitor vdev: %d\n", ret);
      ath10k_monitor_vdev_delete(ar);
      return ret;
    }

    ar->monitor_started = true;
    ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor started\n");

    return 0;
}

static int ath10k_monitor_stop(struct ath10k *ar)
{
    int ret;

    // lockdep_assert_held(&ar->conf_lock);

    ret = ath10k_monitor_vdev_stop(ar);
    if (ret) {
      ath10k_warn(ar, "failed to stop monitor vdev: %d\n", ret);
      return ret;
    }

    ret = ath10k_monitor_vdev_delete(ar);
    if (ret) {
      ath10k_warn(ar, "failed to delete monitor vdev: %d\n", ret);
      return ret;
    }

    ar->monitor_started = false;
    ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor stopped\n");

    return 0;
}

static bool ath10k_mac_monitor_vdev_is_needed(struct ath10k *ar)
{
    int num_ctx;

    /* At least one chanctx is required to derive a channel to start
    * monitor vdev on.
    */
    num_ctx = ath10k_mac_num_chanctxs(ar);
    if (num_ctx == 0)
        return false;

    /* If there's already an existing special monitor interface then don't
    * bother creating another monitor vdev.
    */
    if (ar->monitor_arvif)
        return false;

    return ar->monitor ||
         (ar->filter_flags & FIF_OTHER_BSS) ||
         test_bit(ATH10K_CAC_RUNNING, &ar->dev_flags);
}

static bool ath10k_mac_monitor_vdev_is_allowed(struct ath10k *ar)
{
    int num_ctx;

    num_ctx = ath10k_mac_num_chanctxs(ar);

    /* FIXME: Current interface combinations and cfg80211/mac80211 code
     * shouldn't allow this but make sure to prevent handling the following
     * case anyway since multi-channel DFS hasn't been tested at all.
     */
    if (test_bit(ATH10K_CAC_RUNNING, &ar->dev_flags) && num_ctx > 1)
        return false;

    return true;
}

static int ath10k_monitor_recalc(struct ath10k *ar)
{
    bool needed;
    bool allowed;
    int ret;

    // lockdep_assert_held(&ar->conf_lock);

    needed = ath10k_mac_monitor_vdev_is_needed(ar);
    allowed = ath10k_mac_monitor_vdev_is_allowed(ar);

    ath10k_dbg(ar, ATH10K_DBG_MAC,
         "mac monitor recalc started? %d needed? %d allowed? %d\n",
         ar->monitor_started, needed, allowed);

    if (WARN_ON(needed && !allowed)) {
        if (ar->monitor_started) {
            ath10k_dbg(ar, ATH10K_DBG_MAC, "mac monitor stopping disallowed monitor\n");

            ret = ath10k_monitor_stop(ar);
            if (ret)
                ath10k_warn(ar, "failed to stop disallowed monitor: %d\n", ret);
                /* not serious */
        }
      return -EPERM;
    }

    if (needed == ar->monitor_started)
        return 0;

    if (needed)
        return ath10k_monitor_start(ar);
    else
        return ath10k_monitor_stop(ar);
}

 static int ath10k_start_cac(struct ath10k *ar)
{
    int ret;

    // lockdep_assert_held(&ar->conf_lock);

    set_bit(ATH10K_CAC_RUNNING, &ar->dev_flags);

    ret = ath10k_monitor_recalc(ar);
    if (ret) {
      ath10k_warn(ar, "failed to start monitor (cac): %d\n", ret);
      clear_bit(ATH10K_CAC_RUNNING, &ar->dev_flags);
      return ret;
    }

    ath10k_dbg(ar, ATH10K_DBG_MAC, "mac cac start monitor vdev %d\n",
         ar->monitor_vdev_id);

    return 0;
}

static int ath10k_stop_cac(struct ath10k *ar)
{
    // lockdep_assert_held(&ar->conf_lock);

    /* CAC is not running - do nothing */
    if (!test_bit(ATH10K_CAC_RUNNING, &ar->dev_flags))
        return 0;

    clear_bit(ATH10K_CAC_RUNNING, &ar->dev_flags);
    ath10k_monitor_stop(ar);

    RTE_LOG(DEBUG, PMD, "DRIVER: mac cac finished\n");

    return 0;
}

 static void ath10k_mac_has_radar_iter(struct ieee80211_hw *hw,
                    struct ieee80211_chanctx_conf *conf,
                    void *data)
{
   bool *ret = data;

   if (!*ret && conf->radar_enabled)
       *ret = true;
}

static bool ath10k_mac_has_radar_enabled(struct ath10k *ar)
{
   bool has_radar = false;

   ieee80211_iter_chan_contexts_atomic(ar->hw,
                       ath10k_mac_has_radar_iter,
                       &has_radar);

   return has_radar;
}

static void ath10k_recalc_radar_detection(struct ath10k *ar)
{
    int ret;

//  lockdep_assert_held(&ar->conf_lock);

    ath10k_stop_cac(ar);

  if(!ath10k_mac_has_radar_enabled(ar))
      return;

  if (ar->num_started_vdevs > 0)
      return;

  ret = ath10k_start_cac(ar);
  if (ret) {
      /*
       * Not possible to start CAC on current channel so starting
       * radiation is not allowed, make this channel DFS_UNAVAILABLE
       * by indicating that radar was detected.
       */
      ath10k_warn(ar, "failed to start CAC: %d\n", ret);
      ieee80211_radar_detected(ar->hw);
  }
}

static int eth_ath10k_add_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx) {
    struct ath10k *ar = hw->priv;

    RTE_LOG(DEBUG, PMD, "DRIVER: mac chanctx add freq %hu width %d ptr %pK\n", ctx->def.chan->center_freq, ctx->def.width, ctx);

    rte_spinlock_lock(&ar->conf_lock);

    rte_spinlock_lock(&ar->data_lock);
    ath10k_mac_update_rx_channel(ar, ctx, NULL, 0);
    rte_spinlock_unlock(&ar->data_lock);

    ath10k_recalc_radar_detection(ar);
//    ath10k_monitor_recalc(ar);

    rte_spinlock_unlock(&ar->conf_lock);

    return 0;
}

static void ath10k_check_chain_mask(struct ath10k *ar, u32 cm, const char *dbg)
{
    /* It is not clear that allowing gaps in chainmask
     * is helpful.  Probably it will not do what user
     * is hoping for, so warn in that case.
     */
    if (cm == 15 || cm == 7 || cm == 3 || cm == 1 || cm == 0)
        return;

    ath10k_warn(ar, "mac %s antenna chainmask may be invalid: 0x%x.  Suggested values: 15, 7, 3, 1 or 0.\n", dbg, cm);
}

static struct ieee80211_sta_ht_cap ath10k_get_ht_cap(struct ath10k *ar)
{
    int i;
    struct ieee80211_sta_ht_cap ht_cap = {0};

    if (!(ar->ht_cap_info & WMI_HT_CAP_ENABLED))
        return ht_cap;

    ht_cap.ht_supported = 1;
    ht_cap.ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
    ht_cap.ampdu_density = IEEE80211_HT_MPDU_DENSITY_8;
    ht_cap.cap |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
    ht_cap.cap |= IEEE80211_HT_CAP_DSSSCCK40;
    ht_cap.cap |=
        WLAN_HT_CAP_SM_PS_DISABLED << IEEE80211_HT_CAP_SM_PS_SHIFT;

    if (ar->ht_cap_info & WMI_HT_CAP_HT20_SGI)
        ht_cap.cap |= IEEE80211_HT_CAP_SGI_20;

    if (ar->ht_cap_info & WMI_HT_CAP_HT40_SGI)
        ht_cap.cap |= IEEE80211_HT_CAP_SGI_40;

    if (ar->ht_cap_info & WMI_HT_CAP_DYNAMIC_SMPS) {
        u32 smps;

        smps   = WLAN_HT_CAP_SM_PS_DYNAMIC;
        smps <<= IEEE80211_HT_CAP_SM_PS_SHIFT;

        ht_cap.cap |= smps;
    }

    if ((ar->ht_cap_info & WMI_HT_CAP_TX_STBC) && (ar->cfg_tx_chainmask > 1))
        ht_cap.cap |= IEEE80211_HT_CAP_TX_STBC;

    if (ar->ht_cap_info & WMI_HT_CAP_RX_STBC) {
        u32 stbc;

        stbc   = ar->ht_cap_info;
        stbc  &= WMI_HT_CAP_RX_STBC;
        stbc >>= WMI_HT_CAP_RX_STBC_MASK_SHIFT;
        stbc <<= IEEE80211_HT_CAP_RX_STBC_SHIFT;
        stbc  &= IEEE80211_HT_CAP_RX_STBC;

        ht_cap.cap |= stbc;
    }

    if (ar->ht_cap_info & WMI_HT_CAP_LDPC)
        ht_cap.cap |= IEEE80211_HT_CAP_LDPC_CODING;

    if (ar->ht_cap_info & WMI_HT_CAP_L_SIG_TXOP_PROT)
        ht_cap.cap |= IEEE80211_HT_CAP_LSIG_TXOP_PROT;

    /* max AMSDU is implicitly taken from vht_cap_info */
    if (ar->vht_cap_info & WMI_VHT_CAP_MAX_MPDU_LEN_MASK)
        ht_cap.cap |= IEEE80211_HT_CAP_MAX_AMSDU;

    for (i = 0; i < ar->num_rf_chains; i++) {
        if (ar->cfg_rx_chainmask & BIT(i))
            ht_cap.mcs.rx_mask[i] = 0xFF;
    }

    ht_cap.mcs.tx_params |= IEEE80211_HT_MCS_TX_DEFINED;

    return ht_cap;
}

static int ath10k_mac_get_vht_cap_bf_sts(struct ath10k *ar)
{
    int nsts = ar->vht_cap_info;

    nsts &= IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK;
    nsts >>= IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT;

    /* If firmware does not deliver to host number of space-time
     * streams supported, assume it support up to 4 BF STS and return
     * the value for VHT CAP: nsts-1)
     */
    if (nsts == 0)
        return 3;

    return nsts;
}

static int ath10k_mac_get_vht_cap_bf_sound_dim(struct ath10k *ar)
{
    int sound_dim = ar->vht_cap_info;

    sound_dim &= IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK;
    sound_dim >>= IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT;

    /* If the sounding dimension is not advertised by the firmware,
     * let's use a default value of 1
     */
    if (sound_dim == 0)
        return 1;

    return sound_dim;
}

static struct ieee80211_sta_vht_cap ath10k_create_vht_cap(struct ath10k *ar)
{
    struct ieee80211_sta_vht_cap vht_cap = {0};
    struct ath10k_hw_params *hw = &ar->hw_params;
    u16 mcs_map;
    u32 val;
    int i;

    vht_cap.vht_supported = 1;
    vht_cap.cap = ar->vht_cap_info;

    if (ar->vht_cap_info & (IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE |
                IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE)) {
        val = ath10k_mac_get_vht_cap_bf_sts(ar);
        val <<= IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT;
        val &= IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK;

        vht_cap.cap |= val;
    }

    if (ar->vht_cap_info & (IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE |
                IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE)) {
        val = ath10k_mac_get_vht_cap_bf_sound_dim(ar);
        val <<= IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT;
        val &= IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK;

        vht_cap.cap |= val;
    }

    /* Currently the firmware seems to be buggy, don't enable 80+80
     * mode until that's resolved.
     */
    if ((ar->vht_cap_info & IEEE80211_VHT_CAP_SHORT_GI_160) &&
        (ar->vht_cap_info & IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK) == 0)
         vht_cap.cap |= IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;

    mcs_map = 0;
    for (i = 0; i < 8; i++) {
        if ((i < ar->num_rf_chains) && (ar->cfg_tx_chainmask & BIT(i)))
            mcs_map |= IEEE80211_VHT_MCS_SUPPORT_0_9 << (i * 2);
        else
            mcs_map |= IEEE80211_VHT_MCS_NOT_SUPPORTED << (i * 2);
    }

    if (ar->cfg_tx_chainmask <= 1)
        vht_cap.cap &= ~IEEE80211_VHT_CAP_TXSTBC;

    vht_cap.vht_mcs.rx_mcs_map = rte_cpu_to_le_16(mcs_map);
    vht_cap.vht_mcs.tx_mcs_map = rte_cpu_to_le_16(mcs_map);

    /* If we are supporting 160Mhz or 80+80, then the NIC may be able to do
    * a restricted NSS for 160 or 80+80 vs what it can do for 80Mhz.  Give
    * user-space a clue if that is the case.
    */
    if ((vht_cap.cap & IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK) &&
            (hw->vht160_mcs_rx_highest != 0 ||
                    hw->vht160_mcs_tx_highest != 0)) {
        vht_cap.vht_mcs.rx_highest = cpu_to_le16(hw->vht160_mcs_rx_highest);
        vht_cap.vht_mcs.tx_highest = cpu_to_le16(hw->vht160_mcs_tx_highest);
    }

    return vht_cap;
}

static void ath10k_mac_setup_ht_vht_cap(struct ath10k *ar)
{
    struct ieee80211_supported_band *band;
    struct ieee80211_sta_vht_cap vht_cap;
    struct ieee80211_sta_ht_cap ht_cap;

    ht_cap = ath10k_get_ht_cap(ar);
    vht_cap = ath10k_create_vht_cap(ar);

    if (ar->phy_capability & WHAL_WLAN_11G_CAPABILITY) {
        band = &ar->mac.sbands[NL80211_BAND_2GHZ];
        band->ht_cap = ht_cap;
    }
    if (ar->phy_capability & WHAL_WLAN_11A_CAPABILITY) {
        band = &ar->mac.sbands[NL80211_BAND_5GHZ];
        band->ht_cap = ht_cap;
        band->vht_cap = vht_cap;
    }
}

static int __ath10k_set_antenna(struct ath10k *ar, u32 tx_ant, u32 rx_ant)
{
    int ret;

    // lockdep_assert_held(&ar->conf_lock);

    printf("Set antenna tx: %u rx: %u\n", tx_ant, rx_ant);

    ath10k_check_chain_mask(ar, tx_ant, "tx");
    ath10k_check_chain_mask(ar, rx_ant, "rx");

    ar->cfg_tx_chainmask = tx_ant;
    ar->cfg_rx_chainmask = rx_ant;

    if ((ar->state != ATH10K_STATE_ON) &&
        (ar->state != ATH10K_STATE_RESTARTED))
        return 0;

    ret = ath10k_wmi_pdev_set_param(ar, ar->wmi.pdev_param->tx_chain_mask,
                    tx_ant);
    if (ret) {
        ath10k_warn(ar, "failed to set tx-chainmask: %d, req 0x%x\n",
                ret, tx_ant);
        return ret;
    }

    ret = ath10k_wmi_pdev_set_param(ar, ar->wmi.pdev_param->rx_chain_mask,
                    rx_ant);
    if (ret) {
        ath10k_warn(ar, "failed to set rx-chainmask: %d, req 0x%x\n",
                ret, rx_ant);
        return ret;
    }

    /* Reload HT/VHT capability */
    ath10k_mac_setup_ht_vht_cap(ar);

    return 0;
}

static int eth_ath10k_set_antenna(struct ieee80211_hw *hw, u32 tx_ant, u32 rx_ant)
{
    struct ath10k *ar = hw->priv;
    int ret;

    rte_spinlock_lock(&ar->conf_lock);
    ret = __ath10k_set_antenna(ar, tx_ant, rx_ant);
    rte_spinlock_unlock(&ar->conf_lock);
    return ret;
}

static int eth_ath10k_get_antenna(struct ieee80211_hw *hw, u32 *tx_ant, u32 *rx_ant)
{
    struct ath10k *ar = hw->priv;

    rte_spinlock_lock(&ar->conf_lock);

    *tx_ant = ar->cfg_tx_chainmask;
    *rx_ant = ar->cfg_rx_chainmask;

    rte_spinlock_unlock(&ar->conf_lock);

    return 0;
}

static int ath10k_mac_num_vifs_started(struct ath10k *ar)
{
    struct ath10k_vif *arvif;
    int num = 0;

    // lockdep_assert_held(&ar->conf_lock);

    LIST_FOREACH(arvif, &ar->arvifs, pointers)
      if (arvif->is_started)
          num++;

    return num;
}

static int ath10k_mac_vif_setup_ps(struct ath10k_vif *arvif)
{
    struct ath10k *ar = arvif->ar;
    struct ieee80211_vif *vif = arvif->vif;
    struct ieee80211_conf *conf = &ar->hw->conf;
    enum wmi_sta_powersave_param param;
    enum wmi_sta_ps_mode psmode;
    int ret;
    int ps_timeout;
    bool enable_ps;

    // lockdep_assert_held(&arvif->ar->conf_lock);

    if (arvif->vif->type != NL80211_IFTYPE_STATION)
      return 0;

    enable_ps = arvif->ps;

    if (enable_ps && ath10k_mac_num_vifs_started(ar) > 1 &&
      !test_bit(ATH10K_FW_FEATURE_MULTI_VIF_PS_SUPPORT,
            ar->running_fw->fw_file.fw_features)) {
      ath10k_warn(ar, "refusing to enable ps on vdev %i: not supported by fw\n",
              arvif->vdev_id);
      enable_ps = false;
    }

    if (!arvif->is_started) {
      /* mac80211 can update vif powersave state while disconnected.
       * Firmware doesn't behave nicely and consumes more power than
       * necessary if PS is disabled on a non-started vdev. Hence
       * force-enable PS for non-running vdevs.
       */
      psmode = WMI_STA_PS_MODE_ENABLED;
    } else if (enable_ps) {
      psmode = WMI_STA_PS_MODE_ENABLED;
      param = WMI_STA_PS_PARAM_INACTIVITY_TIME;

      ps_timeout = conf->dynamic_ps_timeout;
      if (ps_timeout == 0) {
          /* Firmware doesn't like 0 */
          ps_timeout = ieee80211_tu_to_usec(
              vif->bss_conf.beacon_int) / 1000;
      }

      ret = ath10k_wmi_set_sta_ps_param(ar, arvif->vdev_id, param,
                        ps_timeout);
      if (ret) {
          ath10k_warn(ar, "failed to set inactivity time for vdev %d: %i\n",
                  arvif->vdev_id, ret);
          return ret;
      }
    } else {
      psmode = WMI_STA_PS_MODE_DISABLED;
    }

    ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d psmode %s\n",
         arvif->vdev_id, psmode ? "enable" : "disable");

    ret = ath10k_wmi_set_psmode(ar, arvif->vdev_id, psmode);
    if (ret) {
      ath10k_warn(ar, "failed to set PS Mode %d for vdev %d: %d\n",
              psmode, arvif->vdev_id, ret);
      return ret;
    }

    return 0;
}

static int ath10k_vdev_stop(struct ath10k_vif *arvif)
{
    struct ath10k *ar = arvif->ar;
    int ret;

    // lockdep_assert_held(&ar->conf_lock);

    reinit_completion(&ar->vdev_setup_done);

    ret = ath10k_wmi_vdev_stop(ar, arvif->vdev_id);
    if (ret) {
        ath10k_warn(ar, "failed to stop WMI vdev %i: %d\n",
                arvif->vdev_id, ret);
        return ret;
    }

    ret = ath10k_vdev_setup_sync(ar);
    if (ret) {
        ath10k_warn(ar, "failed to synchronize setup for vdev %i: %d\n",
                arvif->vdev_id, ret);
        return ret;
    }


    if (ar->num_started_vdevs == 0)
        RTE_LOG(WARNING, PMD, "DRIVER: ar->num_started_vdevs == 0\n");

    if (ar->num_started_vdevs != 0) {
        ar->num_started_vdevs--;
        ath10k_recalc_radar_detection(ar);
    }

    return ret;
}

static int ath10k_vdev_start_restart(struct ath10k_vif *arvif,
                     const struct cfg80211_chan_def *chandef,
                     bool restart)
{
    struct ath10k *ar = arvif->ar;
    struct wmi_vdev_start_request_arg arg = {0};
    int ret = 0;

    // lockdep_assert_held(&ar->conf_lock);

    ath10k_regd_update(ar);

    reinit_completion(&ar->vdev_setup_done);

    arg.vdev_id = arvif->vdev_id;
    arg.dtim_period = arvif->dtim_period;
    arg.bcn_intval = arvif->beacon_interval;

    arg.channel.freq = chandef->chan->center_freq;
    arg.channel.band_center_freq1 = chandef->center_freq1;
    arg.channel.band_center_freq2 = chandef->center_freq2;
    arg.channel.mode = chan_to_phymode(chandef);

    arg.channel.allow_ht = true;
    arg.channel.allow_vht = true;
    arg.channel.passive = true;
    arg.channel.allow_ibss = true;
    arg.channel.ht40plus = true;
    // bool chan_radar;
    arg.channel.min_power = 0;
    // arg.channel.max_power = chandef->chan->max_power * 2;
    // arg.channel.max_reg_power = chandef->chan->max_reg_power * 2;
    // arg.channel.max_antenna_gain = chandef->chan->max_antenna_gain * 2;
    arg.channel.max_power = 35;
    arg.channel.max_reg_power = 35;
    arg.channel.max_antenna_gain = 0;


    if (arvif->vdev_type == WMI_VDEV_TYPE_AP) {
        arg.ssid = arvif->u.ap.ssid;
        arg.ssid_len = arvif->u.ap.ssid_len;
        arg.hidden_ssid = arvif->u.ap.hidden_ssid;

        // /* For now allow DFS for AP mode */
        // arg.channel.chan_radar =
        //     !!(chandef->chan->flags & IEEE80211_CHAN_RADAR);
    } else if (arvif->vdev_type == WMI_VDEV_TYPE_IBSS) {
        arg.ssid = arvif->vif->bss_conf.ssid;
        arg.ssid_len = arvif->vif->bss_conf.ssid_len;
    }

    ath10k_dbg(ar, ATH10K_DBG_MAC,
           "mac vdev %d start center_freq %d phymode %s\n",
           arg.vdev_id, arg.channel.freq,
           ath10k_wmi_phymode_str(arg.channel.mode));

    if (restart)
        ret = ath10k_wmi_vdev_restart(ar, &arg);
    else
        ret = ath10k_wmi_vdev_start(ar, &arg);

    if (ret) {
        ath10k_warn(ar, "failed to start WMI vdev %i: %d\n",
                arg.vdev_id, ret);
        return ret;
    }

    ret = ath10k_vdev_setup_sync(ar);
    if (ret) {
        ath10k_warn(ar,
                "failed to synchronize setup for vdev %i restart %d: %d\n",
                arg.vdev_id, restart, ret);
        return ret;
    }

    ar->num_started_vdevs++;
    // ath10k_recalc_radar_detection(ar);

    return ret;
}

static int ath10k_vdev_start(struct ath10k_vif *arvif,
                 const struct cfg80211_chan_def *def)
{
    return ath10k_vdev_start_restart(arvif, def, false);
}

static int ath10k_vdev_restart(struct ath10k_vif *arvif,
                   const struct cfg80211_chan_def *def)
{
    return ath10k_vdev_start_restart(arvif, def, true);
}

static bool ath10k_mac_can_set_cts_prot(struct ath10k_vif *arvif)
{
   struct ath10k *ar = arvif->ar;

   lockdep_assert_held(&ar->conf_lock);

   if (!arvif->is_started) {
       ath10k_dbg(ar, ATH10K_DBG_MAC, "defer cts setup, vdev is not ready yet\n");
       return false;
   }

   return true;
}

static int ath10k_mac_set_cts_prot(struct ath10k_vif *arvif)
{
   struct ath10k *ar = arvif->ar;
   u32 vdev_param;

   lockdep_assert_held(&ar->conf_lock);

   vdev_param = ar->wmi.vdev_param->protection_mode;

   ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d cts_protection %d\n",
          arvif->vdev_id, arvif->use_cts_prot);

   // return ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
   //                 arvif->use_cts_prot ? 1 : 0);
   return ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, 0);
}

static int eth_ath10k_mac_op_assign_vif_chanctx(struct ieee80211_hw *hw,
               struct ieee80211_vif *vif,
               struct ieee80211_chanctx_conf *ctx)
{
    struct ath10k *ar = hw->priv;
    struct ath10k_vif *arvif = (void *)vif->drv_priv;
    int ret;

    rte_spinlock_lock(&ar->conf_lock);

    ath10k_dbg(ar, ATH10K_DBG_MAC,
         "mac chanctx assign ptr %pK vdev_id %i\n",
         ctx, arvif->vdev_id);

    if (WARN_ON(arvif->is_started)) {
      rte_spinlock_unlock(&ar->conf_lock);
      return -EBUSY;
    }

    ret = ath10k_vdev_start(arvif, &ctx->def);
    if (ret) {
      ath10k_warn(ar, "failed to start vdev %i addr %pM on freq %d: %d\n",
              arvif->vdev_id, vif->addr,
              ctx->def.chan->center_freq, ret);
      goto err;
    }

    arvif->is_started = true;

    ret = ath10k_mac_vif_setup_ps(arvif);
    if (ret) {
      ath10k_warn(ar, "failed to update vdev %i ps: %d\n",
              arvif->vdev_id, ret);
      goto err_stop;
    }

    if (vif->type == NL80211_IFTYPE_MONITOR) {
      ret = ath10k_wmi_vdev_up(ar, arvif->vdev_id, 0, vif->addr);
      if (ret) {
          ath10k_warn(ar, "failed to up monitor vdev %i: %d\n",
                  arvif->vdev_id, ret);
          goto err_stop;
      }

      arvif->is_up = true;
    }

    if (ath10k_mac_can_set_cts_prot(arvif)) {
        ret = ath10k_mac_set_cts_prot(arvif);
        if (ret)
            ath10k_warn(ar, "failed to set cts protection for vdev %d: %d\n",
                    arvif->vdev_id, ret);
    }

    rte_spinlock_unlock(&ar->conf_lock);
    return 0;

    err_stop:
    ath10k_vdev_stop(arvif);
    arvif->is_started = false;
    ath10k_mac_vif_setup_ps(arvif);

    err:
    rte_spinlock_unlock(&ar->conf_lock);
    return ret;
}

 static int ath10k_mac_setup_bcn_p2p_ie(struct ath10k_vif *arvif,
                     struct sk_buff *bcn)
{
    struct ath10k *ar = arvif->ar;
    struct ieee80211_mgmt *mgmt;
    const u8 *p2p_ie;
    int ret;

    if (arvif->vif->type != NL80211_IFTYPE_AP || !arvif->vif->p2p)
      return 0;

    mgmt = (void *)skb_data(bcn);
    p2p_ie = cfg80211_find_vendor_ie(WLAN_OUI_WFA, WLAN_OUI_TYPE_WFA_P2P,
                   mgmt->u.beacon.variable,
                   skb_len(bcn) - (uint16_t)(mgmt->u.beacon.variable)); // TODO: after "mgmt->u.beacon.variable" was " - skb_data(bcn)" but it makes absolutely no sense
    if (!p2p_ie)
      return -ENOENT;

    ret = ath10k_wmi_p2p_go_bcn_ie(ar, arvif->vdev_id, p2p_ie);
    if (ret) {
      ath10k_warn(ar, "failed to submit p2p go bcn ie for vdev %i: %d\n",
              arvif->vdev_id, ret);
      return ret;
    }

    return 0;
}

 static int ath10k_mac_remove_vendor_ie(struct sk_buff *skb, unsigned int oui,
                     u8 oui_type, size_t ie_offset)
{
    size_t len;
    const u8 *next;
    const u8 *end;
    u8 *ie;

    if(skb->data_len < ie_offset) {
        RTE_LOG(WARNING, PMD, "DRIVER: skb->len < ie_offset\n");
        return -EINVAL;
    }

    ie = (u8 *)cfg80211_find_vendor_ie(oui, oui_type,
                     skb_data(skb) + ie_offset,
                     skb_len(skb) - ie_offset);
    if (!ie)
      return -ENOENT;

    len = ie[1] + 2;
    end = skb_data(skb) + skb_len(skb);
    next = ie + len;

    if(next > end) {
        RTE_LOG(WARNING, PMD, "DRIVER: next > end\n");
        return -EINVAL;
    }

    memmove(ie, next, end - next);
    skb_trim(skb, skb->data_len - len);

    return 0;
}

static int ath10k_mac_setup_bcn_tmpl(struct ath10k_vif *arvif)
{
    struct ath10k *ar = arvif->ar;
    struct ieee80211_hw *hw = ar->hw;
    struct ieee80211_vif *vif = arvif->vif;
    struct ieee80211_mutable_offsets offs = {};
    struct sk_buff *bcn;
    int ret;

    if (!test_bit(WMI_SERVICE_BEACON_OFFLOAD, ar->wmi.svc_map))
      return 0;

    if (arvif->vdev_type != WMI_VDEV_TYPE_AP &&
      arvif->vdev_type != WMI_VDEV_TYPE_IBSS)
      return 0;

    // rte_spinlock_lock(&ar->mpool_lock);
    bcn = ieee80211_beacon_get_template(ar->mpool, hw, vif, &offs);
    // rte_spinlock_unlock(&ar->mpool_lock);
    if (!bcn) {
      ath10k_warn(ar, "failed to get beacon template from mac80211\n");
      return -EPERM;
    }

    ret = ath10k_mac_setup_bcn_p2p_ie(arvif, bcn);
    if (ret) {
      ath10k_warn(ar, "failed to setup p2p go bcn ie: %d\n", ret);
      ath10k_free_mbuf(ar, bcn);
      return ret;
    }

    /* P2P IE is inserted by firmware automatically (as configured above)
    * so remove it from the base beacon template to avoid duplicate P2P
    * IEs in beacon frames.
    */
    ath10k_mac_remove_vendor_ie(bcn, WLAN_OUI_WFA, WLAN_OUI_TYPE_WFA_P2P,
                  offsetof(struct ieee80211_mgmt,
                       u.beacon.variable));

    // printf("Setup beacon template!!!\n");
    ret = ath10k_wmi_bcn_tmpl(ar, arvif->vdev_id, offs.tim_offset, bcn, 0,
                0, NULL, 0);
    ath10k_free_mbuf(ar, bcn);

    if (ret) {
      ath10k_warn(ar, "failed to submit beacon template command: %d\n",
              ret);
      return ret;
    }

    return 0;
}

static int ath10k_mac_setup_prb_tmpl(struct ath10k_vif *arvif)
{
    struct ath10k *ar = arvif->ar;
    struct ieee80211_hw *hw = ar->hw;
    struct ieee80211_vif *vif = arvif->vif;
    struct sk_buff *prb;
    int ret;

    if (!test_bit(WMI_SERVICE_BEACON_OFFLOAD, ar->wmi.svc_map))
      return 0;

    if (arvif->vdev_type != WMI_VDEV_TYPE_AP)
      return 0;

    // rte_spinlock_lock(&ar->mpool_lock);
    prb = ieee80211_proberesp_get(ar->mpool, hw, vif);
    // rte_spinlock_unlock(&ar->mpool_lock);
    if (!prb) {
      ath10k_warn(ar, "failed to get probe resp template from mac80211\n");
      return -EPERM;
    }

    ret = ath10k_wmi_prb_tmpl(ar, arvif->vdev_id, prb);
    ath10k_free_mbuf(ar, prb);

    if (ret) {
      ath10k_warn(ar, "failed to submit probe resp template command: %d\n",
              ret);
      return ret;
    }

    return 0;
}

static void ath10k_mac_vif_ap_csa_count_down(struct ath10k_vif *arvif)
{
    struct ath10k *ar = arvif->ar;
    struct ieee80211_vif *vif = arvif->vif;
    int ret;

    // lockdep_assert_held(&arvif->ar->conf_lock);

    if (WARN_ON(!test_bit(WMI_SERVICE_BEACON_OFFLOAD, ar->wmi.svc_map)))
      return;

    if (arvif->vdev_type != WMI_VDEV_TYPE_AP)
      return;

    if (!vif->csa_active)
      return;

    if (!arvif->is_up)
      return;

    if (!ieee80211_csa_is_complete(vif)) {
      ieee80211_csa_update_counter(vif);

      ret = ath10k_mac_setup_bcn_tmpl(arvif);
      if (ret)
          ath10k_warn(ar, "failed to update bcn tmpl during csa: %d\n",
                  ret);

      ret = ath10k_mac_setup_prb_tmpl(arvif);
      if (ret)
          ath10k_warn(ar, "failed to update prb tmpl during csa: %d\n",
                  ret);
    } else {
      ieee80211_csa_finish(vif);
    }
}

static void ath10k_mac_vif_ap_csa_work(struct work_struct *work)
{
    struct ath10k_vif *arvif = container_of(work, struct ath10k_vif,
                      ap_csa_work);
    struct ath10k *ar = arvif->ar;

    ath10k_mac_vif_ap_csa_count_down(arvif);
}

static void ath10k_mac_vif_sta_connection_loss_work(struct work_struct *work)
{
    struct ath10k_vif *arvif = container_of(work, struct ath10k_vif,
                      connection_loss_work.work);
    struct ieee80211_vif *vif = arvif->vif;

    if (!arvif->is_up)
      return;

    ieee80211_connection_loss(vif);
}

static int ath10k_mac_vif_disable_keepalive(struct ath10k_vif *arvif)
{
    struct ath10k *ar = arvif->ar;
    struct wmi_sta_keepalive_arg arg = {};
    int ret;

    // lockdep_assert_held(&arvif->ar->conf_lock);

    if (arvif->vdev_type != WMI_VDEV_TYPE_STA)
        return 0;

    if (!test_bit(WMI_SERVICE_STA_KEEP_ALIVE, ar->wmi.svc_map))
        return 0;

    /* Some firmware revisions have a bug and ignore the `enabled` field.
     * Instead use the interval to disable the keepalive.
     */
    arg.vdev_id = arvif->vdev_id;
    arg.enabled = 1;
    arg.method = WMI_STA_KEEPALIVE_METHOD_NULL_FRAME;
    arg.interval = WMI_STA_KEEPALIVE_INTERVAL_DISABLE;

    ret = ath10k_wmi_sta_keepalive(ar, &arg);
    if (ret) {
        ath10k_warn(ar, "failed to submit keepalive on vdev %i: %d\n",
                arvif->vdev_id, ret);
        return ret;
    }

    return 0;
}

static u32 get_nss_from_chainmask(u16 chain_mask)
{
    if ((chain_mask & 0xf) == 0xf)
        return 4;
    else if ((chain_mask & 0x7) == 0x7)
        return 3;
    else if ((chain_mask & 0x3) == 0x3)
        return 2;
    return 1;
}

static int ath10k_mac_set_kickout(struct ath10k_vif *arvif)
{
    struct ath10k *ar = arvif->ar;
    u32 param;
    int ret;

    param = ar->wmi.pdev_param->sta_kickout_th;
    ret = ath10k_wmi_pdev_set_param(ar, param,
                    ATH10K_KICKOUT_THRESHOLD);
    if (ret) {
        ath10k_warn(ar, "failed to set kickout threshold on vdev %i: %d\n",
                arvif->vdev_id, ret);
        return ret;
    }

    param = ar->wmi.vdev_param->ap_keepalive_min_idle_inactive_time_secs;
    ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, param,
                    ATH10K_KEEPALIVE_MIN_IDLE);
    if (ret) {
        ath10k_warn(ar, "failed to set keepalive minimum idle time on vdev %i: %d\n",
                arvif->vdev_id, ret);
        return ret;
    }

    param = ar->wmi.vdev_param->ap_keepalive_max_idle_inactive_time_secs;
    ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, param,
                    ATH10K_KEEPALIVE_MAX_IDLE);
    if (ret) {
        ath10k_warn(ar, "failed to set keepalive maximum idle time on vdev %i: %d\n",
                arvif->vdev_id, ret);
        return ret;
    }

    param = ar->wmi.vdev_param->ap_keepalive_max_unresponsive_time_secs;
    ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, param,
                    ATH10K_KEEPALIVE_MAX_UNRESPONSIVE);
    if (ret) {
        ath10k_warn(ar, "failed to set keepalive maximum unresponsive time on vdev %i: %d\n",
                arvif->vdev_id, ret);
        return ret;
    }

    return 0;
}

 static int ath10k_mac_vif_recalc_ps_wake_threshold(struct ath10k_vif *arvif)
 {
    struct ath10k *ar = arvif->ar;
    u32 param;
    u32 value;
    int ret;

    lockdep_assert_held(&arvif->ar->conf_lock);

    if (arvif->u.sta.uapsd)
        value = WMI_STA_PS_TX_WAKE_THRESHOLD_NEVER;
    else
        value = WMI_STA_PS_TX_WAKE_THRESHOLD_ALWAYS;

    param = WMI_STA_PS_PARAM_TX_WAKE_THRESHOLD;
    // ret = ath10k_wmi_set_sta_ps_param(ar, arvif->vdev_id, param, value);
    // if (ret) {
    //     ath10k_warn(ar, "failed to submit ps wake threshold %u on vdev %i: %d\n",
    //           value, arvif->vdev_id, ret);
    //     return ret;
    // }

    return 0;
 }

static int ath10k_mac_vif_recalc_ps_poll_count(struct ath10k_vif *arvif)
{
    struct ath10k *ar = arvif->ar;
    u32 param;
    u32 value;
    int ret;

    lockdep_assert_held(&arvif->ar->conf_lock);

    if (arvif->u.sta.uapsd)
        value = WMI_STA_PS_PSPOLL_COUNT_UAPSD;
    else
        value = WMI_STA_PS_PSPOLL_COUNT_NO_MAX;

    param = WMI_STA_PS_PARAM_PSPOLL_COUNT;
    // ret = ath10k_wmi_set_sta_ps_param(ar, arvif->vdev_id,
    //                  param, value);
    // if (ret) {
    //     ath10k_warn(ar, "failed to submit ps poll count %u on vdev %i: %d\n",
    //            value, arvif->vdev_id, ret);
    //     return ret;
    // }

    return 0;
}

static int ath10k_mac_set_txbf_conf(struct ath10k_vif *arvif)
{
    u32 value = 0;
    struct ath10k *ar = arvif->ar;
    int nsts;
    int sound_dim;

    if (ath10k_wmi_get_txbf_conf_scheme(ar) != WMI_TXBF_CONF_BEFORE_ASSOC)
        return 0;

    nsts = ath10k_mac_get_vht_cap_bf_sts(ar);
    if (ar->vht_cap_info & (IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE |
                IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE))
        value |= SM(nsts, WMI_TXBF_STS_CAP_OFFSET);

    sound_dim = ath10k_mac_get_vht_cap_bf_sound_dim(ar);
    if (ar->vht_cap_info & (IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE |
                IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE))
        value |= SM(sound_dim, WMI_BF_SOUND_DIM_OFFSET);

    if (!value)
        return 0;

    if (ar->vht_cap_info & IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE)
        value |= WMI_VDEV_PARAM_TXBF_SU_TX_BFER;

    if (ar->vht_cap_info & IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE)
        value |= (WMI_VDEV_PARAM_TXBF_MU_TX_BFER |
              WMI_VDEV_PARAM_TXBF_SU_TX_BFER);

    if (ar->vht_cap_info & IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE)
        value |= WMI_VDEV_PARAM_TXBF_SU_TX_BFEE;

    if (ar->vht_cap_info & IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE)
        value |= (WMI_VDEV_PARAM_TXBF_MU_TX_BFEE |
              WMI_VDEV_PARAM_TXBF_SU_TX_BFEE);

    return ath10k_wmi_vdev_set_param(ar, arvif->vdev_id,
                     ar->wmi.vdev_param->txbf, value);
}

static int ath10k_mac_set_rts(struct ath10k_vif *arvif, u32 value)
{
    struct ath10k *ar = arvif->ar;
    u32 vdev_param;

    vdev_param = ar->wmi.vdev_param->rts_threshold;
    return ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, value);
}

static int ath10k_mac_txpower_setup(struct ath10k *ar, int txpower)
{
    int ret;
    u32 param;

    lockdep_assert_held(&ar->conf_lock);

    ath10k_dbg(ar, ATH10K_DBG_MAC, "mac txpower %d\n", txpower);

    param = ar->wmi.pdev_param->txpower_limit2g;
    ret = ath10k_wmi_pdev_set_param(ar, param, txpower * 2);
    if (ret) {
        ath10k_warn(ar, "failed to set 2g txpower %d: %d\n",
              txpower, ret);
        return ret;
    }

    param = ar->wmi.pdev_param->txpower_limit5g;
    ret = ath10k_wmi_pdev_set_param(ar, param, txpower * 2);
    if (ret) {
        ath10k_warn(ar, "failed to set 5g txpower %d: %d\n",
              txpower, ret);
        return ret;
    }

    return 0;
}

static int ath10k_mac_txpower_recalc(struct ath10k *ar)
{
    struct ath10k_vif *arvif;
    int ret, txpower = -1;

    lockdep_assert_held(&ar->conf_lock);

    LIST_FOREACH(arvif, &ar->arvifs, pointers) {
        if(arvif->txpower <= 0) {
            RTE_LOG(WARNING, PMD, "negative TX power: %d\n", arvif->txpower);
            continue;
        }

        if (txpower == -1)
            txpower = arvif->txpower;
        else
            txpower = min_t(int, txpower, arvif->txpower);
    }

    if (txpower == -1) {
        RTE_LOG(WARNING, PMD, "TX power == -1\n");
        return 0;
    }

    ret = ath10k_mac_txpower_setup(ar, txpower);
    if (ret) {
        ath10k_warn(ar, "failed to setup tx power %d: %d\n", txpower, ret);
        return ret;
    }
    return 0;
}

/*
 * TODO:
 * Figure out how to handle WMI_VDEV_SUBTYPE_P2P_DEVICE,
 * because we will send mgmt frames without CCK. This requirement
 * for P2P_FIND/GO_NEG should be handled by checking CCK flag
 * in the TX packet.
 */
static int eth_ath10k_add_interface(struct ieee80211_hw *hw,
                struct ieee80211_vif *vif)
{
    struct ath10k *ar = hw->priv;
    struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
    struct ath10k_peer *peer;
    enum wmi_sta_powersave_param param;
    int ret = 0;
    u32 value;
    int bit;
    int i;
    u32 vdev_param;

    // vif->driver_flags |= IEEE80211_VIF_SUPPORTS_UAPSD;

    rte_spinlock_lock(&ar->conf_lock);

    memset(arvif, 0, sizeof(struct ath10k_vif));
    // ath10k_mac_txq_init(vif->txq);

    arvif->ar = ar;
    arvif->vif = vif;

    // INIT_LIST_HEAD(&arvif->list);
    task_create(&arvif->ap_csa_work, ath10k_mac_vif_ap_csa_work);
    // INIT_DELAYED_WORK(&arvif->connection_loss_work, ath10k_mac_vif_sta_connection_loss_work);
    task_create(&arvif->connection_loss_work, ath10k_mac_vif_sta_connection_loss_work);

    for (i = 0; i < ARRAY_SIZE(arvif->bitrate_mask.control); i++) {
        arvif->bitrate_mask.control[i].legacy = 0xffffffff;
        memset(arvif->bitrate_mask.control[i].ht_mcs, 0xff,
               sizeof(arvif->bitrate_mask.control[i].ht_mcs));
        memset(arvif->bitrate_mask.control[i].vht_mcs, 0xff,
               sizeof(arvif->bitrate_mask.control[i].vht_mcs));
    }

    if (ar->num_peers >= ar->max_num_peers) {
        ath10k_warn(ar, "refusing vdev creation due to insufficient peer entry resources in firmware\n  - num_peers: %d; max_num_peers: %d\n", ar->num_peers, ar->max_num_peers);
        ret = -ENOBUFS;
        goto err;
    }

    if (ar->free_vdev_map == 0) {
        ath10k_warn(ar, "Free vdev map is empty, no more interfaces allowed.\n");
        ret = -EBUSY;
        goto err;
    }
    bit = __ffs64(ar->free_vdev_map);

    ath10k_dbg(ar, ATH10K_DBG_MAC, "mac create vdev %i map %llx\n",
           bit, ar->free_vdev_map);

    arvif->vdev_id = bit;
    // arvif->vdev_id = 0;
    arvif->vdev_subtype =
        ath10k_wmi_get_vdev_subtype(ar, WMI_VDEV_SUBTYPE_NONE);

    switch (vif->type) {
        case NL80211_IFTYPE_P2P_DEVICE:
          arvif->vdev_type = WMI_VDEV_TYPE_STA;
          arvif->vdev_subtype = ath10k_wmi_get_vdev_subtype
                      (ar, WMI_VDEV_SUBTYPE_P2P_DEVICE);
          break;
        case NL80211_IFTYPE_UNSPECIFIED:
        case NL80211_IFTYPE_STATION:
          RTE_LOG(WARNING, PMD, "WMI_VDEV_TYPE_STATION_UNSPEC\n");
          arvif->vdev_type = WMI_VDEV_TYPE_STA;
          if (vif->p2p)
              arvif->vdev_subtype = ath10k_wmi_get_vdev_subtype
                      (ar, WMI_VDEV_SUBTYPE_P2P_CLIENT);
          break;
        case NL80211_IFTYPE_ADHOC:
            RTE_LOG(WARNING, PMD, "WMI_VDEV_TYPE_IBSS\n");
            arvif->vdev_type = WMI_VDEV_TYPE_IBSS;
            break;
        case NL80211_IFTYPE_MESH_POINT:
          if (test_bit(WMI_SERVICE_MESH_11S, ar->wmi.svc_map)) {
              arvif->vdev_subtype = ath10k_wmi_get_vdev_subtype
                          (ar, WMI_VDEV_SUBTYPE_MESH_11S);
          } else if (!test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags)) {
              ret = -EINVAL;
              ath10k_warn(ar, "must load driver with rawmode=1 to add mesh interfaces\n");
              goto err;
          }
          arvif->vdev_type = WMI_VDEV_TYPE_AP;
          break;
        case NL80211_IFTYPE_AP:
          arvif->vdev_type = WMI_VDEV_TYPE_AP;

          if (vif->p2p)
              arvif->vdev_subtype = ath10k_wmi_get_vdev_subtype
                          (ar, WMI_VDEV_SUBTYPE_P2P_GO);
          break;
        case NL80211_IFTYPE_MONITOR:
          arvif->vdev_type = WMI_VDEV_TYPE_MONITOR;
          break;
    default:
        RTE_LOG(WARNING, PMD, "vif->type invalid: %d\n", vif->type);
        break;
    }

    /* Using vdev_id as queue number will make it very easy to do per-vif
     * tx queue locking. This shouldn't wrap due to interface combinations
     * but do a modulo for correctness sake and prevent using offchannel tx
     * queues for regular vif tx.
     */
    vif->cab_queue = arvif->vdev_id % (IEEE80211_MAX_QUEUES - 1);
    for (i = 0; i < ARRAY_SIZE(vif->hw_queue); i++)
        vif->hw_queue[i] = arvif->vdev_id % (IEEE80211_MAX_QUEUES - 1);

    /* Some firmware revisions don't wait for beacon tx completion before
     * sending another SWBA event. This could lead to hardware using old
     * (freed) beacon data in some cases, e.g. tx credit starvation
     * combined with missed TBTT. This is very very rare.
     *
     * On non-IOMMU-enabled hosts this could be a possible security issue
     * because hw could beacon some random data on the air.  On
     * IOMMU-enabled hosts DMAR faults would occur in most cases and target
     * device would crash.
     *
     * Since there are no beacon tx completions (implicit nor explicit)
     * propagated to host the only workaround for this is to allocate a
     * DMA-coherent buffer for a lifetime of a vif and use it for all
     * beacon tx commands. Worst case for this approach is some beacons may
     * become corrupted, e.g. have garbled IEs or out-of-date TIM bitmap.
     */
    if (vif->type == NL80211_IFTYPE_ADHOC ||
          vif->type == NL80211_IFTYPE_MESH_POINT ||
          vif->type == NL80211_IFTYPE_AP) {
        // FIXME memory leak
        struct rte_memzone *tmp = dma_zalloc_coherent(ar, IEEE80211_MAX_FRAME_LEN, "beacon buf", 0, SOCKET_ID_ANY);
        arvif->beacon_buf = tmp->addr;
        arvif->beacon_paddr = tmp->phys_addr;
      if (!arvif->beacon_buf) {
          ret = -ENOMEM;
          ath10k_warn(ar, "failed to allocate beacon buffer: %d\n",
                  ret);
          goto err;
      }
      arvif->ap_csa_work.func(&arvif->ap_csa_work);
    }
    if (test_bit(ATH10K_FLAG_HW_CRYPTO_DISABLED, &ar->dev_flags))
      arvif->nohwcrypt = true;

    if (arvif->nohwcrypt &&
      !test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags)) {
      ath10k_warn(ar, "cryptmode module param needed for sw crypto\n");
      goto err;
    }

    ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev create %d (add interface) type %d subtype %d bcnmode %s\n",
           arvif->vdev_id, arvif->vdev_type, arvif->vdev_subtype,
           arvif->beacon_buf ? "single-buf" : "per-skb");

    ret = ath10k_wmi_vdev_create(ar, arvif->vdev_id, arvif->vdev_type,
                     arvif->vdev_subtype, vif->addr);
    if (ret) {
        ath10k_warn(ar, "failed to create WMI vdev %i: %d\n",
                arvif->vdev_id, ret);
        goto err;
    }

    ar->free_vdev_map &= ~(1LL << arvif->vdev_id);
    LIST_INSERT_HEAD(&ar->arvifs, arvif, pointers);

    /* It makes no sense to have firmware do keepalives. mac80211 already
    * takes care of this with idle connection polling.
    */
    // ret = ath10k_mac_vif_disable_keepalive(arvif);
    // if (ret) {
    //   ath10k_warn(ar, "failed to disable keepalive on vdev %i: %d\n",
    //           arvif->vdev_id, ret);
    //   goto err_vdev_delete;
    // }

    arvif->def_wep_key_idx = -1;

    vdev_param = ar->wmi.vdev_param->tx_encap_type;
    ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, ATH10K_HW_TXRX_NATIVE_WIFI);
    /* 10.X firmware does not support this VDEV parameter. Do not warn */
    if (ret && ret != -EOPNOTSUPP) {
      ath10k_warn(ar, "failed to set vdev %i TX encapsulation: %d\n",
              arvif->vdev_id, ret);
      goto err_vdev_delete;
    }

    /* Configuring number of spatial stream for monitor interface is causing
     * target assert in qca9888 and qca6174.
     */
    if (ar->cfg_tx_chainmask && (vif->type != NL80211_IFTYPE_MONITOR)) {
        u16 nss = get_nss_from_chainmask(ar->cfg_tx_chainmask);
        printf("Set nss to %d\n", nss);

        vdev_param = ar->wmi.vdev_param->nss;
        ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
                        nss);
        if (ret) {
            ath10k_warn(ar, "failed to set vdev %i chainmask 0x%x, nss %i: %d\n",
                    arvif->vdev_id, ar->cfg_tx_chainmask, nss,
                    ret);
            goto err_vdev_delete;
        }
    }

    if (arvif->vdev_type == WMI_VDEV_TYPE_AP ||
        arvif->vdev_type == WMI_VDEV_TYPE_IBSS) {
        ret = ath10k_peer_create(ar, vif, NULL, arvif->vdev_id,
                     vif->addr, WMI_PEER_TYPE_DEFAULT);
        if (ret) {
            ath10k_warn(ar, "failed to create vdev %i peer for AP/IBSS: %d\n",
                    arvif->vdev_id, ret);
            goto err_vdev_delete;
        }

     rte_spinlock_lock(&ar->data_lock);

        peer = ath10k_peer_find(ar, arvif->vdev_id, vif->addr);
        if (!peer) {
            ath10k_warn(ar, "failed to lookup peer %pM on vdev %i\n",
                    vif->addr, arvif->vdev_id);
            rte_spinlock_unlock(&ar->data_lock);
            ret = -ENOENT;
            goto err_peer_delete;
        }

        arvif->peer_id = find_first_bit(peer->peer_ids,
                     ATH10K_MAX_NUM_PEER_IDS);

        rte_spinlock_unlock(&ar->data_lock);
    } else {
        arvif->peer_id = HTT_INVALID_PEERID;
    }

  if (arvif->vdev_type == WMI_VDEV_TYPE_AP) {
      ret = ath10k_mac_set_kickout(arvif);
      if (ret) {
          ath10k_warn(ar, "failed to set vdev %i kickout parameters: %d\n",
                  arvif->vdev_id, ret);
          goto err_peer_delete;
      }
  }

  if (arvif->vdev_type == WMI_VDEV_TYPE_STA) {
      param = WMI_STA_PS_PARAM_RX_WAKE_POLICY;
      value = WMI_STA_PS_RX_WAKE_POLICY_WAKE;
      ret = ath10k_wmi_set_sta_ps_param(ar, arvif->vdev_id,
                        param, value);
      if (ret) {
          ath10k_warn(ar, "failed to set vdev %i RX wake policy: %d\n",
                  arvif->vdev_id, ret);
          goto err_peer_delete;
      }

      ret = ath10k_mac_vif_recalc_ps_wake_threshold(arvif);
      if (ret) {
          ath10k_warn(ar, "failed to recalc ps wake threshold on vdev %i: %d\n",
                  arvif->vdev_id, ret);
          goto err_peer_delete;
      }

      ret = ath10k_mac_vif_recalc_ps_poll_count(arvif);
      if (ret) {
          ath10k_warn(ar, "failed to recalc ps poll count on vdev %i: %d\n",
                  arvif->vdev_id, ret);
          goto err_peer_delete;
      }
  }

    ret = ath10k_mac_set_txbf_conf(arvif);
    if (ret) {
        ath10k_warn(ar, "failed to set txbf for vdev %d: %d\n",
                arvif->vdev_id, ret);
        goto err_peer_delete;
    }

    // ret = ath10k_mac_set_rts(arvif, 2346); //ar->hw->wiphy->rts_threshold);
    // if (ret) {
    //     ath10k_warn(ar, "failed to set rts threshold for vdev %d: %d\n", arvif->vdev_id, ret);
    //     goto err_peer_delete;
    // }

    arvif->txpower = vif->bss_conf.txpower;
    ret = ath10k_mac_txpower_recalc(ar);
    if (ret) {
      ath10k_warn(ar, "failed to recalc tx power: %d\n", ret);
      goto err_peer_delete;
    }

    if (vif->type == NL80211_IFTYPE_MONITOR) {
      ar->monitor_arvif = arvif;
      ret = ath10k_monitor_recalc(ar);
      if (ret) {
          ath10k_warn(ar, "failed to recalc monitor: %d\n", ret);
          goto err_peer_delete;
      }
    }

    rte_spinlock_lock(&ar->htt.tx_lock);
    if (!ar->tx_paused)
      ieee80211_wake_queue(ar->hw, arvif->vdev_id);
    rte_spinlock_unlock(&ar->htt.tx_lock);

    rte_spinlock_unlock(&ar->conf_lock);
    return 0;

err_peer_delete:
    if (arvif->vdev_type == WMI_VDEV_TYPE_AP ||
        arvif->vdev_type == WMI_VDEV_TYPE_IBSS)
        ath10k_wmi_peer_delete(ar, arvif->vdev_id, vif->addr);

err_vdev_delete:
    ath10k_wmi_vdev_delete(ar, arvif->vdev_id);
    ar->free_vdev_map |= 1LL << arvif->vdev_id;
    LIST_REMOVE(arvif, pointers);

err:
    if (arvif->beacon_buf) {
      dma_free_coherent(ar, arvif->beacon_buf);
      arvif->beacon_buf = NULL;
    }

    rte_spinlock_unlock(&ar->conf_lock);

    return ret;
}

void eth_ath10k_set_hw_ptrs(struct ieee80211_hw *hw, void *dev_private) {
    struct ath10k_adapter *adapter = ATH10K_DEV_PRIVATE(dev_private);
    hw->priv = adapter->ar;
    adapter->ar->hw = hw;
}

int eth_ath10k_init_vif_priv(struct ieee80211_vif *vif, void *dev_private) {
    vif->drv_priv = rte_zmalloc("ar_vif template", sizeof(struct ath10k_vif), 0);
    if (vif->drv_priv == NULL)
        return -1;
    ether_addr_copy(ATH10K_DEV_PRIVATE(dev_private)->ar->mac_addr, vif->addr);
    return 0;
}

void eth_ath10k_get_mac_addr(struct vif_params* params, void *dev_private) {
    ether_addr_copy(ATH10K_DEV_PRIVATE(dev_private)->ar->mac_addr, params->macaddr);
}

int eth_ath10k_mac_register(void *dev_private) {
    ath10k_mac_register(ATH10K_DEV_PRIVATE(dev_private)->ar);
}

static void ath10k_control_beaconing(struct ath10k_vif *arvif,
                    struct ieee80211_bss_conf *info)
  {
   struct ath10k *ar = arvif->ar;
   int ret = 0;

  lockdep_assert_held(&arvif->ar->conf_lock);

   if (!info->enable_beacon) {
       ret = ath10k_wmi_vdev_down(ar, arvif->vdev_id);
       if (ret)
           ath10k_warn(ar, "failed to down vdev_id %i: %d\n",
                   arvif->vdev_id, ret);

       arvif->is_up = false;

       rte_spinlock_lock(&arvif->ar->data_lock);
       ath10k_mac_vif_beacon_free(arvif);
       rte_spinlock_unlock(&arvif->ar->data_lock);

       return;
   }

   arvif->tx_seq_no = 0x1000;

   arvif->aid = 0;
   ether_addr_copy(info->bssid, arvif->bssid);

   ret = ath10k_wmi_vdev_up(arvif->ar, arvif->vdev_id, arvif->aid,
                arvif->bssid);
   if (ret) {
       ath10k_warn(ar, "failed to bring up vdev %d: %i\n",
               arvif->vdev_id, ret);
       return;
   }

   arvif->is_up = true;

//   ret = ath10k_mac_vif_fix_hidden_ssid(arvif);
//   if (ret) {
//       ath10k_warn(ar, "failed to fix hidden ssid for vdev %i, expect trouble: %d\n",
//               arvif->vdev_id, ret);
//       return;
//   }

    ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d up\n", arvif->vdev_id);
  }

 static void ath10k_bss_info_changed(struct ieee80211_hw *hw,
                  struct ieee80211_vif *vif,
                  struct ieee80211_bss_conf *info,
                  u32 changed)
 {
  struct ath10k *ar = hw->priv;
  struct ath10k_vif *arvif = ath10k_vif_to_arvif(vif);
  int ret = 0;
  u32 vdev_param, pdev_param, slottime, preamble;

  rte_spinlock_lock(&ar->conf_lock);

  if (changed & BSS_CHANGED_IBSS)
     ath10k_control_ibss(arvif, info, vif->addr);

  if (changed & BSS_CHANGED_BEACON_INT) {
      arvif->beacon_interval = info->beacon_int;
      vdev_param = ar->wmi.vdev_param->beacon_interval;
      ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
                      arvif->beacon_interval);
      ath10k_dbg(ar, ATH10K_DBG_MAC,
             "mac vdev %d beacon_interval %d\n",
             arvif->vdev_id, arvif->beacon_interval);

      if (ret)
          ath10k_warn(ar, "failed to set beacon interval for vdev %d: %i\n",
                  arvif->vdev_id, ret);
  }

  if (changed & BSS_CHANGED_BEACON) {
      ath10k_dbg(ar, ATH10K_DBG_MAC,
             "vdev %d set beacon tx mode to staggered\n",
             arvif->vdev_id);
      pdev_param = ar->wmi.pdev_param->beacon_tx_mode;
      ret = ath10k_wmi_pdev_set_param(ar, pdev_param,
                      WMI_BEACON_STAGGERED_MODE);
      if (ret)
          ath10k_warn(ar, "failed to set beacon mode for vdev %d: %i\n",
                  arvif->vdev_id, ret);

      ret = ath10k_mac_setup_bcn_tmpl(arvif);
      if (ret)
          ath10k_warn(ar, "failed to update beacon template: %d\n",
                  ret);

      if (ieee80211_vif_is_mesh(vif)) {
          /* mesh doesn't use SSID but firmware needs it */
          strncpy(arvif->u.ap.ssid, "mesh",
              sizeof(arvif->u.ap.ssid));
          arvif->u.ap.ssid_len = 4;
      }
  }

 if (changed & BSS_CHANGED_AP_PROBE_RESP) {
     ret = ath10k_mac_setup_prb_tmpl(arvif);
     if (ret)
         ath10k_warn(ar, "failed to setup probe resp template on vdev %i: %d\n",
                 arvif->vdev_id, ret);
 }

  if (changed & (BSS_CHANGED_BEACON_INFO | BSS_CHANGED_BEACON)) {
      arvif->dtim_period = info->dtim_period;

      ath10k_dbg(ar, ATH10K_DBG_MAC,
             "mac vdev %d dtim_period %d\n",
             arvif->vdev_id, arvif->dtim_period);

      vdev_param = ar->wmi.vdev_param->dtim_period;
      ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
                      arvif->dtim_period);
      if (ret)
          ath10k_warn(ar, "failed to set dtim period for vdev %d: %i\n",
                  arvif->vdev_id, ret);
  }

 if (changed & BSS_CHANGED_SSID &&
     vif->type == NL80211_IFTYPE_AP) {
     arvif->u.ap.ssid_len = info->ssid_len;
     if (info->ssid_len)
         rte_memcpy(arvif->u.ap.ssid, info->ssid, info->ssid_len);
     arvif->u.ap.hidden_ssid = info->hidden_ssid;
 }

 if (changed & BSS_CHANGED_BSSID && !is_zero_ether_addr(info->bssid))
     ether_addr_copy(info->bssid, arvif->bssid);

  if (changed & BSS_CHANGED_BEACON_ENABLED)
      ath10k_control_beaconing(arvif, info);

 if (changed & BSS_CHANGED_ERP_CTS_PROT) {
     arvif->use_cts_prot = info->use_cts_prot;
     ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d cts_prot %d\n",
            arvif->vdev_id, info->use_cts_prot);

     ret = ath10k_recalc_rtscts_prot(arvif);
     if (ret)
         ath10k_warn(ar, "failed to recalculate rts/cts prot for vdev %d: %d\n",
                 arvif->vdev_id, ret);

//     vdev_param = ar->wmi.vdev_param->protection_mode;
//     // ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
//     //                 info->use_cts_prot ? 1 : 0);
//    ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, 0);
//     if (ret)
//         ath10k_warn(ar, "failed to set protection mode %d on vdev %i: %d\n",
//                 info->use_cts_prot, arvif->vdev_id, ret);
     if (ath10k_mac_can_set_cts_prot(arvif)) {
         ret = ath10k_mac_set_cts_prot(arvif);
         if (ret)
             ath10k_warn(ar, "failed to set cts protection for vdev %d: %d\n",
                     arvif->vdev_id, ret);
     }
 }

 if (changed & BSS_CHANGED_ERP_SLOT) {
     if (info->use_short_slot)
         slottime = WMI_VDEV_SLOT_TIME_SHORT; /* 9us */

     else
         slottime = WMI_VDEV_SLOT_TIME_LONG; /* 20us */

     ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev %d slot_time %d\n",
            arvif->vdev_id, slottime);

     vdev_param = ar->wmi.vdev_param->slot_time;
     ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
                     slottime);
     if (ret)
         ath10k_warn(ar, "failed to set erp slot for vdev %d: %i\n",
                 arvif->vdev_id, ret);
 }

 if (changed & BSS_CHANGED_ERP_PREAMBLE) {
     if (info->use_short_preamble)
         preamble = WMI_VDEV_PREAMBLE_SHORT;
     else
         preamble = WMI_VDEV_PREAMBLE_LONG;

     ath10k_dbg(ar, ATH10K_DBG_MAC,
            "mac vdev %d preamble %d\n",
            arvif->vdev_id, preamble);

     vdev_param = ar->wmi.vdev_param->preamble;
     ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
                     preamble);
     if (ret)
         ath10k_warn(ar, "failed to set preamble for vdev %d: %i\n",
                 arvif->vdev_id, ret);
 }

 // if (changed & BSS_CHANGED_ASSOC) {
 //     if (info->assoc) {
 //          Workaround: Make sure monitor vdev is not running
 //          * when associating to prevent some firmware revisions
 //          * (e.g. 10.1 and 10.2) from crashing.

 //         if (ar->monitor_started)
 //             ath10k_monitor_stop(ar);
 //         ath10k_bss_assoc(hw, vif, info);
 //         ath10k_monitor_recalc(ar);
 //     } else {
 //         ath10k_bss_disassoc(hw, vif);
 //     }
 // }

 if (changed & BSS_CHANGED_TXPOWER) {
     ath10k_dbg(ar, ATH10K_DBG_MAC, "mac vdev_id %i txpower %d\n",
            arvif->vdev_id, info->txpower);

     arvif->txpower = info->txpower;
     ret = ath10k_mac_txpower_recalc(ar);
     if (ret)
         ath10k_warn(ar, "failed to recalc tx power: %d\n", ret);
 }

 // if (changed & BSS_CHANGED_PS) {
 //     arvif->ps = vif->bss_conf.ps;

 //     ret = ath10k_config_ps(ar);
 //     if (ret)
 //         ath10k_warn(ar, "failed to setup ps on vdev %i: %d\n",
 //                 arvif->vdev_id, ret);
 // }

    // u32 rts_cts = 17;
    u32 rts_cts = 0;
    vdev_param = ar->wmi.vdev_param->enable_rtscts;
    ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param,
                     rts_cts);

    ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, ar->wmi.vdev_param->slot_time, WMI_VDEV_SLOT_TIME_SHORT);
    ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, ar->wmi.vdev_param->preamble, WMI_VDEV_PREAMBLE_SHORT);

    // vdev_param = ar->wmi.vdev_param->protection_mode;
    // ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, 0);

    // pdev_param = ar->wmi.pdev_param->rx_filter;
    // ret = ath10k_wmi_pdev_set_param(ar, pdev_param, 0);

    // vdev_param = WMI_10_4_VDEV_PARAM_RX_FILTER;
    // ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, 0);

    // if (ret)
    //     ath10k_warn(ar, "failed to disable protection mode on vdev %i: %d\n", arvif->vdev_id, ret);

    rte_spinlock_unlock(&ar->conf_lock);
}

 // static void ath10k_mac_op_wake_tx_queue(struct ieee80211_hw *hw,
 //                    struct ieee80211_txq *txq)
 // {
 //    struct ath10k *ar = hw->priv;
 //    struct ath10k_txq *artxq = (void *)txq->drv_priv;
 //    struct ieee80211_txq *f_txq;
 //    struct ath10k_txq *f_artxq;
 //    int ret = 0;
 //    int max = 16;

 //    rte_spinlock_lock(&ar->txqs_lock);
 //    // if (list_empty(&artxq->list))
 //    //  list_add_tail(&artxq->list, &ar->txqs); // new, head

 //    // TODO: check if porting concerning those lists did not mess up anything
 //    if(artxq->pointers.tqe_next == NULL && artxq->pointers.tqe_prev == NULL) { // should mean: element is not yet in the list
 //        TAILQ_INSERT_TAIL(&ar->txqs, artxq, pointers);
 //    }

 //    // f_artxq = list_first_entry(&ar->txqs, struct ath10k_txq, list);
 //    f_artxq = TAILQ_FIRST(&ar->txqs);
 //    f_txq = container_of((void *)f_artxq, struct ieee80211_txq, drv_priv);
 //    // list_del_init(&f_artxq->list);
 //    TAILQ_REMOVE(&ar->txqs, f_artxq, pointers);

 //    while (ath10k_mac_tx_can_push(hw, f_txq) && max--) {
 //        ret = ath10k_mac_tx_push_txq(hw, f_txq);
 //        if (ret)
 //            break;
 //    }
 //    if (ret != -ENOENT)
 //        // list_add_tail(&f_artxq->list, &ar->txqs);
 //        TAILQ_INSERT_TAIL(&ar->txqs, f_artxq, pointers);
 //    rte_spinlock_unlock(&ar->txqs_lock);

 //    ath10k_htt_tx_txq_update(hw, f_txq);
 //    ath10k_htt_tx_txq_update(hw, txq);
 // }

const struct ieee80211_ops eth_ath10k_80211_ops = {
    //.tx             = ath10k_mac_op_tx,
    // .wake_tx_queue          = ath10k_mac_op_wake_tx_queue,
    //.start              = ath10k_start,
    //.stop               = ath10k_stop,
    //.config             = ath10k_config,
    .add_interface          = eth_ath10k_add_interface,
    //.remove_interface       = ath10k_remove_interface,
    //.configure_filter       = ath10k_configure_filter,
    .bss_info_changed       = ath10k_bss_info_changed,
    //.hw_scan            = ath10k_hw_scan,
    //.cancel_hw_scan         = ath10k_cancel_hw_scan,
    //.set_key            = ath10k_set_key,
    //.set_default_unicast_key        = ath10k_set_default_unicast_key,
    // .sta_state          = ath10k_sta_state,
    //.conf_tx            = ath10k_conf_tx,
    //.remain_on_channel      = ath10k_remain_on_channel,
    //.cancel_remain_on_channel   = ath10k_cancel_remain_on_channel,
    //.set_rts_threshold      = ath10k_set_rts_threshold,
    //.set_frag_threshold     = ath10k_mac_op_set_frag_threshold,
    //.flush              = ath10k_flush,
    //.tx_last_beacon         = ath10k_tx_last_beacon,
    .set_antenna            = eth_ath10k_set_antenna,
    .get_antenna            = eth_ath10k_get_antenna,
    //.reconfig_complete      = ath10k_reconfig_complete,
    //get_survey         = ath10k_get_survey,
    //.set_bitrate_mask       = ath10k_mac_op_set_bitrate_mask,
    //.sta_rc_update          = ath10k_sta_rc_update,
    //.get_tsf            = ath10k_get_tsf,
    //.set_tsf            = ath10k_set_tsf,
    //.ampdu_action           = ath10k_ampdu_action,
    //.get_et_sset_count      = ath10k_debug_get_et_sset_count,
    //.get_et_stats           = ath10k_debug_get_et_stats,
    //.get_et_strings         = ath10k_debug_get_et_strings,
    .add_chanctx            = eth_ath10k_add_chanctx,
    //.remove_chanctx         = ath10k_mac_op_remove_chanctx,
    //.change_chanctx         = ath10k_mac_op_change_chanctx,
    .assign_vif_chanctx     = eth_ath10k_mac_op_assign_vif_chanctx,
    //.unassign_vif_chanctx       = ath10k_mac_op_unassign_vif_chanctx,
    //.switch_vif_chanctx     = ath10k_mac_op_switch_vif_chanctx,

    //  CFG80211_TESTMODE_CMD(ath10k_tm_cmd)

    // #ifdef CONFIG_PM
    //  .suspend            = ath10k_wow_op_suspend,
    //  .resume             = ath10k_wow_op_resume,
    // #endif
    // #ifdef CONFIG_MAC80211_DEBUGFS
    //  .sta_add_debugfs        = ath10k_sta_add_debugfs,
    //  .sta_statistics         = ath10k_sta_statistics,
    //  .set_wakeup         = ath10k_wow_op_set_wakeup,
    // #endif
    .set_hw_ptrs = eth_ath10k_set_hw_ptrs,
    .init_vif_priv = eth_ath10k_init_vif_priv,
    .get_mac_addr = eth_ath10k_get_mac_addr,
    .mac_register = eth_ath10k_mac_register,
};

int ath10k_add_peer(struct rte_wireless_ctx* ctx, struct rte_wifi_peer* peer) {
    int ret;
    struct ath10k *ar = ctx->hw->priv;
    struct ath10k_vif* arvif = LIST_FIRST(&ar->arvifs);
    rte_spinlock_lock(&ar->conf_lock);
    struct ath10k_peer* ath_peer;
    struct ieee80211_sta_ht_cap ht_cap = ath10k_get_ht_cap(ar);
    struct ieee80211_sta_vht_cap vht_cap = ath10k_create_vht_cap(ar);

    u32 tx_ant = ar->cfg_tx_chainmask;
    u32 rx_ant = ar->cfg_rx_chainmask;
    assert(tx_ant == 3);
    assert(rx_ant == 3);
    uint32_t nss = get_nss_from_chainmask(ar->cfg_tx_chainmask);

    ath10k_dbg(ar, ATH10K_DBG_WMI, "mac_addr %02x:%02x:%02x:%02x:%02x:%02x\n", peer->addr.addr_bytes[0], peer->addr.addr_bytes[1], peer->addr.addr_bytes[2], peer->addr.addr_bytes[3], peer->addr.addr_bytes[4], peer->addr.addr_bytes[5]);

    ret = ath10k_peer_create(ar, arvif->vif, NULL, arvif->vdev_id, peer->addr.addr_bytes, WMI_PEER_TYPE_DEFAULT); // addr2 should be transmitter address in our case
    if (ret) {
        ath10k_warn(ar, "failed to create vdev %i peer: %d\n",
                arvif->vdev_id, ret);
        goto err_unlock;
    }

    // peer associate
    struct wmi_peer_assoc_complete_arg peer_arg;

    memset(&peer_arg, 0, sizeof(struct wmi_peer_assoc_complete_arg));

    peer_arg.peer_phymode = MODE_11AC_VHT80;
    peer_arg.peer_reassoc = 0;

    ether_addr_copy(&peer->addr, peer_arg.addr);
    peer_arg.vdev_id = arvif->vdev_id;
    peer_arg.peer_aid = peer->peer_aid;
    peer_arg.peer_flags = 0;
    peer_arg.peer_flags |= ar->wmi.peer_flags->auth;
    peer_arg.peer_flags |= ar->wmi.peer_flags->qos;
    peer_arg.peer_flags |= ar->wmi.peer_flags->ht;
    peer_arg.peer_flags |= ar->wmi.peer_flags->vht;
    peer_arg.peer_flags |= ar->wmi.peer_flags->ldbc;

    if(peer_arg.peer_phymode == MODE_11AC_VHT40 || peer_arg.peer_phymode == MODE_11AC_VHT80) {
      peer_arg.peer_flags |= ar->wmi.peer_flags->bw40;
    }
    if(peer_arg.peer_phymode == MODE_11AC_VHT80) {
      peer_arg.peer_flags |= ar->wmi.peer_flags->bw80;
    }

    peer_arg.peer_num_spatial_streams = nss;
    peer_arg.peer_listen_intval = 5;

    /*
     * LEGACY
     */
    peer_arg.peer_caps = 0x0;

    struct wmi_rate_set_arg *legacy_rateset = &peer_arg.peer_legacy_rates;
    legacy_rateset->rates[0] = 0x8c;
    legacy_rateset->rates[1] = 0x12;
    legacy_rateset->rates[2] = 0x98;
    legacy_rateset->rates[3] = 0x24;
    legacy_rateset->rates[4] = 0xb0;
    legacy_rateset->rates[5] = 0x48;
    legacy_rateset->rates[6] = 0x60;
    legacy_rateset->rates[7] = 0x6c;
    legacy_rateset->num_rates = 8;

    /*
     * HT
     */
    if(peer_arg.peer_flags & ar->wmi.peer_flags->ht) {
        if(peer_arg.peer_flags & ar->wmi.peer_flags->ldbc) {
            peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_LDPC_CODING;
        }
        peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
        peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_SM_PS;
        peer_arg.peer_ht_caps |= 0x3 << IEEE80211_HT_CAP_SM_PS_SHIFT;
        // peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_GRN_FLD;
        peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_SGI_20;
        peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_SGI_40;

        if(nss > 1) {
            peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_TX_STBC;
            peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_RX_STBC;
            peer_arg.peer_ht_caps |= (nss-1) << IEEE80211_HT_CAP_RX_STBC_SHIFT;
        }

        // peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_DELAY_BA;
        peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_MAX_AMSDU;
        peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_DSSSCCK40;
        // peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_RESERVED;
        // peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_40MHZ_INTOLERANT;
        // peer_arg.peer_ht_caps |= IEEE80211_HT_CAP_LSIG_TXOP_PROT;
        peer_arg.peer_max_mpdu = 65535;
        peer_arg.peer_mpdu_density = 8;

        struct wmi_rate_set_arg *ht_rateset = &peer_arg.peer_ht_rates;
        ht_rateset->num_rates = 8 * nss;
        for(int i = 0; i < ht_rateset->num_rates; ++i) {
            ht_rateset->rates[i] = i;
        }
    }
    // peer_arg.peer_ht_caps = 0x19ef;

    /*
     * VHT
     */
    if(peer_arg.peer_flags & ar->wmi.peer_flags->vht) {
        peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454;
        peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ;
        peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_SHORT_GI_80;
        peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_SHORT_GI_160;
        if(peer_arg.peer_flags & ar->wmi.peer_flags->ldbc) {
            peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_RXLDPC;
        }
        if(nss > 1) {
            peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_TXSTBC;
            peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_RXSTBC_1;
        }
        peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE;
        peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE;
        peer_arg.peer_vht_caps |= ath10k_mac_get_vht_cap_bf_sts(ar) << IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT;
        peer_arg.peer_vht_caps |= ath10k_mac_get_vht_cap_bf_sound_dim(ar) << IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT;
        peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE;
        peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE;
        peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN;
        peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN;
        
        // peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB;
        // peer_arg.peer_vht_caps |= IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_UNSOL_MFB;

        // uint32_t ampdu_factor = (vht_cap.cap &
        //      IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK) >>
        //         IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;
        peer_arg.peer_max_mpdu = max(peer_arg.peer_max_mpdu, 1048575);

        uint16_t vht_mcs_set = 0;
        for(int stream = 0; stream < 8; ++stream) {
            if(stream < nss) {
                vht_mcs_set |= IEEE80211_VHT_MCS_SUPPORT_0_9 << (2 * stream);
            } else {
                vht_mcs_set |= IEEE80211_VHT_MCS_NOT_SUPPORTED << (2 * stream);
            }
        }

        struct wmi_vht_rate_set_arg *vht_rateset = &peer_arg.peer_vht_rates;
        vht_rateset->rx_max_rate = 0;
        vht_rateset->rx_mcs_set = vht_mcs_set;
        vht_rateset->tx_max_rate = 0;
        vht_rateset->tx_mcs_set = vht_mcs_set;
    }

    /*
     * RATE CONTROL
     */
    if(peer_arg.peer_flags & ar->wmi.peer_flags->ht) {
        peer_arg.peer_rate_caps |= WMI_RC_HT_FLAG;
    }

    if(nss > 1) {
        peer_arg.peer_rate_caps |= WMI_RC_TX_STBC_FLAG;
        peer_arg.peer_rate_caps |= WMI_RC_RX_STBC_FLAG;
    }

    peer_arg.peer_rate_caps |= WMI_RC_SGI_FLAG;
    if(peer_arg.peer_flags & ar->wmi.peer_flags->bw40 || peer_arg.peer_flags & ar->wmi.peer_flags->bw80) {
        peer_arg.peer_rate_caps |= WMI_RC_CW40_FLAG;
    }

    if(nss >= 2) {
        peer_arg.peer_rate_caps |= WMI_RC_DS_FLAG;
    }

    if(nss >= 3) {
        peer_arg.peer_rate_caps |= WMI_RC_TS_FLAG;
    }

    if(nss > 1) {
        peer_arg.peer_rate_caps |= (nss - 1) << WMI_RC_RX_STBC_FLAG_S;
        peer_arg.peer_flags |= ar->wmi.peer_flags->stbc;
    }

    // peer_arg.peer_vht_caps = 0x339979fa;
    // peer_arg.peer_flags = 0x2019003;
    // peer_arg.peer_rate_caps = 0x6d;
    // struct wmi_vht_rate_set_arg *vht_rateset = &peer_arg.peer_vht_rates;
    // vht_rateset->rx_max_rate = 780;
    // vht_rateset->rx_mcs_set = 0xfffa;
    // vht_rateset->tx_max_rate = 780;
    // vht_rateset->tx_mcs_set = 0xfffa;

    ret = ath10k_wmi_peer_assoc(ar, &peer_arg);
    if (ret) {
        ath10k_warn(ar, "failed to run peer assoc for STA %pM vdev %i: %d\n",
                    peer->addr.addr_bytes, arvif->vdev_id, ret);
        goto err_unlock;
    }

    // ath10k_wmi_peer_set_param(ar, arvif->vdev_id, peer->addr.addr_bytes, WMI_PEER_SMPS_STATE, WMI_PEER_SMPS_PS_NONE);
    // if(peer_arg.peer_phymode == MODE_11AC_VHT20) {
    //     ath10k_wmi_peer_set_param(ar, arvif->vdev_id, peer->addr.addr_bytes, WMI_PEER_CHAN_WIDTH, WMI_PEER_CHWIDTH_20MHZ);
    // }
    // if(peer_arg.peer_phymode == MODE_11AC_VHT40) {
    //     ath10k_wmi_peer_set_param(ar, arvif->vdev_id, peer->addr.addr_bytes, WMI_PEER_CHAN_WIDTH, WMI_PEER_CHWIDTH_40MHZ);
    // }
    // if(peer_arg.peer_phymode == MODE_11AC_VHT80) {
    //     ath10k_wmi_peer_set_param(ar, arvif->vdev_id, peer->addr.addr_bytes, WMI_PEER_CHAN_WIDTH, WMI_PEER_CHWIDTH_80MHZ);
    // }
    // ath10k_wmi_peer_set_param(ar, arvif->vdev_id, peer->addr.addr_bytes, WMI_PEER_NSS, nss);
    // ath10k_wmi_peer_set_param(ar, arvif->vdev_id, peer->addr.addr_bytes, WMI_PEER_USE_4ADDR, 1);

    /*
        period = ar->thermal.quiet_period;
        duration = (period * ar->thermal.throttle_state) / 100;
        enabled = duration ? 1 : 0;

        ret = ath10k_wmi_pdev_set_quiet_mode(ar, period, duration,
                 ATH10K_QUIET_START_OFFSET,
                 enabled);
    */
    // ath10k_wmi_pdev_set_quiet_mode(ar, 25, 2, 10, 1);

err_unlock:
    rte_spinlock_unlock(&ar->conf_lock);
    return ret;
}

int ath10k_delete_peer(struct rte_wireless_ctx* ctx, struct rte_wifi_peer* peer) {
    struct ath10k *ar = ctx->hw->priv;
    int vdev_id = 0;
    return ath10k_wmi_peer_delete(ar, vdev_id, peer->addr.addr_bytes);
}

void ath10k_enable_polling(struct rte_wireless_ctx* ctx) {
    struct ath10k *ar = ctx->hw->priv;
    ar->polling_enabled = true;
    // ath10k_hif_irq_disable(ar);
}

void ath10k_disable_polling(struct rte_wireless_ctx* ctx) {
    struct ath10k *ar = ctx->hw->priv;
    ar->polling_enabled = false;
    // ath10k_hif_irq_enable(ar);
}

int ath10k_offset_tsf(struct rte_wireless_ctx* ctx, int64_t tsfadj) {
    struct ath10k *ar = ctx->hw->priv;
    u32 offset, vdev_param;
    int vdev_id = 0;
    int ret;

    if (tsfadj < 0) {
        vdev_param = ar->wmi.vdev_param->dec_tsf;
        offset = -tsfadj;
    } else {
        vdev_param = ar->wmi.vdev_param->inc_tsf;
        offset = tsfadj;
    }

    ret = ath10k_wmi_vdev_set_param(ar, 0,
                    vdev_param, offset);

    if (ret && ret != -EOPNOTSUPP)
        ath10k_warn(ar, "failed to set tsf offset %d cmd %d: %d\n",
                offset, vdev_param, ret);

    return ret;
}

int ath10k_set_tsf(struct rte_wireless_ctx* ctx, uint64_t tsf) {
    struct ath10k *ar = ctx->hw->priv;
    struct ath10k_vif* arvif = LIST_FIRST(&ar->arvifs);
    struct ath10k_pci* ar_pci = ath10k_pci_priv(ar);

    rte_spinlock_lock(&ar_pci->intr_lock);
    ar->polling_enabled = false;
    rte_spinlock_unlock(&ar_pci->intr_lock);

    struct ieee80211_if_ibss *ifibss = &ctx->sdata->u.ibss;

    ctx->dev_ops->bss_info_changed(ctx->hw, ctx->vif, &ctx->vif->bss_conf, BSS_CHANGED_IBSS | BSS_CHANGED_BEACON_INFO | BSS_CHANGED_BEACON | BSS_CHANGED_BEACON_ENABLED);

    __ieee80211_sta_join_ibss(ctx->sdata, arvif->bssid, ctx->sdata->vif.bss_conf.beacon_int,
                  &ifibss->chandef, ifibss->basic_rates,
                  WLAN_CAPABILITY_IBSS, tsf, true);

    ctx->dev_ops->bss_info_changed(ctx->hw, ctx->vif, &ctx->vif->bss_conf, BSS_CHANGED_IBSS | BSS_CHANGED_BEACON_INFO | BSS_CHANGED_BEACON | BSS_CHANGED_BEACON_ENABLED);

    assert(arvif->is_up);
    rte_spinlock_lock(&ar_pci->intr_lock);
    ar->polling_enabled = true;
    rte_spinlock_unlock(&ar_pci->intr_lock);

    return 0;
}

int ath10k_up(struct rte_wireless_ctx* ctx) {
    struct ath10k *ar = ctx->hw->priv;
    struct ath10k_pci* ar_pci = ath10k_pci_priv(ar);
    struct ath10k_vif* arvif = LIST_FIRST(&ar->arvifs);
    int ret;

    rte_spinlock_lock(&ar_pci->intr_lock);
    rte_spinlock_lock(&ar->conf_lock);

    // uint32_t vdev_param = ar->wmi.vdev_param->beacon_interval;
    // ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, arvif->beacon_interval);
    ret = ath10k_wmi_vdev_up(ar, arvif->vdev_id, arvif->aid, arvif->bssid);
    arvif->is_up = true;
    ar->polling_enabled = true;

    rte_spinlock_unlock(&ar->conf_lock);
    rte_spinlock_unlock(&ar_pci->intr_lock);

    return ret;
}

int ath10k_down(struct rte_wireless_ctx* ctx) {
    struct ath10k *ar = ctx->hw->priv;
    struct ath10k_vif* arvif = LIST_FIRST(&ar->arvifs);
    struct ath10k_pci* ar_pci = ath10k_pci_priv(ar);

    rte_spinlock_lock(&ar_pci->intr_lock);
    ar->polling_enabled = false;
    arvif->is_up = false;
    rte_spinlock_unlock(&ar_pci->intr_lock);

    ieee80211_sta_create_ibss(ctx->sdata);

    ctx->vif->bss_conf.enable_beacon = false;
    ctx->dev_ops->bss_info_changed(ctx->hw, ctx->vif, &ctx->vif->bss_conf, BSS_CHANGED_BEACON);

    ctx->vif->bss_conf.enable_beacon = true;
    ctx->dev_ops->bss_info_changed(ctx->hw, ctx->vif, &ctx->vif->bss_conf, BSS_CHANGED_BEACON_ENABLED);

    ar->polling_enabled = false;
    arvif->is_up = false;
    return 0;

    int ret = ath10k_wmi_vdev_down(ar, arvif->vdev_id);

    rte_pktmbuf_free(arvif->beacon);
    arvif->beacon = NULL;
    arvif->beacon_state = ATH10K_BEACON_SCHEDULED;

    uint32_t vdev_param = ar->wmi.vdev_param->beacon_interval;
    ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, vdev_param, arvif->beacon_interval);

    arvif->tx_seq_no = 0x1000;

    ret = ath10k_wmi_vdev_up(ar, arvif->vdev_id, arvif->aid, arvif->bssid);

    rte_spinlock_lock(&ar_pci->intr_lock);
    arvif->is_up = true;
    ar->polling_enabled = true;
    rte_spinlock_unlock(&ar_pci->intr_lock);

    rte_spinlock_unlock(&ar->conf_lock);

    return ret;
}

int ath10k_send_addba(struct rte_wireless_ctx* ctx, const u8 *mac, u32 tid, u32 buf_size) {
    struct ath10k *ar = ctx->hw->priv;

    // TODO: fix vdev id 0
    return ath10k_wmi_addba_send(ar, 0, mac, tid, buf_size);
}

int ath10k_addba_set_resp(struct rte_wireless_ctx* ctx, const uint8_t *mac, uint32_t tid, uint32_t status) {
    struct ath10k *ar = ctx->hw->priv;

    // TODO: fix vdev id 0
    return ath10k_wmi_addba_set_resp(ar, 0, mac, tid, status);
}

int ath10k_get_pdev_temperature(struct rte_wireless_ctx* ctx) {
    struct ath10k *ar = ctx->hw->priv;
    return ath10k_wmi_pdev_get_temperature(ar);
}

const struct rte_wireless_ops ath10k_wireless_ops = {
    .add_peer = ath10k_add_peer,
    .delete_peer = ath10k_delete_peer,
    .enable_polling = ath10k_enable_polling,
    .disable_polling = ath10k_disable_polling,
    .offset_tsf = ath10k_offset_tsf,
    .set_tsf = ath10k_set_tsf,
    .up = ath10k_up,
    .down = ath10k_down,
    .send_addba = ath10k_send_addba,
    .addba_set_resp = ath10k_addba_set_resp,
    .get_pdev_temperature = ath10k_get_pdev_temperature

    // add_vif(port_id, mode)
    // delete_vif(port_id)
};


/* Initialize device. */
static int eth_ath10k_dev_init(struct rte_eth_dev *dev) {
	char *device_name = NULL;
	switch(RTE_DEV_TO_PCI(dev->device)->id.device_id) {
		case QCA988X_2_0_DEVICE_ID:
			device_name = (char*) "PCIe QCA988X Hw 2.0";
			break;
		case QCA6164_2_1_DEVICE_ID:
			device_name = (char*) "PCIe QCA6164 Hw 2.1";
			break;
		case QCA6174_2_1_DEVICE_ID:
			device_name = (char*) "PCIe QCA6174 Hw 2.1";
			break;
		case QCA99X0_2_0_DEVICE_ID:
			device_name = (char*) "PCIe QCA99X0 Hw 2.0";
			break;
		case QCA9888_2_0_DEVICE_ID:
			device_name = (char*) "PCIe QCA9888 Hw 2.0";
			break;
		case QCA9984_1_0_DEVICE_ID:
			device_name = (char*) "PCIe QCA9984 Hw 1.0";
			break;
		case QCA9377_1_0_DEVICE_ID:
			device_name = (char*) "PCIe QCA9377 Hw 1.0";
			break;
		case QCA9887_1_0_DEVICE_ID:
			device_name = (char*) "PCIe QCA9887 Hw 1.0";
			break;
		default:
			device_name = (char*) "(Unknown Device)";
	}

	RTE_LOG(INFO, PMD, "Initializing ath10k device of type %s on port %" PRIu16 "\n", device_name, dev->data->port_id);

	struct rte_pci_device *pci_dev;
	struct ath10k_adapter *adapter = ATH10K_DEV_PRIVATE(dev->data->dev_private);
	struct ath10k_hw *hw = ATH10K_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	int ret;

	pci_dev = RTE_DEV_TO_PCI(dev->device);
	hw->mac.rar_entry_count = 15; // TODO this is a hotfix for mac init.
	rte_eth_copy_pci_info(dev, pci_dev);

	dev->dev_ops = &eth_ath10k_ops;
	dev->rx_pkt_burst = (eth_rx_burst_t)&eth_ath10k_rx;
	dev->tx_pkt_burst = (eth_tx_burst_t)&eth_ath10k_tx;
	dev->tx_pkt_prepare = (eth_tx_prep_t)&eth_ath10k_prepare_tx;

    struct rte_wireless_ctx *wifi_dev = rte_zmalloc("ath10k_rte_wireless_ctx", sizeof(struct rte_wireless_ctx), 0);
	dev->wireless_ctx = wifi_dev;
	wifi_dev->dev_ops = &eth_ath10k_80211_ops;
    wifi_dev->ops = &ath10k_wireless_ops;

    ret = ath10k_pci_probe(pci_dev, dev);
	if (ret != 0) {
		RTE_LOG(DEBUG, PMD, "Failed to probe\n");
		return -1;
	}

	void* hw_addr = RTE_DEV_TO_PCI(dev->device)->mem_resource[0].addr;
	hw->hw_addr = hw_addr;
	hw->device_id = pci_dev->id.device_id;
	adapter->stopped = 0;

	// Allocate memory for storing MAC addresses
	RTE_LOG(DEBUG, PMD, "DRIVER: alloc memory for mac address\n");
	dev->data->mac_addrs = rte_zmalloc("ath10k", ETHER_ADDR_LEN * hw->mac.rar_entry_count, 0);
	if (dev->data->mac_addrs == NULL) {
		RTE_LOG(DEBUG, PMD, "Failed to allocate %d bytes needed to store MAC addresses", \
				ETHER_ADDR_LEN * hw->mac.rar_entry_count);
		return -ENOMEM;
	}

    RTE_LOG(INFO, PMD, "ath10k device of type %s initialized on port %" PRIu16 "\n", device_name, dev->data->port_id);

	return 0;
}

/* Uninitialize device. */
static int eth_ath10k_dev_uninit(struct rte_eth_dev *dev) {
	RTE_LOG(DEBUG, PMD, "Uninitializing device %d\n", RTE_DEV_TO_PCI(dev->device)->id.device_id);

	void* hw_addr = RTE_DEV_TO_PCI(dev->device)->mem_resource[0].addr;
	// ath10k_pci_remove() TODO add pci dev
	// TODO speicherfreigabe ath10_pci_remove(dev->pci_dev);

	//RTE_LOG(DEBUG, PMD, "Putting device back to sleep...\n");
	//ath10k_pci_sleep(hw_addr);

	return 0;
}

static int
eth_ath10k_vif_probe(struct rte_vdev_device *dev) {
  return 0;
}

static int
eth_ath10k_vif_remove(struct rte_vdev_device *dev) {
  return 0;
}

RTE_PMD_REGISTER_PCI(net_ath10k, rte_ath10k_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_ath10k, pci_id_ath10k_map);
RTE_PMD_REGISTER_KMOD_DEP(net_ath10k, "* igb_uio | uio_pci_generic | vfio");

struct rte_vdev_driver rte_ath10k_vif_pmd = {
  .probe = eth_ath10k_vif_probe,
  .remove = eth_ath10k_vif_remove,
};

RTE_PMD_REGISTER_VDEV(net_ath10k_vif, rte_ath10k_vif_pmd);

RTE_PMD_REGISTER_PARAM_STRING(net_ath10k_vif,
  "pdev=<ifc>");

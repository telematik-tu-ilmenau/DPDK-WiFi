#include "rte_cfg80211.h"
#include "rte_mac80211.h"
#include "rte_ieee80211_i.h"
#include <rte_byteorder.h>
#include <sys/queue.h>

/* privid for wiphys to determine whether they belong to us or not */
const void *const mac80211_wiphy_privid = &mac80211_wiphy_privid;

void ieee80211_radar_detected(struct ieee80211_hw *hw)
{
    struct ieee80211_local *local = hw_to_local(hw);

    // this is for kernel debugging only
    // trace_api_radar_detected(local);

    // TODO: use kernel work queue or something custom?
    // schedule_work(&local->radar_detected_work);
}

unsigned int ieee80211_hdrlen(uint16_t fc)
{
    unsigned int hdrlen = 24;

    if (ieee80211_is_data(fc)) {
        if (ieee80211_has_a4(fc))
            hdrlen = 30;
        if (ieee80211_is_data_qos(fc)) {
            hdrlen += IEEE80211_QOS_CTL_LEN;
            if (ieee80211_has_order(fc))
                hdrlen += IEEE80211_HT_CTL_LEN;
        }
        goto out;
    }

    if (ieee80211_is_mgmt(fc)) {
        if (ieee80211_has_order(fc))
            hdrlen += IEEE80211_HT_CTL_LEN;
        goto out;
    }

    if (ieee80211_is_ctl(fc)) {
        /*
         * ACK and CTS are 10 bytes, all others 16. To see how
         * to get this condition consider
         *   subtype mask:   0b0000000011110000 (0x00F0)
         *   ACK subtype:    0b0000000011010000 (0x00D0)
         *   CTS subtype:    0b0000000011000000 (0x00C0)
         *   bits that matter:         ^^^      (0x00E0)
         *   value of those: 0b0000000011000000 (0x00C0)
         */
        if ((fc & rte_cpu_to_le_16(0x00E0)) == rte_cpu_to_le_16(0x00C0))
            hdrlen = 10;
        else
            hdrlen = 16;
    }
out:
    return hdrlen;
}

void ieee80211_queue_work(struct ieee80211_hw *hw, struct work_struct *work)
{
    struct ieee80211_local *local = hw_to_local(hw);

//    if (!ieee80211_can_queue_work(local))
//        return;

    queue_work(local->workqueue, work);
}

void ieee80211_propagate_queue_wake(struct ieee80211_local *local, int queue)
{
    RTE_LOG(WARNING, 80211, "do we need to \"propagate\" a queue wake?\n");
//    struct ieee80211_sub_if_data *sdata;
//    int n_acs = IEEE80211_NUM_ACS;
//
//    // if (local->ops->wake_tx_queue)
//    //     return;
//
//    if (local->hw.queues < IEEE80211_NUM_ACS)
//        n_acs = 1;
//
//    // list_for_each_entry_rcu(sdata, &local->interfaces, list) {
//    LIST_FOREACH(sdata, &local->interfaces, pointers) {
//        int ac;
//
//        if (!sdata->dev)
//            continue;
//
//        if (sdata->vif.cab_queue != IEEE80211_INVAL_HW_QUEUE &&
//            local->queue_stop_reasons[sdata->vif.cab_queue] != 0)
//            continue;
//
//        for (ac = 0; ac < n_acs; ac++) {
//            int ac_queue = sdata->vif.hw_queue[ac];
//
//            if (ac_queue == queue ||
//                (sdata->vif.cab_queue == queue &&
//                 local->queue_stop_reasons[ac_queue] == 0 &&
//                 LIST_EMPTY(&local->pending[ac_queue])))
//                netif_wake_subqueue(sdata->dev, ac);
//        }
//    }
}

static void __ieee80211_wake_queue(struct ieee80211_hw *hw, int queue,
                   enum queue_stop_reason reason,
                   bool refcounted)
{
    struct ieee80211_local *local = hw_to_local(hw);

    // for kernel debugging only
    // trace_wake_queue(local, queue, reason);

    if (queue >= hw->queues) {
        RTE_LOG(WARNING, 80211, "queue >= hw->queues\n");
        return;
    }

    if (!test_bit(reason, &local->queue_stop_reasons[queue]))
        return;

    if (!refcounted) {
        local->q_stop_reasons[queue][reason] = 0;
    } else {
        local->q_stop_reasons[queue][reason]--;
        if (local->q_stop_reasons[queue][reason] < 0) {
            RTE_LOG(WARNING, 80211, "local->q_stop_reasons[queue][reason] < 0\n");
            local->q_stop_reasons[queue][reason] = 0;
        }
    }

    if (local->q_stop_reasons[queue][reason] == 0)
        __clear_bit(reason, &local->queue_stop_reasons[queue]);

    if (local->queue_stop_reasons[queue] != 0)
        /* someone still has this queue stopped */
        return;

    if (LIST_EMPTY(&local->pending[queue])) {
        // rcu_read_lock();
        ieee80211_propagate_queue_wake(local, queue); // TODO: this may not be necessary in our case
        // rcu_read_unlock();
    } else {
        // TODO: this may not be necessary in our case
        // tasklet_schedule(&local->tx_pending_tasklet);
        RTE_LOG(WARNING, 80211, "scheduling the traditional way does not apply to our case\n");
    }
}

void ieee80211_wake_queue_by_reason(struct ieee80211_hw *hw, int queue,
                    enum queue_stop_reason reason,
                    bool refcounted)
{
    struct ieee80211_local *local = hw_to_local(hw);
    unsigned long flags;

    // spin_lock_irqsave(&local->queue_stop_reason_lock, flags);
    __ieee80211_wake_queue(hw, queue, reason, refcounted);
    // spin_unlock_irqrestore(&local->queue_stop_reason_lock, flags);
}

void ieee80211_wake_queue(struct ieee80211_hw *hw, int queue)
{
    ieee80211_wake_queue_by_reason(hw, queue,
                       IEEE80211_QUEUE_STOP_REASON_DRIVER,
                       false);
}

int ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
{
    /* see 802.11 17.3.8.3.2 and Annex J
     * there are overlapping channel numbers in 5GHz and 2GHz bands */
    if (chan <= 0)
        return 0; /* not supported */
    switch (band) {
    case NL80211_BAND_2GHZ:
        if (chan == 14)
            return 2484;
        else if (chan < 14)
            return 2407 + chan * 5;
        break;
    case NL80211_BAND_5GHZ:
        if (chan >= 182 && chan <= 196)
            return 4000 + chan * 5;
        else
            return 5000 + chan * 5;
        break;
    case NL80211_BAND_60GHZ:
        if (chan < 5)
            return 56160 + chan * 2160;
        break;
    default:
        ;
    }
    return 0; /* not supported */
}

int ieee80211_frequency_to_channel(int freq)
{
    /* see 802.11 17.3.8.3.2 and Annex J */
    if (freq == 2484)
        return 14;
    else if (freq < 2484)
        return (freq - 2407) / 5;
    else if (freq >= 4910 && freq <= 4980)
        return (freq - 4000) / 5;
    else if (freq <= 45000) /* DMG band lower limit */
        return (freq - 5000) / 5;
    else if (freq >= 58320 && freq <= 64800)
        return (freq - 56160) / 2160;
    else
        return 0;
}

uint8_t *ieee80211_add_wmm_info_ie(uint8_t *buf, uint8_t qosinfo)
{
    *buf++ = WLAN_EID_VENDOR_SPECIFIC;
    *buf++ = 7; /* len */
    *buf++ = 0x00; /* Microsoft OUI 00:50:F2 */
    *buf++ = 0x50;
    *buf++ = 0xf2;
    *buf++ = 2; /* WME */
    *buf++ = 0; /* WME info */
    *buf++ = 1; /* WME ver */
    *buf++ = qosinfo; /* U-APSD no in use */

    return buf;
}

uint8_t *ieee80211_ie_build_ht_cap(uint8_t *pos, struct ieee80211_sta_ht_cap *ht_cap,
                  uint16_t cap)
{
    uint16_t tmp;

    *pos++ = WLAN_EID_HT_CAPABILITY;
    *pos++ = sizeof(struct ieee80211_ht_cap);
    memset(pos, 0, sizeof(struct ieee80211_ht_cap));

    /* capability flags */
    tmp = rte_cpu_to_le_16(cap);
    memcpy(pos, &tmp, sizeof(uint16_t));
    pos += sizeof(uint16_t);

    /* AMPDU parameters */
    *pos++ = ht_cap->ampdu_factor |
         (ht_cap->ampdu_density <<
            IEEE80211_HT_AMPDU_PARM_DENSITY_SHIFT);

    /* MCS set */
    memcpy(pos, &ht_cap->mcs, sizeof(ht_cap->mcs));
    // fixme: remove 0xff, only quick test
    pos[0] = 0xff;
    pos[1] = 0xff;
    pos += sizeof(ht_cap->mcs);

    /* extended capabilities */
    pos += sizeof(uint16_t);

    /* BF capabilities */
    pos += sizeof(uint32_t);

    /* antenna selection */
    pos += sizeof(uint8_t);

    return pos;
}

uint8_t *ieee80211_ie_build_vht_cap(uint8_t *pos, struct ieee80211_sta_vht_cap *vht_cap,
                   uint32_t cap)
{
    uint32_t tmp;

    *pos++ = WLAN_EID_VHT_CAPABILITY;
    *pos++ = sizeof(struct ieee80211_vht_cap);
    memset(pos, 0, sizeof(struct ieee80211_vht_cap));

    /* capability flags */
    tmp = rte_cpu_to_le_32(cap);
    memcpy(pos, &tmp, sizeof(uint32_t));
    pos += sizeof(uint32_t);

    /* VHT MCS set */
    memcpy(pos, &vht_cap->vht_mcs, sizeof(vht_cap->vht_mcs));
    pos += sizeof(vht_cap->vht_mcs);

    return pos;
}

uint8_t *ieee80211_ie_build_ht_oper(uint8_t *pos, struct ieee80211_sta_ht_cap *ht_cap,
                   const struct cfg80211_chan_def *chandef,
                   uint16_t prot_mode, bool rifs_mode)
{
    struct ieee80211_ht_operation *ht_oper;
    /* Build HT Information */
    *pos++ = WLAN_EID_HT_OPERATION;
    *pos++ = sizeof(struct ieee80211_ht_operation);
    ht_oper = (struct ieee80211_ht_operation *)pos;
    ht_oper->primary_chan = ieee80211_frequency_to_channel(
                    chandef->chan->center_freq);
    switch (chandef->width) {
    case NL80211_CHAN_WIDTH_160:
    case NL80211_CHAN_WIDTH_80P80:
    case NL80211_CHAN_WIDTH_80:
    case NL80211_CHAN_WIDTH_40:
        if (chandef->center_freq1 > chandef->chan->center_freq)
            ht_oper->ht_param = IEEE80211_HT_PARAM_CHA_SEC_ABOVE;
        else
            ht_oper->ht_param = IEEE80211_HT_PARAM_CHA_SEC_BELOW;
        break;
    default:
        ht_oper->ht_param = IEEE80211_HT_PARAM_CHA_SEC_NONE;
        break;
    }
    if (ht_cap->cap & IEEE80211_HT_CAP_SUP_WIDTH_20_40 &&
        chandef->width != NL80211_CHAN_WIDTH_20_NOHT &&
        chandef->width != NL80211_CHAN_WIDTH_20)
        ht_oper->ht_param |= IEEE80211_HT_PARAM_CHAN_WIDTH_ANY;

    if (rifs_mode)
        ht_oper->ht_param |= IEEE80211_HT_PARAM_RIFS_MODE;

    ht_oper->operation_mode = rte_cpu_to_le_16(prot_mode);
    ht_oper->stbc_param = 0x0000;

    /* It seems that Basic MCS set and Supported MCS set
       are identical for the first 10 bytes */
    memset(&ht_oper->basic_set, 0, 16);
    memcpy(&ht_oper->basic_set, &ht_cap->mcs, 10);

    return pos + sizeof(struct ieee80211_ht_operation);
}

uint8_t *ieee80211_ie_build_vht_oper(uint8_t *pos, struct ieee80211_sta_vht_cap *vht_cap,
                const struct cfg80211_chan_def *chandef)
{
    struct ieee80211_vht_operation *vht_oper;

    *pos++ = WLAN_EID_VHT_OPERATION;
    *pos++ = sizeof(struct ieee80211_vht_operation);
    vht_oper = (struct ieee80211_vht_operation *)pos;
    vht_oper->center_freq_seg0_idx = ieee80211_frequency_to_channel(
                            chandef->center_freq1);
    if (chandef->center_freq2)
        vht_oper->center_freq_seg1_idx =
            ieee80211_frequency_to_channel(chandef->center_freq2);
    else
        vht_oper->center_freq_seg1_idx = 0x00;

    switch (chandef->width) {
    case NL80211_CHAN_WIDTH_160:
        /*
         * Convert 160 MHz channel width to new style as interop
         * workaround.
         */
        vht_oper->chan_width = IEEE80211_VHT_CHANWIDTH_80MHZ;
        vht_oper->center_freq_seg1_idx = vht_oper->center_freq_seg0_idx;
        if (chandef->chan->center_freq < chandef->center_freq1)
            vht_oper->center_freq_seg0_idx -= 8;
        else
            vht_oper->center_freq_seg0_idx += 8;
        break;
    case NL80211_CHAN_WIDTH_80P80:
        /*
         * Convert 80+80 MHz channel width to new style as interop
         * workaround.
         */
        vht_oper->chan_width = IEEE80211_VHT_CHANWIDTH_80MHZ;
        break;
    case NL80211_CHAN_WIDTH_80:
        vht_oper->chan_width = IEEE80211_VHT_CHANWIDTH_80MHZ;
        break;
    default:
        vht_oper->chan_width = IEEE80211_VHT_CHANWIDTH_USE_HT;
        break;
    }

    /* don't require special VHT peer rates */
    vht_oper->basic_mcs_set = rte_cpu_to_le_16(0xffff);

    return pos + sizeof(struct ieee80211_vht_operation);
}

bool ieee80211_chandef_ht_oper(const struct ieee80211_ht_operation *ht_oper,
                   struct cfg80211_chan_def *chandef)
{
    enum nl80211_channel_type channel_type;

    if (!ht_oper)
        return false;

    switch (ht_oper->ht_param & IEEE80211_HT_PARAM_CHA_SEC_OFFSET) {
    case IEEE80211_HT_PARAM_CHA_SEC_NONE:
        channel_type = NL80211_CHAN_HT20;
        break;
    case IEEE80211_HT_PARAM_CHA_SEC_ABOVE:
        channel_type = NL80211_CHAN_HT40PLUS;
        break;
    case IEEE80211_HT_PARAM_CHA_SEC_BELOW:
        channel_type = NL80211_CHAN_HT40MINUS;
        break;
    default:
        channel_type = NL80211_CHAN_NO_HT;
        return false;
    }

    cfg80211_chandef_create(chandef, chandef->chan, channel_type);
    return true;
}

bool ieee80211_chandef_vht_oper(const struct ieee80211_vht_operation *oper,
                struct cfg80211_chan_def *chandef)
{
    struct cfg80211_chan_def new = *chandef;
    int cf1, cf2;

    if (!oper)
        return false;

    cf1 = ieee80211_channel_to_frequency(oper->center_freq_seg0_idx,
                         chandef->chan->band);
    cf2 = ieee80211_channel_to_frequency(oper->center_freq_seg1_idx,
                         chandef->chan->band);

    switch (oper->chan_width) {
    case IEEE80211_VHT_CHANWIDTH_USE_HT:
        break;
    case IEEE80211_VHT_CHANWIDTH_80MHZ:
        new.width = NL80211_CHAN_WIDTH_80;
        new.center_freq1 = cf1;
        /* If needed, adjust based on the newer interop workaround. */
        if (oper->center_freq_seg1_idx) {
            unsigned int diff;

            diff = abs(oper->center_freq_seg1_idx -
                   oper->center_freq_seg0_idx);
            if (diff == 8) {
                new.width = NL80211_CHAN_WIDTH_160;
                new.center_freq1 = cf2;
            } else if (diff > 8) {
                new.width = NL80211_CHAN_WIDTH_80P80;
                new.center_freq2 = cf2;
            }
        }
        break;
    case IEEE80211_VHT_CHANWIDTH_160MHZ:
        new.width = NL80211_CHAN_WIDTH_160;
        new.center_freq1 = cf1;
        break;
    case IEEE80211_VHT_CHANWIDTH_80P80MHZ:
        new.width = NL80211_CHAN_WIDTH_80P80;
        new.center_freq1 = cf1;
        new.center_freq2 = cf2;
        break;
    default:
        return false;
    }

    if (!cfg80211_chandef_valid(&new))
        return false;

    *chandef = new;
    return true;
}

const uint8_t *ieee80211_bss_get_ie(struct cfg80211_bss *bss, uint8_t ie)
{
    const struct cfg80211_bss_ies *ies;

    // ies = rcu_dereference(bss->ies);
    ies = bss->ies;
    if (!ies)
        return NULL;

    return cfg80211_find_ie(ie, ies->data, ies->len);
}

uint32_t ieee80211_chandef_downgrade(struct cfg80211_chan_def *c)
{
    uint32_t ret;
    int tmp;

    switch (c->width) {
    case NL80211_CHAN_WIDTH_20:
        c->width = NL80211_CHAN_WIDTH_20_NOHT;
        ret = IEEE80211_STA_DISABLE_HT | IEEE80211_STA_DISABLE_VHT;
        break;
    case NL80211_CHAN_WIDTH_40:
        c->width = NL80211_CHAN_WIDTH_20;
        c->center_freq1 = c->chan->center_freq;
        ret = IEEE80211_STA_DISABLE_40MHZ |
              IEEE80211_STA_DISABLE_VHT;
        break;
    case NL80211_CHAN_WIDTH_80:
        tmp = (30 + c->chan->center_freq - c->center_freq1)/20;
        /* n_P40 */
        tmp /= 2;
        /* freq_P40 */
        c->center_freq1 = c->center_freq1 - 20 + 40 * tmp;
        c->width = NL80211_CHAN_WIDTH_40;
        ret = IEEE80211_STA_DISABLE_VHT;
        break;
    case NL80211_CHAN_WIDTH_80P80:
        c->center_freq2 = 0;
        c->width = NL80211_CHAN_WIDTH_80;
        ret = IEEE80211_STA_DISABLE_80P80MHZ |
              IEEE80211_STA_DISABLE_160MHZ;
        break;
    case NL80211_CHAN_WIDTH_160:
        /* n_P20 */
        tmp = (70 + c->chan->center_freq - c->center_freq1)/20;
        /* n_P80 */
        tmp /= 4;
        c->center_freq1 = c->center_freq1 - 40 + 80 * tmp;
        c->width = NL80211_CHAN_WIDTH_80;
        ret = IEEE80211_STA_DISABLE_80P80MHZ |
              IEEE80211_STA_DISABLE_160MHZ;
        break;
    default:
    case NL80211_CHAN_WIDTH_20_NOHT:
//        WARN_ON_ONCE(1);
        c->width = NL80211_CHAN_WIDTH_20_NOHT;
        ret = IEEE80211_STA_DISABLE_HT | IEEE80211_STA_DISABLE_VHT;
        break;
    case NL80211_CHAN_WIDTH_5:
    case NL80211_CHAN_WIDTH_10:
//        WARN_ON_ONCE(1);
        /* keep c->width */
        ret = IEEE80211_STA_DISABLE_HT | IEEE80211_STA_DISABLE_VHT;
        break;
    }

    if(!cfg80211_chandef_valid(c))
        RTE_LOG(WARNING, 80211, "!cfg80211_chandef_valid(c)\n");

    return ret;
}

struct ieee80211_channel *ieee80211_get_channel(struct wiphy *wiphy, int freq)
{
    enum nl80211_band band;
    struct ieee80211_supported_band *sband;
    int i;

    for (band = 0; band < NUM_NL80211_BANDS; band++) {
        sband = wiphy->bands[band];

        if (!sband)
            continue;

        for (i = 0; i < sband->n_channels; i++) {
            if (sband->channels[i].center_freq == freq)
                return &sband->channels[i];
        }
    }

    return NULL;
}

static void __iterate_interfaces(struct ieee80211_local *local,
                 uint32_t iter_flags,
                 void (*iterator)(void *data, uint8_t *mac,
                          struct ieee80211_vif *vif),
                 void *data)
{
    if(!local) {
        RTE_LOG(WARNING, 80211, "ieee80211_local not set yet\n");
        return;
    }
    struct ieee80211_sub_if_data *sdata;
    bool active_only = iter_flags & IEEE80211_IFACE_ITER_ACTIVE;

    // list_for_each_entry_rcu(sdata, &local->interfaces, list) {
    LIST_FOREACH(sdata, &local->interfaces, pointers) {
        switch (sdata->vif.type) {
        case NL80211_IFTYPE_MONITOR:
//            if (!(sdata->u.mntr.flags & MONITOR_FLAG_ACTIVE))
              continue;
            break;
        case NL80211_IFTYPE_AP_VLAN:
            continue;
        default:
            break;
        }
        if (!(iter_flags & IEEE80211_IFACE_ITER_RESUME_ALL) &&
            active_only && !(sdata->flags & IEEE80211_SDATA_IN_DRIVER))
            continue;
        if (ieee80211_sdata_running(sdata) || !active_only)
            iterator(data, sdata->vif.addr,
                 &sdata->vif);
    }

//    sdata = rcu_dereference_check(local->monitor_sdata,
//                      lockdep_is_held(&local->iflist_mtx) ||
//                      lockdep_rtnl_is_held());
    sdata = local->monitor_sdata;
    if (sdata &&
        (iter_flags & IEEE80211_IFACE_ITER_RESUME_ALL || !active_only ||
         sdata->flags & IEEE80211_SDATA_IN_DRIVER))
        iterator(data, sdata->vif.addr, &sdata->vif);
}

void ieee80211_iterate_active_interfaces_atomic(
    struct ieee80211_hw *hw, uint32_t iter_flags,
    void (*iterator)(void *data, uint8_t *mac,
             struct ieee80211_vif *vif),
    void *data)
{
    struct ieee80211_local *local = hw_to_local(hw);

//     rcu_read_lock();
    __iterate_interfaces(local, iter_flags | IEEE80211_IFACE_ITER_ACTIVE,
                 iterator, data);
//     rcu_read_unlock();
}

void ieee80211_txq_get_depth(struct ieee80211_txq *txq,
                 unsigned long *frame_cnt,
                 unsigned long *byte_cnt)
{
    struct txq_info *txqi = to_txq_info(txq);
    uint32_t frag_cnt = 0, frag_bytes = 0;
    struct sk_buff *skb;
    TAILQ_FOREACH(skb, &txqi->frags, pointers_tailq) {
        frag_cnt++;
        frag_bytes += skb_len(skb);
    }

    if (frame_cnt)
        *frame_cnt = txqi->tin.backlog_packets + frag_cnt;

    if (byte_cnt)
        *byte_cnt = txqi->tin.backlog_bytes + frag_bytes;
}

int ieee80211_frame_duration(enum nl80211_band band, long unsigned int len,
                 int rate, int erp, int short_preamble,
                 int shift)
{
    int dur;

    /* calculate duration (in microseconds, rounded up to next higher
     * integer if it includes a fractional microsecond) to send frame of
     * len bytes (does not include FCS) at the given rate. Duration will
     * also include SIFS.
     *
     * rate is in 100 kbps, so divident is multiplied by 10 in the
     * DIV_ROUND_UP() operations.
     *
     * shift may be 2 for 5 MHz channels or 1 for 10 MHz channels, and
     * is assumed to be 0 otherwise.
     */

    if (band == NL80211_BAND_5GHZ || erp) {
        /*
         * OFDM:
         *
         * N_DBPS = DATARATE x 4
         * N_SYM = Ceiling((16+8xLENGTH+6) / N_DBPS)
         *  (16 = SIGNAL time, 6 = tail bits)
         * TXTIME = T_PREAMBLE + T_SIGNAL + T_SYM x N_SYM + Signal Ext
         *
         * T_SYM = 4 usec
         * 802.11a - 18.5.2: aSIFSTime = 16 usec
         * 802.11g - 19.8.4: aSIFSTime = 10 usec +
         *  signal ext = 6 usec
         */
        dur = 16; /* SIFS + signal ext */
        dur += 16; /* IEEE 802.11-2012 18.3.2.4: T_PREAMBLE = 16 usec */
        dur += 4; /* IEEE 802.11-2012 18.3.2.4: T_SIGNAL = 4 usec */

        /* IEEE 802.11-2012 18.3.2.4: all values above are:
         *  * times 4 for 5 MHz
         *  * times 2 for 10 MHz
         */
        dur *= 1 << shift;

        /* rates should already consider the channel bandwidth,
         * don't apply divisor again.
         */
        dur += 4 * DIV_ROUND_UP((16 + 8 * (len + 4) + 6) * 10,
                    4 * rate); /* T_SYM x N_SYM */
    } else {
        /*
         * 802.11b or 802.11g with 802.11b compatibility:
         * 18.3.4: TXTIME = PreambleLength + PLCPHeaderTime +
         * Ceiling(((LENGTH+PBCC)x8)/DATARATE). PBCC=0.
         *
         * 802.11 (DS): 15.3.3, 802.11b: 18.3.4
         * aSIFSTime = 10 usec
         * aPreambleLength = 144 usec or 72 usec with short preamble
         * aPLCPHeaderLength = 48 usec or 24 usec with short preamble
         */
        dur = 10; /* aSIFSTime = 10 usec */
        dur += short_preamble ? (72 + 24) : (144 + 48);

        dur += DIV_ROUND_UP(8 * (len + 4) * 10, rate);
    }

    return dur;
}

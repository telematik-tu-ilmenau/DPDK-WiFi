/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "core.h"
#include "txrx.h"
#include "htt.h"
#include "mac.h"
#include "debug.h"

#include <generic/rte_spinlock.h>
#include <generic/rte_cycles.h>
#include <rte_ether.h>

static void ath10k_report_offchan_tx(struct ath10k *ar, struct sk_buff *skb)
{
// 	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

// 	if (likely(!(info->flags & IEEE80211_TX_CTL_TX_OFFCHAN)))
// 		return;

// 	if (ath10k_mac_tx_frm_has_freq(ar))
// 		return;

// 	 If the original wait_for_completion() timed out before
// 	 * {data,mgmt}_tx_completed() was called then we could complete
// 	 * offchan_tx_completed for a different skb. Prevent this by using
// 	 * offchan_tx_skb. 
// 	rte_spinlock_lock(&ar->data_lock);
// 	if (ar->offchan_tx_skb != skb) {
// 		ath10k_warn(ar, "completed old offchannel frame\n");
// 		goto out;
// 	}

// 	complete(&ar->offchan_tx_completed);
// 	ar->offchan_tx_skb = NULL; /* just for sanity */

// 	ath10k_dbg(ar, ATH10K_DBG_HTT, "completed offchannel skb %pK\n", skb);
// out:
// 	rte_spinlock_unlock(&ar->data_lock);
}

int ath10k_txrx_tx_unref_bulk(struct ath10k_htt *htt, const struct htt_tx_done *tx_done, __le16* msdu_ids, u8 num_msdus)
{
    if(num_msdus == 0) {
        ath10k_warn(ar, "warning: there are 0 msdu's in a bulk\n");
        return -EINVAL;
    }

    struct ath10k *ar = htt->ar;
    struct ieee80211_tx_info *info;
    struct ieee80211_txq *txq;
    struct ath10k_skb_cb *skb_cb;
    struct ath10k_txq *artxq;
    unsigned int num_msdus_processed = 0;
    struct rte_mbuf* msdu;

    // ath10k_dbg(ar, ATH10K_DBG_HTT, "htt tx completion with status %d for msdu_id's:\n", tx_done->status);
    // for(unsigned int idx = 0; idx < num_msdus - 1; ++idx) {
    //     ath10k_dbg(ar, ATH10K_DBG_HTT, "├──> %d\n", msdu_ids[idx]);
    // }
    // ath10k_dbg(ar, ATH10K_DBG_HTT, "└──> %d\n", msdu_ids[num_msdus - 1]);

    rte_spinlock_lock(&htt->tx_lock);

    for(unsigned int idx = 0; idx < num_msdus; ++idx) {

        if (msdu_ids[idx] >= htt->max_num_pending_tx) {
            assert(false);
            continue;
        }

        msdu = idr_find(&htt->pending_tx, msdu_ids[idx]);
        if (!msdu) {
            assert(false);
            continue;
        }
        ath10k_htt_tx_free_msdu_id(htt, msdu_ids[idx]);

        skb_cb = ATH10K_SKB_CB(msdu);
        txq = skb_cb->txq;

        if (txq) {
            artxq = (void *)txq->drv_priv;
            artxq->num_fw_queued--;
        }

        rte_pktmbuf_free(msdu);
        ++num_msdus_processed;
    }

    // if (htt->num_pending_tx == 0)
    //     sleepqueue_wake_all(&htt->empty_tx_wq);
    ath10k_htt_tx_dec_pending_bulk(htt, num_msdus_processed);
    rte_spinlock_unlock(&htt->tx_lock);

    // if(num_msdus_processed < num_msdus)
    //     ath10k_warn(ar, "warning: a few msdu_id's were too big or invalid - they've been ignored\n");

    // ath10k_dbg(ar, ATH10K_DBG_HTT, "htt tx completion num_msdus_processed: %d\n", num_msdus_processed);
    // for(unsigned int idx = 0; idx < num_msdus_processed; ++idx) {
        // dma_unmap_single(dev, skb_cb->paddr, msdu->len, DMA_TO_DEVICE);

        // ath10k_report_offchan_tx(htt->ar, msdus[idx]);

        /*
        info = IEEE80211_SKB_CB(msdu);
        memset(&info->status, 0, sizeof(info->status));

        if (tx_done->status == HTT_TX_COMPL_STATE_DISCARD) {
        //  ieee80211_free_txskb(htt->ar->hw, msdu);
            ath10k_free_mbuf(ar, msdu);
            return 0;
        }

        if (!(info->flags & IEEE80211_TX_CTL_NO_ACK))
            info->flags |= IEEE80211_TX_STAT_ACK;

        if (tx_done->status == HTT_TX_COMPL_STATE_NOACK)
            info->flags &= ~IEEE80211_TX_STAT_ACK;

        if ((tx_done->status == HTT_TX_COMPL_STATE_ACK) &&
            (info->flags & IEEE80211_TX_CTL_NO_ACK))
            info->flags |= IEEE80211_TX_STAT_NOACK_TRANSMITTED;
        */
        // ieee80211_tx_status(htt->ar->hw, msdu);
        // /* we do not own the msdu anymore */
        // TODO: as long as we don't have anything like ieee80211_tx_status, free the skb here
        // ath10k_free_mbuf(ar, msdus[idx]);
    // }
    // ath10k_dbg(ar, ATH10K_DBG_HTT, "htt tx completion free complete\n");

    return 0;
}

int ath10k_txrx_tx_unref(struct ath10k_htt *htt,
			 const struct htt_tx_done *tx_done)
{
	struct ath10k *ar = htt->ar;
	struct ieee80211_tx_info *info;
	struct ieee80211_txq *txq;
	struct ath10k_skb_cb *skb_cb;
	struct ath10k_txq *artxq;
	struct sk_buff *msdu;

	ath10k_dbg(ar, ATH10K_DBG_HTT,
		   "htt tx completion msdu_id %u status %d\n",
		   tx_done->msdu_id, tx_done->status);

	if (tx_done->msdu_id >= htt->max_num_pending_tx) {
		ath10k_warn(ar, "warning: msdu_id %d too big, ignoring\n",
			    tx_done->msdu_id);
		return -EINVAL;
	}

	rte_spinlock_lock(&htt->tx_lock);
	msdu = idr_find(&htt->pending_tx, tx_done->msdu_id);
	if (!msdu) {
		ath10k_warn(ar, "received tx completion for invalid msdu_id: %d\n",
			    tx_done->msdu_id);
		rte_spinlock_unlock(&htt->tx_lock);
		return -ENOENT;
	}

	skb_cb = ATH10K_SKB_CB(msdu);
	txq = skb_cb->txq;

	if (txq) {
		artxq = (void *)txq->drv_priv;
		artxq->num_fw_queued--;
	}

	ath10k_htt_tx_free_msdu_id(htt, tx_done->msdu_id);
	ath10k_htt_tx_dec_pending(htt);
	if (htt->num_pending_tx == 0)
		sleepqueue_wake_all(&htt->empty_tx_wq);
	rte_spinlock_unlock(&htt->tx_lock);

	// dma_unmap_single(dev, skb_cb->paddr, msdu->len, DMA_TO_DEVICE);

	ath10k_report_offchan_tx(htt->ar, msdu);

	info = IEEE80211_SKB_CB(msdu);
	memset(&info->status, 0, sizeof(info->status));

	if (tx_done->status == HTT_TX_COMPL_STATE_DISCARD) {
	// 	ieee80211_free_txskb(htt->ar->hw, msdu);
		ath10k_free_mbuf(ar, msdu);
		return 0;
	}

	if (!(info->flags & IEEE80211_TX_CTL_NO_ACK))
		info->flags |= IEEE80211_TX_STAT_ACK;

	if (tx_done->status == HTT_TX_COMPL_STATE_NOACK)
		info->flags &= ~IEEE80211_TX_STAT_ACK;

	if ((tx_done->status == HTT_TX_COMPL_STATE_ACK) &&
	    (info->flags & IEEE80211_TX_CTL_NO_ACK))
		info->flags |= IEEE80211_TX_STAT_NOACK_TRANSMITTED;

	// ieee80211_tx_status(htt->ar->hw, msdu);
	// /* we do not own the msdu anymore */
	// TODO: as long as we don't have anything like ieee80211_tx_status, free the skb here
	ath10k_free_mbuf(ar, msdu);

	return 0;
}

struct ath10k_peer *ath10k_peer_find(struct ath10k *ar, int vdev_id,
				     const u8 *addr)
{
	struct ath10k_peer *peer;

	lockdep_assert_held(&ar->data_lock);

	LIST_FOREACH(peer, &ar->peers, pointers) {
		if (peer->vdev_id != vdev_id)
			continue;
		if (!is_same_ether_addr(peer->addr, addr))
			continue;
		return peer;
	}

	return NULL;
}

struct ath10k_peer *ath10k_peer_find_by_id(struct ath10k *ar, int peer_id)
{
	struct ath10k_peer *peer;

	lockdep_assert_held(&ar->data_lock);

	LIST_FOREACH(peer, &ar->peers, pointers) {
		if (test_bit(peer_id, peer->peer_ids))
			return peer;
	}

	return NULL;
}

static int ath10k_wait_for_peer_common(struct ath10k *ar, int vdev_id,
				       const u8 *addr, bool expect_mapped)
{
	 uint64_t to = rte_get_timer_cycles() + rte_get_timer_hz() * ATH10K_WAIT_FOR_PEER_COMMON_TIMEOUT_HZ;
	     do {
             rte_spinlock_lock(&ar->data_lock);
             bool mapped= !!ath10k_peer_find(ar, vdev_id, addr);
             rte_spinlock_unlock(&ar->data_lock);

             if (mapped == true || test_bit(ATH10K_FLAG_CRASH_FLUSH, &ar->dev_flags))
                 return 0;
	     } while(to > rte_get_timer_cycles());

	return -ETIMEDOUT;
}

int ath10k_wait_for_peer_created(struct ath10k *ar, int vdev_id, const u8 *addr)
{
	return ath10k_wait_for_peer_common(ar, vdev_id, addr, true);
}

int ath10k_wait_for_peer_deleted(struct ath10k *ar, int vdev_id, const u8 *addr)
{
	return ath10k_wait_for_peer_common(ar, vdev_id, addr, false);
}

void ath10k_peer_map_event(struct ath10k_htt *htt,
			   struct htt_peer_map_event *ev)
{
 	struct ath10k *ar = htt->ar;
 	struct ath10k_peer *peer;

 	if (ev->peer_id >= ATH10K_MAX_NUM_PEER_IDS) {
 		ath10k_warn(ar,
 			    "received htt peer map event with idx out of bounds: %hu\n",
 			    ev->peer_id);
 		return;
 	}

 	rte_spinlock_lock(&ar->data_lock);
 	peer = ath10k_peer_find(ar, ev->vdev_id, ev->addr);
 	if (!peer) {
 		peer = kzalloc(sizeof(*peer), GFP_ATOMIC);
 		if (!peer)
 			goto exit;

 		peer->vdev_id = ev->vdev_id;
 		ether_addr_copy(ev->addr, peer->addr);
 		LIST_INSERT_HEAD(&ar->peers, peer, pointers);

 		sleepqueue_wake_all(&ar->peer_mapping_wq);
 	}

 	ath10k_info(ar, "htt peer map vdev %d peer %pM id %d\n",
 		   ev->vdev_id, ev->addr, ev->peer_id);

 	WARN_ON(ar->peer_map[ev->peer_id] && (ar->peer_map[ev->peer_id] != peer));
 	ar->peer_map[ev->peer_id] = peer;
 	set_bit(ev->peer_id, peer->peer_ids);
exit:
	rte_spinlock_unlock(&ar->data_lock);
}

void ath10k_peer_unmap_event(struct ath10k_htt *htt,
			     struct htt_peer_unmap_event *ev)
{
	struct ath10k *ar = htt->ar;
	struct ath10k_peer *peer;

	if (ev->peer_id >= ATH10K_MAX_NUM_PEER_IDS) {
		ath10k_warn(ar,
			    "received htt peer unmap event with idx out of bounds: %hu\n",
			    ev->peer_id);
		return;
	}

	rte_spinlock_lock(&ar->data_lock);
	peer = ath10k_peer_find_by_id(ar, ev->peer_id);
	if (!peer) {
		ath10k_warn(ar, "peer-unmap-event: unknown peer id %d\n",
			    ev->peer_id);
		goto exit;
	}

	ath10k_info(ar, "htt peer unmap vdev %d peer %pM id %d\n",
		   peer->vdev_id, peer->addr, ev->peer_id);

	ar->peer_map[ev->peer_id] = NULL;
	clear_bit(ev->peer_id, peer->peer_ids);

	if (bitmap_empty(peer->peer_ids, ATH10K_MAX_NUM_PEER_IDS)) {
		LIST_REMOVE(peer, pointers);
		kfree(peer);
		sleepqueue_wake_all(&ar->peer_mapping_wq);
	}

exit:
	rte_spinlock_unlock(&ar->data_lock);
}

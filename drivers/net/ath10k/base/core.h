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

#ifndef _CORE_H_
#define _CORE_H_

#include "htt.h"
#include "htc.h"
#include "hw.h"
#include "targaddrs.h"
#include "wmi.h"
#include "swap.h"
#include "sleepqueue.h"
#include "taskqueue.h"

#include <assert.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include <rte_ieee80211.h>
#include <rte_cfg80211.h>
#include <rte_mac80211.h>

#include <rte_hexdump.h>

#include <sys/queue.h>

#define MS(_v, _f) (((_v) & _f##_MASK) >> _f##_LSB)
#define SM(_v, _f) (((_v) << _f##_LSB) & _f##_MASK)
#define WO(_f)      ((_f##_OFFSET) >> 2)

#define ATH10K_SCAN_ID 0
#define WMI_READY_TIMEOUT (5 * HZ)
#define ATH10K_FLUSH_TIMEOUT_HZ (5 * HZ)
#define ATH10K_CONNECTION_LOSS_HZ (3 * HZ)
#define ATH10K_NUM_CHANS 40

/* Antenna noise floor */
#define ATH10K_DEFAULT_NOISE_FLOOR -95

#define ATH10K_MAX_NUM_MGMT_PENDING 128

/* number of failed packets (20 packets with 16 sw reties each) */
#define ATH10K_KICKOUT_THRESHOLD (20 * 16)

/*
 * Use insanely high numbers to make sure that the firmware implementation
 * won't start, we have the same functionality already in hostapd. Unit
 * is seconds.
 */
#define ATH10K_KEEPALIVE_MIN_IDLE 3747
#define ATH10K_KEEPALIVE_MAX_IDLE 3895
#define ATH10K_KEEPALIVE_MAX_UNRESPONSIVE 3900

/* NAPI poll budget */
#define ATH10K_NAPI_BUDGET      64
#define ATH10K_NAPI_QUOTA_LIMIT 60

/* SMBIOS type containing Board Data File Name Extension */
#define ATH10K_SMBIOS_BDF_EXT_TYPE 0xF8

/* SMBIOS type structure length (excluding strings-set) */
#define ATH10K_SMBIOS_BDF_EXT_LENGTH 0x9

/* Offset pointing to Board Data File Name Extension */
#define ATH10K_SMBIOS_BDF_EXT_OFFSET 0x8

/* Board Data File Name Extension string length.
 * String format: BDF_<Customer ID>_<Extension>\0
 */
#define ATH10K_SMBIOS_BDF_EXT_STR_LENGTH 0x20

/* The magic used by QCA spec */
#define ATH10K_SMBIOS_BDF_EXT_MAGIC "BDF_"

enum ath10k_bus {
	ATH10K_BUS_PCI,
	ATH10K_BUS_AHB,
	ATH10K_BUS_SDIO,
	ATH10K_BUS_USB,
};

static inline const char *ath10k_bus_str(enum ath10k_bus bus)
{
	switch (bus) {
	case ATH10K_BUS_PCI:
		return "pci";
	case ATH10K_BUS_AHB:
		return "ahb";
	case ATH10K_BUS_SDIO:
		return "sdio";
	case ATH10K_BUS_USB:
		return "usb";
	}

	return "unknown";
}

enum ath10k_skb_flags {
	ATH10K_SKB_F_NO_HWCRYPT = BIT(0),
	ATH10K_SKB_F_DTIM_ZERO = BIT(1),
	ATH10K_SKB_F_DELIVER_CAB = BIT(2),
	ATH10K_SKB_F_MGMT = BIT(3),
	ATH10K_SKB_F_QOS = BIT(4),
};

struct ath10k_skb_cb {
	dma_addr_t paddr;
	u8 flags;
	u8 eid;
	u16 msdu_id;
	u8 vdev_id;

	struct ieee80211_vif *vif;
	struct ieee80211_txq *txq;

	struct {
		u8 tid;
		u16 freq;
		bool is_offchan;
		bool nohwcrypt;

		/* These just point above; makes code easier to port */
		struct ath10k_htt_txbuf *txbuf;
		uint32_t txbuf_paddr;
	} __packed htt;

	struct {
		bool dtim_zero;
		bool deliver_cab;
		uint32_t paddr;
	} bcn;
} __packed;

static inline struct ath10k_skb_cb *ATH10K_SKB_CB(struct sk_buff *skb)
{
	// BUILD_BUG_ON(sizeof(struct ath10k_skb_cb) >
	// 	     IEEE80211_TX_INFO_DRIVER_DATA_SIZE);
	// return (struct ath10k_skb_cb *)&IEEE80211_SKB_CB(skb)->driver_data;
	// TODO: FIXME
    return (struct ath10k_skb_cb*)skb->cb;
	// return NULL;
}

#define ATH10K_CB_SKB(controlblock) \
		container_of((void *)controlblock, struct sk_buff, cb)

static inline uint32_t host_interest_item_address(uint32_t item_offset)
{
	return QCA988X_HOST_INTEREST_ADDRESS + item_offset;
}

struct ath10k_bmi {
	bool done_sent;
};

struct ath10k_mem_chunk {
	void *vaddr;
	dma_addr_t paddr;
	uint32_t len;
	uint32_t req_id;
};

struct ath10k_wmi {
	enum ath10k_htc_ep_id eid;
	struct completion service_ready;
	struct completion unified_ready;
	struct completion barrier;
	struct sleepqueue tx_credits_wq;
	struct completion tx_credits_compl;
	DECLARE_BITMAP(svc_map, WMI_SERVICE_MAX);
	struct wmi_cmd_map *cmd;
	struct wmi_vdev_param_map *vdev_param;
	struct wmi_pdev_param_map *pdev_param;
	const struct wmi_ops *ops;
	const struct wmi_peer_flags_map *peer_flags;

	uint32_t num_mem_chunks;
	uint32_t rx_decap_mode;
	struct ath10k_mem_chunk mem_chunks[WMI_MAX_MEM_REQS];
	struct rte_memzone* chunk_memzones[WMI_MAX_MEM_REQS];
};

struct ath10k_fw_stats_peer {
	struct list_head list;

	u8 peer_macaddr[ETH_ALEN];
	uint32_t peer_rssi;
	uint32_t peer_tx_rate;
	uint32_t peer_rx_rate;  /* 10x only */
	uint32_t rx_duration;
};

struct ath10k_fw_extd_stats_peer {
	struct list_head list;

	u8 peer_macaddr[ETH_ALEN];
	uint32_t rx_duration;
};

struct ath10k_fw_stats_vdev {
	struct list_head list;

	uint32_t vdev_id;
	uint32_t beacon_snr;
	uint32_t data_snr;
	uint32_t num_tx_frames[4];
	uint32_t num_rx_frames;
	uint32_t num_tx_frames_retries[4];
	uint32_t num_tx_frames_failures[4];
	uint32_t num_rts_fail;
	uint32_t num_rts_success;
	uint32_t num_rx_err;
	uint32_t num_rx_discard;
	uint32_t num_tx_not_acked;
	uint32_t tx_rate_history[10];
	uint32_t beacon_rssi_history[10];
};

struct ath10k_fw_stats_pdev {
	struct list_head list;

	/* PDEV stats */
	s32 ch_noise_floor;
	uint32_t tx_frame_count; /* Cycles spent transmitting frames */
	uint32_t rx_frame_count; /* Cycles spent receiving frames */
	uint32_t rx_clear_count; /* Total channel busy time, evidently */
	uint32_t cycle_count; /* Total on-channel time */
	uint32_t phy_err_count;
	uint32_t chan_tx_power;
	uint32_t ack_rx_bad;
	uint32_t rts_bad;
	uint32_t rts_good;
	uint32_t fcs_bad;
	uint32_t no_beacons;
	uint32_t mib_int_count;

	/* PDEV TX stats */
	s32 comp_queued;
	s32 comp_delivered;
	s32 msdu_enqued;
	s32 mpdu_enqued;
	s32 wmm_drop;
	s32 local_enqued;
	s32 local_freed;
	s32 hw_queued;
	s32 hw_reaped;
	s32 underrun;
	uint32_t hw_paused;
	s32 tx_abort;
	s32 mpdus_requed;
	uint32_t tx_ko;
	uint32_t data_rc;
	uint32_t self_triggers;
	uint32_t sw_retry_failure;
	uint32_t illgl_rate_phy_err;
	uint32_t pdev_cont_xretry;
	uint32_t pdev_tx_timeout;
	uint32_t pdev_resets;
	uint32_t phy_underrun;
	uint32_t txop_ovf;
	uint32_t seq_posted;
	uint32_t seq_failed_queueing;
	uint32_t seq_completed;
	uint32_t seq_restarted;
	uint32_t mu_seq_posted;
	uint32_t mpdus_sw_flush;
	uint32_t mpdus_hw_filter;
	uint32_t mpdus_truncated;
	uint32_t mpdus_ack_failed;
	uint32_t mpdus_expired;

	/* PDEV RX stats */
	s32 mid_ppdu_route_change;
	s32 status_rcvd;
	s32 r0_frags;
	s32 r1_frags;
	s32 r2_frags;
	s32 r3_frags;
	s32 htt_msdus;
	s32 htt_mpdus;
	s32 loc_msdus;
	s32 loc_mpdus;
	s32 oversize_amsdu;
	s32 phy_errs;
	s32 phy_err_drop;
	s32 mpdu_errs;
	s32 rx_ovfl_errs;
};

struct ath10k_fw_stats {
	bool extended;
	struct list_head pdevs;
	struct list_head vdevs;
	struct list_head peers;
	struct list_head peers_extd;
};

#define ATH10K_TPC_TABLE_TYPE_FLAG	1
#define ATH10K_TPC_PREAM_TABLE_END	0xFFFF

struct ath10k_tpc_table {
	uint32_t pream_idx[WMI_TPC_RATE_MAX];
	u8 rate_code[WMI_TPC_RATE_MAX];
	char tpc_value[WMI_TPC_RATE_MAX][WMI_TPC_TX_N_CHAIN * WMI_TPC_BUF_SIZE];
};

struct ath10k_tpc_stats {
	uint32_t reg_domain;
	uint32_t chan_freq;
	uint32_t phy_mode;
	uint32_t twice_antenna_reduction;
	uint32_t twice_max_rd_power;
	s32 twice_antenna_gain;
	uint32_t power_limit;
	uint32_t num_tx_chain;
	uint32_t ctl;
	uint32_t rate_max;
	u8 flag[WMI_TPC_FLAG];
	struct ath10k_tpc_table tpc_table[WMI_TPC_FLAG];
};

struct ath10k_dfs_stats {
	uint32_t phy_errors;
	uint32_t pulses_total;
	uint32_t pulses_detected;
	uint32_t pulses_discarded;
	uint32_t radar_detected;
};

#define ATH10K_MAX_NUM_PEER_IDS (1 << 11) /* htt rx_desc limit */

struct ath10k_peer {
    LIST_ENTRY(ath10k_peer) pointers;
	struct ieee80211_vif *vif;
	struct ieee80211_sta *sta;

	bool removed;
	int vdev_id;
	u8 addr[ETH_ALEN];
	DECLARE_BITMAP(peer_ids, ATH10K_MAX_NUM_PEER_IDS);

	/* protected by ar->data_lock */
	struct ieee80211_key_conf *keys[WMI_MAX_KEY_INDEX + 1];
};

struct ath10k_txq {
    TAILQ_ENTRY(ath10k_txq) pointers;
	unsigned long num_fw_queued;
	unsigned long num_push_allowed;
	struct ath10k_htt* htt;
};

struct ath10k_sta {
	struct ath10k_vif *arvif;

	/* the following are protected by ar->data_lock */
	uint32_t changed; /* IEEE80211_RC_* */
	uint32_t bw;
	uint32_t nss;
	uint32_t smps;
	u16 peer_id;
	struct rate_info txrate;

	struct task update_wk;

#ifdef CONFIG_MAC80211_DEBUGFS
	/* protected by conf_mutex */
	bool aggr_mode;
	u64 rx_duration;
#endif
};

#define ATH10K_VDEV_SETUP_TIMEOUT_HZ (5 * HZ)
#define ATH10K_WAIT_FOR_PEER_COMMON_TIMEOUT_HZ (3 * HZ)

enum ath10k_beacon_state {
	ATH10K_BEACON_SCHEDULED = 0,
	ATH10K_BEACON_SENDING,
	ATH10K_BEACON_SENT,
};

struct ath10k_vif {
	LIST_ENTRY(ath10k_vif) pointers;

	uint32_t vdev_id;
	u16 peer_id;
	enum wmi_vdev_type vdev_type;
	enum wmi_vdev_subtype vdev_subtype;
	uint32_t beacon_interval;
	uint32_t dtim_period;
	struct sk_buff *beacon;
// 	/* protected by data_lock */
	enum ath10k_beacon_state beacon_state;
	void *beacon_buf;
	dma_addr_t beacon_paddr;
	unsigned long tx_paused; /* arbitrary values defined by target */

	struct ath10k *ar;
	struct ieee80211_vif *vif;

	bool is_started;
	bool is_up;
	bool spectral_enabled;
	bool ps;
	uint32_t aid;
	u8 bssid[ETH_ALEN];

	struct ieee80211_key_conf *wep_keys[WMI_MAX_KEY_INDEX + 1];
	s8 def_wep_key_idx;

	u16 tx_seq_no;

	union {
		struct {
			uint32_t uapsd;
		} sta;
		struct {
			/* 512 stations */
			u8 tim_bitmap[64];
			u8 tim_len;
			uint32_t ssid_len;
			u8 ssid[IEEE80211_MAX_SSID_LEN];
			bool hidden_ssid;
			/* P2P_IE with NoA attribute for P2P_GO case */
			uint32_t noa_len;
			u8 *noa_data;
		} ap;
	} u;

	bool use_cts_prot;
	bool nohwcrypt;
	int num_legacy_stations;
	int txpower;
	struct wmi_wmm_params_all_arg wmm_params;
 	struct task ap_csa_work;
 	struct delayed_work connection_loss_work;
	struct cfg80211_bitrate_mask bitrate_mask;
};

struct ath10k_vif_iter {
	u32 vdev_id;
	struct ath10k_vif *arvif;
};

/* Copy Engine register dump, protected by ce-lock */
struct ath10k_ce_crash_data {
	__le32 base_addr;
	__le32 src_wr_idx;
	__le32 src_r_idx;
	__le32 dst_wr_idx;
	__le32 dst_r_idx;
};

struct ath10k_ce_crash_hdr {
	__le32 ce_count;
	__le32 reserved[3]; /* for future use */
	struct ath10k_ce_crash_data entries[];
};

/* used for crash-dump storage, protected by data-lock */
struct ath10k_fw_crash_data {
	bool crashed_since_read;

	uint32_t guid;
	struct timespec timestamp;
	__le32 registers[REG_DUMP_COUNT_QCA988X];
	struct ath10k_ce_crash_data ce_crash_data[CE_COUNT_MAX];
};

enum ath10k_state {
	ATH10K_STATE_OFF = 0,
	ATH10K_STATE_ON,

	/* When doing firmware recovery the device is first powered down.
	 * mac80211 is supposed to call in to start() hook later on. It is
	 * however possible that driver unloading and firmware crash overlap.
	 * mac80211 can wait on conf_mutex in stop() while the device is
	 * stopped in ath10k_core_restart() work holding conf_mutex. The state
	 * RESTARTED means that the device is up and mac80211 has started hw
	 * reconfiguration. Once mac80211 is done with the reconfiguration we
	 * set the state to STATE_ON in reconfig_complete(). */
	ATH10K_STATE_RESTARTING,
	ATH10K_STATE_RESTARTED,

	/* The device has crashed while restarting hw. This state is like ON
	 * but commands are blocked in HTC and -ECOMM response is given. This
	 * prevents completion timeouts and makes the driver more responsive to
	 * userspace commands. This is also prevents recursive recovery. */
	ATH10K_STATE_WEDGED,

	/* factory tests */
	ATH10K_STATE_UTF,
};

enum ath10k_firmware_mode {
	/* the default mode, standard 802.11 functionality */
	ATH10K_FIRMWARE_MODE_NORMAL,

	/* factory tests etc */
	ATH10K_FIRMWARE_MODE_UTF,
};

enum ath10k_fw_features {
/* wmi_mgmt_rx_hdr contains extra RSSI information */
	ATH10K_FW_FEATURE_EXT_WMI_MGMT_RX = 0,

	/* Firmware from 10X branch. Deprecated, don't use in new code. */
	ATH10K_FW_FEATURE_WMI_10X = 1,

	/* firmware support tx frame management over WMI, otherwise it's HTT */
	ATH10K_FW_FEATURE_HAS_WMI_MGMT_TX = 2,

	/* Firmware does not support P2P */
	ATH10K_FW_FEATURE_NO_P2P = 3,

	/* Firmware 10.2 feature bit. The ATH10K_FW_FEATURE_WMI_10X feature
	 * bit is required to be set as well. Deprecated, don't use in new
	 * code.
	 */
	ATH10K_FW_FEATURE_WMI_10_2 = 4,

	/* Some firmware revisions lack proper multi-interface client powersave
	 * implementation. Enabling PS could result in connection drops,
	 * traffic stalls, etc.
	 */
	ATH10K_FW_FEATURE_MULTI_VIF_PS_SUPPORT = 5,

	/* Some firmware revisions have an incomplete WoWLAN implementation
	 * despite WMI service bit being advertised. This feature flag is used
	 * to distinguish whether WoWLAN is really supported or not.
	 */
	ATH10K_FW_FEATURE_WOWLAN_SUPPORT = 6,

	/* Don't trust error code from otp.bin */
	ATH10K_FW_FEATURE_IGNORE_OTP_RESULT = 7,

	/* Some firmware revisions pad 4th hw address to 4 byte boundary making
	 * it 8 bytes long in Native Wifi Rx decap.
	 */
	ATH10K_FW_FEATURE_NO_NWIFI_DECAP_4ADDR_PADDING = 8,

	/* Firmware supports bypassing PLL setting on init. */
	ATH10K_FW_FEATURE_SUPPORTS_SKIP_CLOCK_INIT = 9,

	/* Raw mode support. If supported, FW supports receiving and trasmitting
	 * frames in raw mode.
	 */
	ATH10K_FW_FEATURE_RAW_MODE_SUPPORT = 10,

	/* Firmware Supports Adaptive CCA*/
	ATH10K_FW_FEATURE_SUPPORTS_ADAPTIVE_CCA = 11,

	/* Firmware supports management frame protection */
	ATH10K_FW_FEATURE_MFP_SUPPORT = 12,

	/* Firmware supports pull-push model where host shares it's software
	 * queue state with firmware and firmware generates fetch requests
	 * telling host which queues to dequeue tx from.
	 *
	 * Primary function of this is improved MU-MIMO performance with
	 * multiple clients.
	 */
	ATH10K_FW_FEATURE_PEER_FLOW_CONTROL = 13,

	/* Firmware supports BT-Coex without reloading firmware via pdev param.
	 * To support Bluetooth coexistence pdev param, WMI_COEX_GPIO_SUPPORT of
	 * extended resource config should be enabled always. This firmware IE
	 * is used to configure WMI_COEX_GPIO_SUPPORT.
	 */
	ATH10K_FW_FEATURE_BTCOEX_PARAM = 14,

	/* Unused flag and proven to be not working, enable this if you want
	 * to experiment sending NULL func data frames in HTT TX
	 */
	ATH10K_FW_FEATURE_SKIP_NULL_FUNC_WAR = 15,

	/* Firmware allow other BSS mesh broadcast/multicast frames without
	 * creating monitor interface. Appropriate rxfilters are programmed for
	 * mesh vdev by firmware itself. This feature flags will be used for
	 * not creating monitor vdev while configuring mesh node.
	 */
	ATH10K_FW_FEATURE_ALLOWS_MESH_BCAST = 16,

	/* Firmware does not support power save in station mode. */
	ATH10K_FW_FEATURE_NO_PS = 17,

	/* tx-status has the noack bits (CT firmware version 14 and higher ) */
	ATH10K_FW_FEATURE_HAS_TXSTATUS_NOACK = 30,

	/* Firmware from Candela Technologies, enables more VIFs, etc */
	ATH10K_FW_FEATURE_WMI_10X_CT = 31,

	/* Firmware from Candela Technologies with rx-software-crypt.
	 * Required for multiple stations connected to same AP when using
	 * encryption (ie, commercial version of CT firmware) */
	ATH10K_FW_FEATURE_CT_RXSWCRYPT = 32,

	/* Firmware supports extended wmi_common_peer_assoc_complete_cmd that contains
	 * an array of rate-disable masks.  This allows the host to have better control
	 * over what rates the firmware will use.  CT Firmware only (v15 and higher)
	 */
	ATH10K_FW_FEATURE_CT_RATEMASK = 33,

	/* Versions of firmware before approximately 10.2.4.72 would corrupt txop fields
	 * during burst.  Since this is fixed now, add a flag to denote this.
	 */
	ATH10K_FW_FEATURE_HAS_SAFE_BURST = 34,

	/* Register-dump is supported. */
	ATH10K_FW_FEATURE_REGDUMP_CT = 35,

	/* TX-Rate is reported. */
	ATH10K_FW_FEATURE_TXRATE_CT = 36,

	/* Firmware can flush all peers. */
	ATH10K_FW_FEATURE_FLUSH_ALL_CT = 37,

	/* Firmware can read memory with ping-pong protocol. */
	ATH10K_FW_FEATURE_PINGPONG_READ_CT = 38,

	/* Firmware can skip channel reservation. */
	ATH10K_FW_FEATURE_SKIP_CH_RES_CT = 39,

	/* Firmware supports NOPcan skip channel reservation. */
	ATH10K_FW_FEATURE_NOP_CT = 40,

	/* Firmware supports CT HTT MGT feature. */
	ATH10K_FW_FEATURE_HTT_MGT_CT = 41,

	/* Set-special cmd-id is supported. */
	ATH10K_FW_FEATURE_SET_SPECIAL_CT = 42,

	/* SW Beacon Miss is disabled in this kernel, so you have to
	 * let mac80211 manage the connection.
	 */
	ATH10K_FW_FEATURE_NO_BMISS_CT = 43,

	/* 10.1 firmware that supports getting temperature.  Stock
	 * 10.1 cannot.
	 */
	ATH10K_FW_FEATURE_HAS_GET_TEMP_CT = 44,

	/* keep last */
	ATH10K_FW_FEATURE_COUNT,
};

enum ath10k_dev_flags {
	/* Indicates that ath10k device is during CAC phase of DFS */
	ATH10K_CAC_RUNNING,
	ATH10K_FLAG_CORE_REGISTERED,

	/* Device has crashed and needs to restart. This indicates any pending
	 * waiters should immediately cancel instead of waiting for a time out.
	 */
	ATH10K_FLAG_CRASH_FLUSH,

	/* Use Raw mode instead of native WiFi Tx/Rx encap mode.
	 * Raw mode supports both hardware and software crypto. Native WiFi only
	 * supports hardware crypto.
	 */
	ATH10K_FLAG_RAW_MODE,

	/* Disable HW crypto engine */
	ATH10K_FLAG_HW_CRYPTO_DISABLED,

	/* Bluetooth coexistance enabled */
	ATH10K_FLAG_BTCOEX,

	/* Per Station statistics service */
	ATH10K_FLAG_PEER_STATS,
};

enum ath10k_cal_mode {
	ATH10K_CAL_MODE_FILE,
	ATH10K_CAL_MODE_OTP,
	ATH10K_CAL_MODE_DT,
	ATH10K_PRE_CAL_MODE_FILE,
	ATH10K_PRE_CAL_MODE_DT,
	ATH10K_CAL_MODE_EEPROM,
};

enum ath10k_crypt_mode {
	/* Only use hardware crypto engine */
	ATH10K_CRYPT_MODE_HW,
	/* Only use software crypto engine */
	ATH10K_CRYPT_MODE_SW,
};

static inline const char *ath10k_cal_mode_str(enum ath10k_cal_mode mode)
{
	switch (mode) {
	case ATH10K_CAL_MODE_FILE:
		return "file";
	case ATH10K_CAL_MODE_OTP:
		return "otp";
	case ATH10K_CAL_MODE_DT:
		return "dt";
	case ATH10K_PRE_CAL_MODE_FILE:
		return "pre-cal-file";
	case ATH10K_PRE_CAL_MODE_DT:
		return "pre-cal-dt";
	case ATH10K_CAL_MODE_EEPROM:
		return "eeprom";
	}

	return "unknown";
}

enum ath10k_scan_state {
	ATH10K_SCAN_IDLE,
	ATH10K_SCAN_STARTING,
	ATH10K_SCAN_RUNNING,
	ATH10K_SCAN_ABORTING,
};

static inline const char *ath10k_scan_state_str(enum ath10k_scan_state state)
{
	switch (state) {
	case ATH10K_SCAN_IDLE:
		return "idle";
	case ATH10K_SCAN_STARTING:
		return "starting";
	case ATH10K_SCAN_RUNNING:
		return "running";
	case ATH10K_SCAN_ABORTING:
		return "aborting";
	}

	return "unknown";
}

enum ath10k_tx_pause_reason {
	ATH10K_TX_PAUSE_Q_FULL,
	ATH10K_TX_PAUSE_MAX,
};

struct ath10k_fw_file {
	const struct firmware *firmware;

	char fw_version[ETHTOOL_FWVERS_LEN];

	DECLARE_BITMAP(fw_features, ATH10K_FW_FEATURE_COUNT);

	enum ath10k_fw_wmi_op_version wmi_op_version;
	enum ath10k_fw_htt_op_version htt_op_version;

	const void *firmware_data;
	size_t firmware_len;

	const void *otp_data;
	size_t otp_len;

	const void *codeswap_data;
	size_t codeswap_len;

	/* The original idea of struct ath10k_fw_file was that it only
	 * contains struct firmware and pointers to various parts (actual
	 * firmware binary, otp, metadata etc) of the file. This seg_info
	 * is actually created separate but as this is used similarly as
	 * the other firmware components it's more convenient to have it
	 * here.
	 */
	struct ath10k_swap_code_seg_info *firmware_swap_code_seg_info;
};

struct ath10k_fw_components {
	const struct firmware *board;
	const void *board_data;
	size_t board_len;

	struct ath10k_fw_file fw_file;
};

struct ath10k_adapter;

struct ath10k_per_peer_tx_stats {
       uint32_t     succ_bytes;
       uint32_t     retry_bytes;
       uint32_t     failed_bytes;
       u8      ratecode;
       u8      flags;
       u16     peer_id;
       u16     succ_pkts;
       u16     retry_pkts;
       u16     failed_pkts;
       u16     duration;
       uint32_t     reserved1;
       uint32_t     reserved2;
};

struct ath10k {
	struct ath10k_adapter *adapter; // pointer to parent
	struct ath_common ath_common;
	struct ieee80211_hw* hw;
	struct rte_eth_dev *dev;
	u8 mac_addr[ETH_ALEN];

	enum ath10k_hw_rev hw_rev;
	u16 dev_id;
	u32 chip_id;
	u32 target_version;
	u8 fw_version_major;
	u32 fw_version_minor;
	u16 fw_version_release;
	u16 fw_version_build;
	u32 fw_stats_req_mask;
	u32 phy_capability;
	u32 hw_min_tx_power;
	u32 hw_max_tx_power;
	u32 hw_eeprom_rd;
	u32 ht_cap_info;
	u32 vht_cap_info;
	u32 num_rf_chains;
	u32 max_spatial_stream;
	/* protected by conf_mutex */
	u32 low_5ghz_chan;
	u32 high_5ghz_chan;
	bool ani_enabled;

	bool p2p;

	struct {
		enum ath10k_bus bus;
		const struct ath10k_hif_ops *ops;
	} hif;

	struct completion target_suspend;

	const struct ath10k_hw_regs *regs;
	const struct ath10k_hw_ce_regs *hw_ce_regs;
	const struct ath10k_hw_values *hw_values;
	struct ath10k_bmi bmi;
	struct ath10k_wmi wmi;
	struct ath10k_htc htc;
	struct ath10k_htt htt;

	struct ath10k_hw_params hw_params;

	/* contains the firmware images used with ATH10K_FIRMWARE_MODE_NORMAL */
	struct ath10k_fw_components normal_mode_fw;

	/* READ-ONLY images of the running firmware, which can be either
	 * normal or UTF. Do not modify, release etc!
	 */
	const struct ath10k_fw_components *running_fw;

	const struct firmware *pre_cal_file;
	const struct firmware *cal_file;

	struct {
		u32 vendor;
		u32 device;
		u32 subsystem_vendor;
		u32 subsystem_device;

		bool bmi_ids_valid;
		u8 bmi_board_id;
		u8 bmi_chip_id;

		char bdf_ext[ATH10K_SMBIOS_BDF_EXT_STR_LENGTH];
	} id;

	int fw_api;
	int bd_api;
	enum ath10k_cal_mode cal_mode;

	struct {
		struct completion started;
		struct completion completed;
		struct completion on_channel;
		struct delayed_work timeout;
		enum ath10k_scan_state state;
		bool is_roc;
		int vdev_id;
		int roc_freq;
		bool roc_notify;
	} scan;

	struct {
		struct ieee80211_supported_band sbands[NUM_NL80211_BANDS];
	} mac;

	/* should never be NULL; needed for regular htt rx */
	struct ieee80211_channel *rx_channel;

	/* valid during scan; needed for mgmt rx during scan */
	struct ieee80211_channel *scan_channel;

	// /* current operating channel definition */
	// struct cfg80211_chan_def chandef;

	/* currently configured operating channel in firmware */
	struct ieee80211_channel *tgt_oper_chan;

	unsigned long long free_vdev_map;
	struct ath10k_vif *monitor_arvif;
	bool monitor;
	int monitor_vdev_id;
	bool monitor_started;
	unsigned int filter_flags;
	unsigned long dev_flags;
	bool dfs_block_radar_events;

	/* protected by conf_mutex */
	bool radar_enabled;
	int num_started_vdevs;

	/* Protected by conf-mutex */
	u8 cfg_tx_chainmask;
	u8 cfg_rx_chainmask;

	struct completion install_key_done;

	struct completion vdev_setup_done;

	struct taskqueue *workqueue;
	//  Auxiliary workqueue
	struct taskqueue *workqueue_aux;

	/* prevents concurrent FW reconfiguration */
	rte_spinlock_t conf_lock;

	/* protects shared structure data */
	rte_spinlock_t data_lock;
	/* protects: ar->txqs, artxq->list */
	rte_spinlock_t txqs_lock;

	TAILQ_HEAD(ath10k_txq_tailq, ath10k_txq) txqs;
	LIST_HEAD(ath10k_vif_list, ath10k_vif) arvifs;
	LIST_HEAD(ath10k_peer_list, ath10k_peer) peers;
	struct ath10k_peer *peer_map[ATH10K_MAX_NUM_PEER_IDS];
	struct sleepqueue peer_mapping_wq;

	/* protected by conf_mutex */
	int num_peers;
	int num_stations;

	int max_num_peers;
	int max_num_stations;
	int max_num_vdevs;
	int max_num_tdls_vdevs;
	int num_active_peers;
	int num_tids;

	struct task svc_rdy_work;
	struct sk_buff *svc_rdy_skb;

	struct task offchan_tx_work;
	skb_tailq_t offchan_tx_queue;
	struct completion offchan_tx_completed;
	struct sk_buff *offchan_tx_skb;

	struct task wmi_mgmt_tx_work;
	skb_tailq_t wmi_mgmt_tx_queue;

	enum ath10k_state state;

	struct task register_work;
	struct task restart_work;

	/* cycle count is reported twice for each visited channel during scan.
	 * access protected by data_lock */
	uint32_t survey_last_rx_clear_count;
	uint32_t survey_last_cycle_count;
	struct survey_info survey[ATH10K_NUM_CHANS];

	/* Channel info events are expected to come in pairs without and with
	 * COMPLETE flag set respectively for each channel visit during scan.
	 *
	 * However there are deviations from this rule. This flag is used to
	 * avoid reporting garbage data.
	 */
	bool ch_info_can_report_survey;
	struct completion bss_survey_done;

	// struct dfs_pattern_detector *dfs_detector;

	unsigned long tx_paused; /* see ATH10K_TX_PAUSE_ */

	struct {
		/* protected by conf_mutex */
		struct ath10k_fw_components utf_mode_fw;

		/* protected by data_lock */
		bool utf_monitor;
	} testmode;

	struct {
		/* protected by data_lock */
		uint32_t fw_crash_counter;
		uint32_t fw_warm_reset_counter;
		uint32_t fw_cold_reset_counter;
	} stats;

	struct ath10k_per_peer_tx_stats peer_tx_stats;

	rte_spinlock_t mpool_lock;
	struct rte_mempool *mpool;

  bool powered_up;
  bool polling_enabled;
  uint64_t last_poll_timestamp;

    struct work_struct set_coverage_class_work;
    /* protected by conf_mutex */
    struct {
        /* writing also protected by data_lock */
        s16 coverage_class;

        u32 reg_phyclk;
        u32 reg_slottime_conf;
        u32 reg_slottime_orig;
        u32 reg_ack_cts_timeout_conf;
        u32 reg_ack_cts_timeout_orig;
    } fw_coverage;

    u32 ampdu_reference;

	void *ce_priv;

	/* must be last */
	u8 drv_priv[0] __aligned(sizeof(void *));
};

// --------------------------------------------------
/* Structure to store private data of the driver. */
// this is for the ath10k_ethdev
struct ath10k_mac_info {
	u16 	rar_entry_count;
	u8 	addr[ETH_ADDR_LEN];
};

struct ath10k_hw {
	u8 			*hw_addr;
	u16 			device_id;
	struct ath10k_mac_info	mac;
};

struct ath10k_adapter {
	struct ath10k_hw      	hw;
	bool                	stopped;
	struct rte_eth_dev	*dev; // pointer to parent
	/* MUST BE LAST */
	struct ath10k*       	ar;
};

#define ATH10K_DEV_PRIVATE(adapter) \
	    ((struct ath10k_adapter *)adapter)

#define ATH10K_DEV_PRIVATE_TO_HW(adapter) \
	    (&((struct ath10k_adapter *)adapter)->hw)


static inline bool ath10k_peer_stats_enabled(struct ath10k *ar)
{
	if (test_bit(ATH10K_FLAG_PEER_STATS, &ar->dev_flags) &&
	    test_bit(WMI_SERVICE_PEER_STATS, ar->wmi.svc_map))
		return true;

	return false;
}

static inline struct rte_mbuf *ath10k_alloc_mbuf(struct ath10k *ar, unsigned int length) {
	assert(ar->mpool != NULL);
	struct rte_mbuf *mbuf = NULL;

	// rte_spinlock_lock(&ar->mpool_lock);
	mbuf = rte_pktmbuf_alloc(ar->mpool);
	assert(rte_pktmbuf_data_room_size(ar->mpool) >= length);

	// for temporary debug only
	assert(mbuf);
	if(mbuf->buf_addr == NULL) {
	    RTE_LOG(DEBUG, PMD, "mpool status: maxSize %d; inUseCount %d\n", ar->mpool->size, rte_mempool_in_use_count(ar->mpool));
	    assert(mbuf->buf_addr);
	    goto err_unlock;
	}

err_unlock:
	// rte_spinlock_unlock(&ar->mpool_lock);
	return mbuf;
}

static inline void ath10k_free_mbuf(struct ath10k* ar, struct rte_mbuf *mbuf) {
	// rte_spinlock_lock(&ar->mpool_lock);
	if(mbuf != NULL) {
		rte_pktmbuf_free(mbuf);
	}
	// rte_spinlock_unlock(&ar->mpool_lock);
}

struct ath10k *ath10k_core_create(size_t priv_size, struct rte_eth_dev *dev,
				  enum ath10k_bus bus,
				  enum ath10k_hw_rev hw_rev,
				  const struct ath10k_hif_ops *hif_ops);
void ath10k_core_destroy(struct ath10k *ar);
void ath10k_core_get_fw_features_str(struct ath10k *ar,
				     char *buf,
				     size_t max_len);
int ath10k_core_fetch_firmware_api_n(struct ath10k *ar, const char *name,
				     struct ath10k_fw_file *fw_file);

int ath10k_core_start(struct ath10k *ar, enum ath10k_firmware_mode mode,
		      const struct ath10k_fw_components *fw_components);
int ath10k_wait_for_suspend(struct ath10k *ar, uint32_t suspend_opt);
void ath10k_core_stop(struct ath10k *ar);
int ath10k_core_register(struct ath10k *ar, uint32_t chip_id);
void ath10k_core_unregister(struct ath10k *ar);

#endif /* _CORE_H_ */

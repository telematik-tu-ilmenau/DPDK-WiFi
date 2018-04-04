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

#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <rte_hexdump.h>
#include <rte_log.h>


enum ath10k_debug_mask {
	ATH10K_DBG_PCI			= 0x00000001,
	ATH10K_DBG_WMI			= 0x00000002,
	ATH10K_DBG_HTC			= 0x00000004,
	ATH10K_DBG_HTT			= 0x00000008,
	ATH10K_DBG_MAC			= 0x00000010,
	ATH10K_DBG_BOOT			= 0x00000020,
	ATH10K_DBG_PCI_DUMP		= 0x00000040,
	ATH10K_DBG_HTT_DUMP		= 0x00000080,
	ATH10K_DBG_MGMT			= 0x00000100,
	ATH10K_DBG_DATA			= 0x00000200,
	ATH10K_DBG_BMI			= 0x00000400,
	ATH10K_DBG_REGULATORY	= 0x00000800,
	ATH10K_DBG_TESTMODE		= 0x00001000,
	ATH10K_DBG_WMI_PRINT	= 0x00002000,
	ATH10K_DBG_PCI_PS		= 0x00004000,
	ATH10K_DBG_AHB			= 0x00008000,
	ATH10K_DBG_ANY			= 0xffffffff,
};

enum ath10k_pktlog_filter {
	ATH10K_PKTLOG_RX         = 0x000000001,
	ATH10K_PKTLOG_TX         = 0x000000002,
	ATH10K_PKTLOG_RCFIND     = 0x000000004,
	ATH10K_PKTLOG_RCUPDATE   = 0x000000008,
	ATH10K_PKTLOG_DBG_PRINT  = 0x000000010,
	ATH10K_PKTLOG_ANY        = 0x00000001f,
};

enum ath10k_dbg_aggr_mode {
	ATH10K_DBG_AGGR_MODE_AUTO,
	ATH10K_DBG_AGGR_MODE_MANUAL,
	ATH10K_DBG_AGGR_MODE_MAX,
};

#define ATH10K_DBG_BOOT 0x00000020

#define dev_err(x, msg, ...) RTE_LOG(ERR, PMD, msg, ##__VA_ARGS__)
#define dev_dbg(x, msg, ...) RTE_LOG(DEBUG, PMD, msg, ##__VA_ARGS__)
#define ath10k_err(x, msg, ...) RTE_LOG(ERR, PMD, msg, ##__VA_ARGS__)
#define ath10k_warn(x, msg, ...) RTE_LOG(WARNING, PMD, msg, ##__VA_ARGS__)
#define ath10k_dbg(x, y, msg, ...) RTE_LOG(DEBUG, PMD, msg, ##__VA_ARGS__)
#define ath10k_info(x, msg, ...) RTE_LOG(INFO, PMD, msg, ##__VA_ARGS__)

/* FIXME: How to calculate the buffer size sanely? */
#define ATH10K_FW_STATS_BUF_SIZE (1024 * 1024)

extern unsigned int ath10k_debug_mask;

void ath10k_debug_print_hwfw_info(struct ath10k *ar);
void ath10k_debug_print_board_info(struct ath10k *ar);
void ath10k_debug_print_boot_info(struct ath10k *ar);
void ath10k_print_driver_info(struct ath10k *ar);

void ath10k_dbg_dump(struct ath10k *ar,
		     enum ath10k_debug_mask mask,
		     const char *msg, const char *prefix,
		     const void *buf, size_t len);
#endif /* _DEBUG_H_ */

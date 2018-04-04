/*
 * IEEE 802.11 defines
 *
 * Copyright (c) 2001-2002, SSH Communications Security Corp and Jouni Malinen
 * <jkmaline@cc.hut.fi>
 * Copyright (c) 2002-2003, Jouni Malinen <jkmaline@cc.hut.fi>
 * Copyright (c) 2005, Devicescape Software, Inc.
 * Copyright (c) 2006, Michael Wu <flamingice@sourmilk.net>
 * Copyright (c) 2013 - 2014 Intel Mobile Communications GmbH
 * Copyright (c) 2016 Intel Deutschland GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef LINUX_IEEE80211_H
#define LINUX_IEEE80211_H

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <stdbool.h>
#include "rte_general.h"

/*
 * DS bit usage
 *
 * TA = transmitter address
 * RA = receiver address
 * DA = destination address
 * SA = source address
 *
 * ToDS    FromDS  A1(RA)  A2(TA)  A3      A4      Use
 * -----------------------------------------------------------------
 *  0       0       DA      SA      BSSID   -       IBSS/DLS
 *  0       1       DA      BSSID   SA      -       AP -> STA
 *  1       0       BSSID   SA      DA      -       AP <- STA
 *  1       1       RA      TA      DA      SA      unspecified (WDS)
 */

#define FCS_LEN 4

#define IEEE80211_FCTL_VERS     0x0003
#define IEEE80211_FCTL_FTYPE        0x000c
#define IEEE80211_FCTL_STYPE        0x00f0
#define IEEE80211_FCTL_TODS     0x0100
#define IEEE80211_FCTL_FROMDS       0x0200
#define IEEE80211_FCTL_MOREFRAGS    0x0400
#define IEEE80211_FCTL_RETRY        0x0800
#define IEEE80211_FCTL_PM       0x1000
#define IEEE80211_FCTL_MOREDATA     0x2000
#define IEEE80211_FCTL_PROTECTED    0x4000
#define IEEE80211_FCTL_ORDER        0x8000
#define IEEE80211_FCTL_CTL_EXT      0x0f00

#define IEEE80211_SCTL_FRAG     0x000F
#define IEEE80211_SCTL_SEQ      0xFFF0

#define IEEE80211_FTYPE_MGMT        0x0000
#define IEEE80211_FTYPE_CTL     0x0004
#define IEEE80211_FTYPE_DATA        0x0008
#define IEEE80211_FTYPE_EXT     0x000c

/* management */
#define IEEE80211_STYPE_ASSOC_REQ   0x0000
#define IEEE80211_STYPE_ASSOC_RESP  0x0010
#define IEEE80211_STYPE_REASSOC_REQ 0x0020
#define IEEE80211_STYPE_REASSOC_RESP    0x0030
#define IEEE80211_STYPE_PROBE_REQ   0x0040
#define IEEE80211_STYPE_PROBE_RESP  0x0050
#define IEEE80211_STYPE_BEACON      0x0080
#define IEEE80211_STYPE_ATIM        0x0090
#define IEEE80211_STYPE_DISASSOC    0x00A0
#define IEEE80211_STYPE_AUTH        0x00B0
#define IEEE80211_STYPE_DEAUTH      0x00C0
#define IEEE80211_STYPE_ACTION      0x00D0

/* control */
#define IEEE80211_STYPE_CTL_EXT     0x0060
#define IEEE80211_STYPE_BACK_REQ    0x0080
#define IEEE80211_STYPE_BACK        0x0090
#define IEEE80211_STYPE_PSPOLL      0x00A0
#define IEEE80211_STYPE_RTS     0x00B0
#define IEEE80211_STYPE_CTS     0x00C0
#define IEEE80211_STYPE_ACK     0x00D0
#define IEEE80211_STYPE_CFEND       0x00E0
#define IEEE80211_STYPE_CFENDACK    0x00F0

/* data */
#define IEEE80211_STYPE_DATA            0x0000
#define IEEE80211_STYPE_DATA_CFACK      0x0010
#define IEEE80211_STYPE_DATA_CFPOLL     0x0020
#define IEEE80211_STYPE_DATA_CFACKPOLL      0x0030
#define IEEE80211_STYPE_NULLFUNC        0x0040
#define IEEE80211_STYPE_CFACK           0x0050
#define IEEE80211_STYPE_CFPOLL          0x0060
#define IEEE80211_STYPE_CFACKPOLL       0x0070
#define IEEE80211_STYPE_QOS_DATA        0x0080
#define IEEE80211_STYPE_QOS_DATA_CFACK      0x0090
#define IEEE80211_STYPE_QOS_DATA_CFPOLL     0x00A0
#define IEEE80211_STYPE_QOS_DATA_CFACKPOLL  0x00B0
#define IEEE80211_STYPE_QOS_NULLFUNC        0x00C0
#define IEEE80211_STYPE_QOS_CFACK       0x00D0
#define IEEE80211_STYPE_QOS_CFPOLL      0x00E0
#define IEEE80211_STYPE_QOS_CFACKPOLL       0x00F0

/* extension, added by 802.11ad */
#define IEEE80211_STYPE_DMG_BEACON      0x0000

/* control extension - for IEEE80211_FTYPE_CTL | IEEE80211_STYPE_CTL_EXT */
#define IEEE80211_CTL_EXT_POLL      0x2000
#define IEEE80211_CTL_EXT_SPR       0x3000
#define IEEE80211_CTL_EXT_GRANT 0x4000
#define IEEE80211_CTL_EXT_DMG_CTS   0x5000
#define IEEE80211_CTL_EXT_DMG_DTS   0x6000
#define IEEE80211_CTL_EXT_SSW       0x8000
#define IEEE80211_CTL_EXT_SSW_FBACK 0x9000
#define IEEE80211_CTL_EXT_SSW_ACK   0xa000


#define IEEE80211_SN_MASK       ((IEEE80211_SCTL_SEQ) >> 4)
#define IEEE80211_MAX_SN        IEEE80211_SN_MASK
#define IEEE80211_SN_MODULO     (IEEE80211_MAX_SN + 1)

static inline bool ieee80211_sn_less(uint16_t sn1, uint16_t sn2)
{
    return ((sn1 - sn2) & IEEE80211_SN_MASK) > (IEEE80211_SN_MODULO >> 1);
}

static inline uint16_t ieee80211_sn_add(uint16_t sn1, uint16_t sn2)
{
    return (sn1 + sn2) & IEEE80211_SN_MASK;
}

static inline uint16_t ieee80211_sn_inc(uint16_t sn)
{
    return ieee80211_sn_add(sn, 1);
}

static inline uint16_t ieee80211_sn_sub(uint16_t sn1, uint16_t sn2)
{
    return (sn1 - sn2) & IEEE80211_SN_MASK;
}

#define IEEE80211_SEQ_TO_SN(seq)    (((seq) & IEEE80211_SCTL_SEQ) >> 4)
#define IEEE80211_SN_TO_SEQ(ssn)    (((ssn) << 4) & IEEE80211_SCTL_SEQ)

/* miscellaneous IEEE 802.11 constants */
#define IEEE80211_MAX_FRAG_THRESHOLD    2352
#define IEEE80211_MAX_RTS_THRESHOLD 2353
#define IEEE80211_MAX_AID       2007
#define IEEE80211_MAX_TIM_LEN       251
#define IEEE80211_MAX_MESH_PEERINGS 63
/* Maximum size for the MA-UNITDATA primitive, 802.11 standard section
   6.2.1.1.2.

   802.11e clarifies the figure in section 7.1.2. The frame body is
   up to 2304 octets long (maximum MSDU size) plus any crypt overhead. */
#define IEEE80211_MAX_DATA_LEN      2304
/* 802.11ad extends maximum MSDU size for DMG (freq > 40Ghz) networks
 * to 7920 bytes, see 8.2.3 General frame format
 */
#define IEEE80211_MAX_DATA_LEN_DMG  7920
/* 30 byte 4 addr hdr, 2 byte QoS, 2304 byte MSDU, 12 byte crypt, 4 byte FCS */
#define IEEE80211_MAX_FRAME_LEN     2352

/* Maximal size of an A-MSDU that can be transported in a HT BA session */
#define IEEE80211_MAX_MPDU_LEN_HT_BA        4095

/* Maximal size of an A-MSDU */
#define IEEE80211_MAX_MPDU_LEN_HT_3839      3839
#define IEEE80211_MAX_MPDU_LEN_HT_7935      7935

#define IEEE80211_MAX_MPDU_LEN_VHT_3895     3895
#define IEEE80211_MAX_MPDU_LEN_VHT_7991     7991
#define IEEE80211_MAX_MPDU_LEN_VHT_11454    11454

#define IEEE80211_MAX_SSID_LEN      32

#define IEEE80211_MAX_MESH_ID_LEN   32

#define IEEE80211_FIRST_TSPEC_TSID  8
#define IEEE80211_NUM_TIDS      16

/* number of user priorities 802.11 uses */
#define IEEE80211_NUM_UPS       8

#define IEEE80211_QOS_CTL_LEN       2
/* 1d tag mask */
#define IEEE80211_QOS_CTL_TAG1D_MASK        0x0007
/* TID mask */
#define IEEE80211_QOS_CTL_TID_MASK      0x000f
/* EOSP */
#define IEEE80211_QOS_CTL_EOSP          0x0010
/* ACK policy */
#define IEEE80211_QOS_CTL_ACK_POLICY_NORMAL 0x0000
#define IEEE80211_QOS_CTL_ACK_POLICY_NOACK  0x0020
#define IEEE80211_QOS_CTL_ACK_POLICY_NO_EXPL    0x0040
#define IEEE80211_QOS_CTL_ACK_POLICY_BLOCKACK   0x0060
#define IEEE80211_QOS_CTL_ACK_POLICY_MASK   0x0060
/* A-MSDU 802.11n */
#define IEEE80211_QOS_CTL_A_MSDU_PRESENT    0x0080
/* Mesh Control 802.11s */
#define IEEE80211_QOS_CTL_MESH_CONTROL_PRESENT  0x0100

/* Mesh Power Save Level */
#define IEEE80211_QOS_CTL_MESH_PS_LEVEL     0x0200
/* Mesh Receiver Service Period Initiated */
#define IEEE80211_QOS_CTL_RSPI          0x0400

/* U-APSD queue for WMM IEs sent by AP */
#define IEEE80211_WMM_IE_AP_QOSINFO_UAPSD   (1<<7)
#define IEEE80211_WMM_IE_AP_QOSINFO_PARAM_SET_CNT_MASK  0x0f

/* U-APSD queues for WMM IEs sent by STA */
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_VO  (1<<0)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_VI  (1<<1)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_BK  (1<<2)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_BE  (1<<3)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK    0x0f

/* U-APSD max SP length for WMM IEs sent by STA */
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL 0x00
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_2   0x01
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_4   0x02
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_6   0x03
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_MASK    0x03
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_SHIFT   5

#define IEEE80211_HT_CTL_LEN        4

struct ieee80211_hdr {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[ETHER_ADDR_LEN];
    uint8_t addr2[ETHER_ADDR_LEN];
    uint8_t addr3[ETHER_ADDR_LEN];
    uint16_t seq_ctrl;
    uint8_t addr4[ETHER_ADDR_LEN];
} __attribute__((__packed__)) __attribute__((aligned(2)));

struct ieee80211_hdr_3addr {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[ETHER_ADDR_LEN];
    uint8_t addr2[ETHER_ADDR_LEN];
    uint8_t addr3[ETHER_ADDR_LEN];
    uint16_t seq_ctrl;
} __attribute__((__packed__)) __attribute__((aligned(2)));

struct ieee80211_qos_hdr {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[ETHER_ADDR_LEN];
    uint8_t addr2[ETHER_ADDR_LEN];
    uint8_t addr3[ETHER_ADDR_LEN];
    uint16_t seq_ctrl;
    uint16_t qos_ctrl;
} __attribute__((__packed__)) __attribute__((aligned(2)));

/**
 * ieee80211_has_tods - check if IEEE80211_FCTL_TODS is set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_has_tods(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_TODS)) != 0;
}

/**
 * ieee80211_has_fromds - check if IEEE80211_FCTL_FROMDS is set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_has_fromds(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FROMDS)) != 0;
}

/**
 * ieee80211_has_a4 - check if IEEE80211_FCTL_TODS and IEEE80211_FCTL_FROMDS are set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_has_a4(uint16_t fc)
{
    uint16_t tmp = rte_cpu_to_le_16(IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS);
    return (fc & tmp) == tmp;
}

/**
 * ieee80211_has_morefrags - check if IEEE80211_FCTL_MOREFRAGS is set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_has_morefrags(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_MOREFRAGS)) != 0;
}

/**
 * ieee80211_has_retry - check if IEEE80211_FCTL_RETRY is set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_has_retry(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_RETRY)) != 0;
}

/**
 * ieee80211_has_pm - check if IEEE80211_FCTL_PM is set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_has_pm(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_PM)) != 0;
}

/**
 * ieee80211_has_moredata - check if IEEE80211_FCTL_MOREDATA is set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_has_moredata(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_MOREDATA)) != 0;
}

/**
 * ieee80211_has_protected - check if IEEE80211_FCTL_PROTECTED is set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_has_protected(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_PROTECTED)) != 0;
}

/**
 * ieee80211_has_order - check if IEEE80211_FCTL_ORDER is set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_has_order(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_ORDER)) != 0;
}

/**
 * ieee80211_is_mgmt - check if type is IEEE80211_FTYPE_MGMT
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_mgmt(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT);
}

/**
 * ieee80211_is_ctl - check if type is IEEE80211_FTYPE_CTL
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_ctl(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_CTL);
}

/**
 * ieee80211_is_data - check if type is IEEE80211_FTYPE_DATA
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_data(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_DATA);
}

/**
 * ieee80211_is_data_qos - check if type is IEEE80211_FTYPE_DATA and IEEE80211_STYPE_QOS_DATA is set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_data_qos(uint16_t fc)
{
    /*
     * mask with QOS_DATA rather than IEEE80211_FCTL_STYPE as we just need
     * to check the one bit
     */
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_STYPE_QOS_DATA)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA);
}

/**
 * ieee80211_is_data_present - check if type is IEEE80211_FTYPE_DATA and has data
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_data_present(uint16_t fc)
{
    /*
     * mask with 0x40 and test that that bit is clear to only return true
     * for the data-containing substypes.
     */
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | 0x40)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_DATA);
}

/**
 * ieee80211_is_assoc_req - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_ASSOC_REQ
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_assoc_req(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ASSOC_REQ);
}

/**
 * ieee80211_is_assoc_resp - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_ASSOC_RESP
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_assoc_resp(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ASSOC_RESP);
}

/**
 * ieee80211_is_reassoc_req - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_REASSOC_REQ
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_reassoc_req(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_REASSOC_REQ);
}

/**
 * ieee80211_is_reassoc_resp - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_REASSOC_RESP
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_reassoc_resp(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_REASSOC_RESP);
}

/**
 * ieee80211_is_probe_req - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_PROBE_REQ
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_probe_req(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ);
}

/**
 * ieee80211_is_probe_resp - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_PROBE_RESP
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_probe_resp(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_RESP);
}

/**
 * ieee80211_is_beacon - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_BEACON
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_beacon(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_BEACON);
}

/**
 * ieee80211_is_atim - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_ATIM
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_atim(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ATIM);
}

/**
 * ieee80211_is_disassoc - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_DISASSOC
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_disassoc(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_DISASSOC);
}

/**
 * ieee80211_is_auth - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_AUTH
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_auth(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_AUTH);
}

/**
 * ieee80211_is_deauth - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_DEAUTH
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_deauth(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_DEAUTH);
}

/**
 * ieee80211_is_action - check if IEEE80211_FTYPE_MGMT && IEEE80211_STYPE_ACTION
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_action(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION);
}

/**
 * ieee80211_is_back_req - check if IEEE80211_FTYPE_CTL && IEEE80211_STYPE_BACK_REQ
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_back_req(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_BACK_REQ);
}

/**
 * ieee80211_is_back - check if IEEE80211_FTYPE_CTL && IEEE80211_STYPE_BACK
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_back(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_BACK);
}

/**
 * ieee80211_is_pspoll - check if IEEE80211_FTYPE_CTL && IEEE80211_STYPE_PSPOLL
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_pspoll(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_PSPOLL);
}

/**
 * ieee80211_is_rts - check if IEEE80211_FTYPE_CTL && IEEE80211_STYPE_RTS
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_rts(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_RTS);
}

/**
 * ieee80211_is_cts - check if IEEE80211_FTYPE_CTL && IEEE80211_STYPE_CTS
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_cts(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_CTS);
}

/**
 * ieee80211_is_ack - check if IEEE80211_FTYPE_CTL && IEEE80211_STYPE_ACK
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_ack(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_ACK);
}

/**
 * ieee80211_is_cfend - check if IEEE80211_FTYPE_CTL && IEEE80211_STYPE_CFEND
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_cfend(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_CFEND);
}

/**
 * ieee80211_is_cfendack - check if IEEE80211_FTYPE_CTL && IEEE80211_STYPE_CFENDACK
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_cfendack(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_CFENDACK);
}

/**
 * ieee80211_is_nullfunc - check if frame is a regular (non-QoS) nullfunc frame
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_nullfunc(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_NULLFUNC);
}

/**
 * ieee80211_is_qos_nullfunc - check if frame is a QoS nullfunc frame
 * @fc: frame control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_qos_nullfunc(uint16_t fc)
{
    return (fc & rte_cpu_to_le_16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
           rte_cpu_to_le_16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_NULLFUNC);
}

/**
 * ieee80211_is_bufferable_mmpdu - check if frame is bufferable MMPDU
 * @fc: frame control field in little-endian byteorder
 */
static inline bool ieee80211_is_bufferable_mmpdu(uint16_t fc)
{
    /* IEEE 802.11-2012, definition of "bufferable management frame";
     * note that this ignores the IBSS special case. */
    return ieee80211_is_mgmt(fc) &&
           (ieee80211_is_action(fc) ||
        ieee80211_is_disassoc(fc) ||
        ieee80211_is_deauth(fc));
}

/**
 * ieee80211_is_first_frag - check if IEEE80211_SCTL_FRAG is not set
 * @seq_ctrl: frame sequence control bytes in little-endian byteorder
 */
static inline bool ieee80211_is_first_frag(uint16_t seq_ctrl)
{
    return (seq_ctrl & rte_cpu_to_le_16(IEEE80211_SCTL_FRAG)) == 0;
}

/**
 * ieee80211_is_frag - check if a frame is a fragment
 * @hdr: 802.11 header of the frame
 */
static inline bool ieee80211_is_frag(struct ieee80211_hdr *hdr)
{
    return ieee80211_has_morefrags(hdr->frame_control) ||
           hdr->seq_ctrl & rte_cpu_to_le_16(IEEE80211_SCTL_FRAG);
}

struct ieee80211s_hdr {
    uint8_t flags;
    uint8_t ttl;
    uint32_t seqnum;
    uint8_t eaddr1[ETHER_ADDR_LEN];
    uint8_t eaddr2[ETHER_ADDR_LEN];
} __attribute__((__packed__)) __attribute__((aligned(2)));

/* Mesh flags */
#define MESH_FLAGS_AE_A4    0x1
#define MESH_FLAGS_AE_A5_A6 0x2
#define MESH_FLAGS_AE       0x3
#define MESH_FLAGS_PS_DEEP  0x4

/**
 * enum ieee80211_preq_flags - mesh PREQ element flags
 *
 * @IEEE80211_PREQ_PROACTIVE_PREP_FLAG: proactive PREP subfield
 */
enum ieee80211_preq_flags {
    IEEE80211_PREQ_PROACTIVE_PREP_FLAG  = 1<<2,
};

/**
 * enum ieee80211_preq_target_flags - mesh PREQ element per target flags
 *
 * @IEEE80211_PREQ_TO_FLAG: target only subfield
 * @IEEE80211_PREQ_USN_FLAG: unknown target HWMP sequence number subfield
 */
enum ieee80211_preq_target_flags {
    IEEE80211_PREQ_TO_FLAG  = 1<<0,
    IEEE80211_PREQ_USN_FLAG = 1<<2,
};

/**
 * struct ieee80211_quiet_ie
 *
 * This structure refers to "Quiet information element"
 */
struct ieee80211_quiet_ie {
    uint8_t count;
    uint8_t period;
    uint16_t duration;
    uint16_t offset;
} __attribute__((__packed__));

/**
 * struct ieee80211_msrment_ie
 *
 * This structure refers to "Measurement Request/Report information element"
 */
struct ieee80211_msrment_ie {
    uint8_t token;
    uint8_t mode;
    uint8_t type;
    uint8_t request[0];
} __attribute__((__packed__));

/**
 * struct ieee80211_channel_sw_ie
 *
 * This structure refers to "Channel Switch Announcement information element"
 */
struct ieee80211_channel_sw_ie {
    uint8_t mode;
    uint8_t new_ch_num;
    uint8_t count;
} __attribute__((__packed__));

/**
 * struct ieee80211_ext_chansw_ie
 *
 * This structure represents the "Extended Channel Switch Announcement element"
 */
struct ieee80211_ext_chansw_ie {
    uint8_t mode;
    uint8_t new_operating_class;
    uint8_t new_ch_num;
    uint8_t count;
} __attribute__((__packed__));

/**
 * struct ieee80211_sec_chan_offs_ie - secondary channel offset IE
 * @sec_chan_offs: secondary channel offset, uses IEEE80211_HT_PARAM_CHA_SEC_*
 *  values here
 * This structure represents the "Secondary Channel Offset element"
 */
struct ieee80211_sec_chan_offs_ie {
    uint8_t sec_chan_offs;
} __attribute__((__packed__));

/**
 * struct ieee80211_mesh_chansw_params_ie - mesh channel switch parameters IE
 *
 * This structure represents the "Mesh Channel Switch Paramters element"
 */
struct ieee80211_mesh_chansw_params_ie {
    uint8_t mesh_ttl;
    uint8_t mesh_flags;
    uint16_t mesh_reason;
    uint16_t mesh_pre_value;
} __attribute__((__packed__));

/**
 * struct ieee80211_wide_bw_chansw_ie - wide bandwidth channel switch IE
 */
struct ieee80211_wide_bw_chansw_ie {
    uint8_t new_channel_width;
    uint8_t new_center_freq_seg0, new_center_freq_seg1;
} __attribute__((__packed__));

/**
 * struct ieee80211_tim
 *
 * This structure refers to "Traffic Indication Map information element"
 */
struct ieee80211_tim_ie {
    uint8_t dtim_count;
    uint8_t dtim_period;
    uint8_t bitmap_ctrl;
    /* variable size: 1 - 251 bytes */
    uint8_t virtual_map[1];
} __attribute__((__packed__));

/**
 * struct ieee80211_meshconf_ie
 *
 * This structure refers to "Mesh Configuration information element"
 */
struct ieee80211_meshconf_ie {
    uint8_t meshconf_psel;
    uint8_t meshconf_pmetric;
    uint8_t meshconf_congest;
    uint8_t meshconf_synch;
    uint8_t meshconf_auth;
    uint8_t meshconf_form;
    uint8_t meshconf_cap;
} __attribute__((__packed__));

/**
 * enum mesh_config_capab_flags - Mesh Configuration IE capability field flags
 *
 * @IEEE80211_MESHCONF_CAPAB_ACCEPT_PLINKS: STA is willing to establish
 *  additional mesh peerings with other mesh STAs
 * @IEEE80211_MESHCONF_CAPAB_FORWARDING: the STA forwards MSDUs
 * @IEEE80211_MESHCONF_CAPAB_TBTT_ADJUSTING: TBTT adjustment procedure
 *  is ongoing
 * @IEEE80211_MESHCONF_CAPAB_POWER_SAVE_LEVEL: STA is in deep sleep mode or has
 *  neighbors in deep sleep mode
 */
enum mesh_config_capab_flags {
    IEEE80211_MESHCONF_CAPAB_ACCEPT_PLINKS      = 0x01,
    IEEE80211_MESHCONF_CAPAB_FORWARDING     = 0x08,
    IEEE80211_MESHCONF_CAPAB_TBTT_ADJUSTING     = 0x20,
    IEEE80211_MESHCONF_CAPAB_POWER_SAVE_LEVEL   = 0x40,
};

/**
 * mesh channel switch parameters element's flag indicator
 *
 */
#define WLAN_EID_CHAN_SWITCH_PARAM_TX_RESTRICT BIT(0)
#define WLAN_EID_CHAN_SWITCH_PARAM_INITIATOR BIT(1)
#define WLAN_EID_CHAN_SWITCH_PARAM_REASON BIT(2)

/**
 * struct ieee80211_rann_ie
 *
 * This structure refers to "Root Announcement information element"
 */
struct ieee80211_rann_ie {
    uint8_t rann_flags;
    uint8_t rann_hopcount;
    uint8_t rann_ttl;
    uint8_t rann_addr[ETHER_ADDR_LEN];
    uint32_t rann_seq;
    uint32_t rann_interval;
    uint32_t rann_metric;
} __attribute__((__packed__));

enum ieee80211_rann_flags {
    RANN_FLAG_IS_GATE = 1 << 0,
};

enum ieee80211_ht_chanwidth_values {
    IEEE80211_HT_CHANWIDTH_20MHZ = 0,
    IEEE80211_HT_CHANWIDTH_ANY = 1,
};

/**
 * enum ieee80211_opmode_bits - VHT operating mode field bits
 * @IEEE80211_OPMODE_NOTIF_CHANWIDTH_MASK: channel width mask
 * @IEEE80211_OPMODE_NOTIF_CHANWIDTH_20MHZ: 20 MHz channel width
 * @IEEE80211_OPMODE_NOTIF_CHANWIDTH_40MHZ: 40 MHz channel width
 * @IEEE80211_OPMODE_NOTIF_CHANWIDTH_80MHZ: 80 MHz channel width
 * @IEEE80211_OPMODE_NOTIF_CHANWIDTH_160MHZ: 160 MHz or 80+80 MHz channel width
 * @IEEE80211_OPMODE_NOTIF_RX_NSS_MASK: number of spatial streams mask
 *  (the NSS value is the value of this field + 1)
 * @IEEE80211_OPMODE_NOTIF_RX_NSS_SHIFT: number of spatial streams shift
 * @IEEE80211_OPMODE_NOTIF_RX_NSS_TYPE_BF: indicates streams in SU-MIMO PPDU
 *  using a beamforming steering matrix
 */
enum ieee80211_vht_opmode_bits {
    IEEE80211_OPMODE_NOTIF_CHANWIDTH_MASK   = 3,
    IEEE80211_OPMODE_NOTIF_CHANWIDTH_20MHZ  = 0,
    IEEE80211_OPMODE_NOTIF_CHANWIDTH_40MHZ  = 1,
    IEEE80211_OPMODE_NOTIF_CHANWIDTH_80MHZ  = 2,
    IEEE80211_OPMODE_NOTIF_CHANWIDTH_160MHZ = 3,
    IEEE80211_OPMODE_NOTIF_RX_NSS_MASK  = 0x70,
    IEEE80211_OPMODE_NOTIF_RX_NSS_SHIFT = 4,
    IEEE80211_OPMODE_NOTIF_RX_NSS_TYPE_BF   = 0x80,
};

#define WLAN_SA_QUERY_TR_ID_LEN 2
#define WLAN_MEMBERSHIP_LEN 8
#define WLAN_USER_POSITION_LEN 16

/**
 * struct ieee80211_tpc_report_ie
 *
 * This structure refers to "TPC Report element"
 */
struct ieee80211_tpc_report_ie {
    uint8_t tx_power;
    uint8_t link_margin;
} __attribute__((__packed__));

struct ieee80211_mgmt {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t da[ETHER_ADDR_LEN];
    uint8_t sa[ETHER_ADDR_LEN];
    uint8_t bssid[ETHER_ADDR_LEN];
    uint16_t seq_ctrl;
    union {
        struct {
            uint16_t auth_alg;
            uint16_t auth_transaction;
            uint16_t status_code;
            /* possibly followed by Challenge text */
            uint8_t variable[0];
        } __attribute__((__packed__)) auth;
        struct {
            uint16_t reason_code;
        } __attribute__((__packed__)) deauth;
        struct {
            uint16_t capab_info;
            uint16_t listen_interval;
            /* followed by SSID and Supported rates */
            uint8_t variable[0];
        } __attribute__((__packed__)) assoc_req;
        struct {
            uint16_t capab_info;
            uint16_t status_code;
            uint16_t aid;
            /* followed by Supported rates */
            uint8_t variable[0];
        } __attribute__((__packed__)) assoc_resp, reassoc_resp;
        struct {
            uint16_t capab_info;
            uint16_t listen_interval;
            uint8_t current_ap[ETHER_ADDR_LEN];
            /* followed by SSID and Supported rates */
            uint8_t variable[0];
        } __attribute__((__packed__)) reassoc_req;
        struct {
            uint16_t reason_code;
        } __attribute__((__packed__)) disassoc;
        struct {
            uint64_t timestamp;
            uint16_t beacon_int;
            uint16_t capab_info;
            /* followed by some of SSID, Supported rates,
             * FH Params, DS Params, CF Params, IBSS Params, TIM */
            uint8_t variable[0];
        } __attribute__((__packed__)) beacon;
        struct {
            /* only variable items: SSID, Supported rates */
            uint8_t variable[0];
        } __attribute__((__packed__)) probe_req;
        struct {
            uint64_t timestamp;
            uint16_t beacon_int;
            uint16_t capab_info;
            /* followed by some of SSID, Supported rates,
             * FH Params, DS Params, CF Params, IBSS Params */
            uint8_t variable[0];
        } __attribute__((__packed__)) probe_resp;
        struct {
            uint8_t category;
            union {
                struct {
                    uint8_t action_code;
                    uint8_t dialog_token;
                    uint8_t status_code;
                    uint8_t variable[0];
                } __attribute__((__packed__)) wme_action;
                struct{
                    uint8_t action_code;
                    uint8_t variable[0];
                } __attribute__((__packed__)) chan_switch;
                struct{
                    uint8_t action_code;
                    struct ieee80211_ext_chansw_ie data;
                    uint8_t variable[0];
                } __attribute__((__packed__)) ext_chan_switch;
                struct{
                    uint8_t action_code;
                    uint8_t dialog_token;
                    uint8_t element_id;
                    uint8_t length;
                    struct ieee80211_msrment_ie msr_elem;
                } __attribute__((__packed__)) measurement;
                struct{
                    uint8_t action_code;
                    uint8_t dialog_token;
                    uint16_t capab;
                    uint16_t timeout;
                    uint16_t start_seq_num;
                } __attribute__((__packed__)) addba_req;
                struct{
                    uint8_t action_code;
                    uint8_t dialog_token;
                    uint16_t status;
                    uint16_t capab;
                    uint16_t timeout;
                } __attribute__((__packed__)) addba_resp;
                struct{
                    uint8_t action_code;
                    uint16_t params;
                    uint16_t reason_code;
                } __attribute__((__packed__)) delba;
                struct {
                    uint8_t action_code;
                    uint8_t variable[0];
                } __attribute__((__packed__)) self_prot;
                struct{
                    uint8_t action_code;
                    uint8_t variable[0];
                } __attribute__((__packed__)) mesh_action;
                struct {
                    uint8_t action;
                    uint8_t trans_id[WLAN_SA_QUERY_TR_ID_LEN];
                } __attribute__((__packed__)) sa_query;
                struct {
                    uint8_t action;
                    uint8_t smps_control;
                } __attribute__((__packed__)) ht_smps;
                struct {
                    uint8_t action_code;
                    uint8_t chanwidth;
                } __attribute__((__packed__)) ht_notify_cw;
                struct {
                    uint8_t action_code;
                    uint8_t dialog_token;
                    uint16_t capability;
                    uint8_t variable[0];
                } __attribute__((__packed__)) tdls_discover_resp;
                struct {
                    uint8_t action_code;
                    uint8_t operating_mode;
                } __attribute__((__packed__)) vht_opmode_notif;
                struct {
                    uint8_t action_code;
                    uint8_t membership[WLAN_MEMBERSHIP_LEN];
                    uint8_t position[WLAN_USER_POSITION_LEN];
                } __attribute__((__packed__)) vht_group_notif;
                struct {
                    uint8_t action_code;
                    uint8_t dialog_token;
                    uint8_t tpc_elem_id;
                    uint8_t tpc_elem_length;
                    struct ieee80211_tpc_report_ie tpc;
                } __attribute__((__packed__)) tpc_report;
                struct {
                    uint8_t action_code;
                    uint8_t dialog_token;
                    uint8_t follow_up;
                    uint8_t tod[6];
                    uint8_t toa[6];
                    uint16_t tod_error;
                    uint16_t toa_error;
                    uint8_t variable[0];
                } __attribute__((__packed__)) ftm;
            } u;
        } __attribute__((__packed__)) action;
    } u;
} __attribute__((__packed__)) __attribute__((aligned(2)));

/* Supported Rates value encodings in 802.11n-2009 7.3.2.2 */
#define BSS_MEMBERSHIP_SELECTOR_HT_PHY  127
#define BSS_MEMBERSHIP_SELECTOR_VHT_PHY 126

/* mgmt header + 1 byte category code */
#define IEEE80211_MIN_ACTION_SIZE offsetof(struct ieee80211_mgmt, u.action.u)


/* Management MIC information element (IEEE 802.11w) */
struct ieee80211_mmie {
    uint8_t element_id;
    uint8_t length;
    uint16_t key_id;
    uint8_t sequence_number[6];
    uint8_t mic[8];
} __attribute__((__packed__));

/* Management MIC information element (IEEE 802.11w) for GMAC and CMAC-256 */
struct ieee80211_mmie_16 {
    uint8_t element_id;
    uint8_t length;
    uint16_t key_id;
    uint8_t sequence_number[6];
    uint8_t mic[16];
} __attribute__((__packed__));

struct ieee80211_vendor_ie {
    uint8_t element_id;
    uint8_t len;
    uint8_t oui[3];
    uint8_t oui_type;
} __attribute__((__packed__));

struct ieee80211_wmm_ac_param {
    uint8_t aci_aifsn; /* AIFSN, ACM, ACI */
    uint8_t cw; /* ECWmin, ECWmax (CW = 2^ECW - 1) */
    uint16_t txop_limit;
} __attribute__((__packed__));

struct ieee80211_wmm_param_ie {
    uint8_t element_id; /* Element ID: 221 (0xdd); */
    uint8_t len; /* Length: 24 */
    /* required fields for WMM version 1 */
    uint8_t oui[3]; /* 00:50:f2 */
    uint8_t oui_type; /* 2 */
    uint8_t oui_subtype; /* 1 */
    uint8_t version; /* 1 for WMM version 1.0 */
    uint8_t qos_info; /* AP/STA specific QoS info */
    uint8_t reserved; /* 0 */
    /* AC_BE, AC_BK, AC_VI, AC_VO */
    struct ieee80211_wmm_ac_param ac[4];
} __attribute__((__packed__));

/* Control frames */
struct ieee80211_rts {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t ra[ETHER_ADDR_LEN];
    uint8_t ta[ETHER_ADDR_LEN];
} __attribute__((__packed__)) __attribute__((aligned(2)));

struct ieee80211_cts {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t ra[ETHER_ADDR_LEN];
} __attribute__((__packed__)) __attribute__((aligned(2)));

struct ieee80211_pspoll {
    uint16_t frame_control;
    uint16_t aid;
    uint8_t bssid[ETHER_ADDR_LEN];
    uint8_t ta[ETHER_ADDR_LEN];
} __attribute__((__packed__)) __attribute__((aligned(2)));

/* TDLS */

/* Channel switch timing */
struct ieee80211_ch_switch_timing {
    uint16_t switch_time;
    uint16_t switch_timeout;
} __attribute__((__packed__));

/* Link-id information element */
struct ieee80211_tdls_lnkie {
    uint8_t ie_type; /* Link Identifier IE */
    uint8_t ie_len;
    uint8_t bssid[ETHER_ADDR_LEN];
    uint8_t init_sta[ETHER_ADDR_LEN];
    uint8_t resp_sta[ETHER_ADDR_LEN];
} __attribute__((__packed__));

struct ieee80211_tdls_data {
    uint8_t da[ETHER_ADDR_LEN];
    uint8_t sa[ETHER_ADDR_LEN];
    uint16_t ether_type;
    uint8_t payload_type;
    uint8_t category;
    uint8_t action_code;
    union {
        struct {
            uint8_t dialog_token;
            uint16_t capability;
            uint8_t variable[0];
        } __attribute__((__packed__)) setup_req;
        struct {
            uint16_t status_code;
            uint8_t dialog_token;
            uint16_t capability;
            uint8_t variable[0];
        } __attribute__((__packed__)) setup_resp;
        struct {
            uint16_t status_code;
            uint8_t dialog_token;
            uint8_t variable[0];
        } __attribute__((__packed__)) setup_cfm;
        struct {
            uint16_t reason_code;
            uint8_t variable[0];
        } __attribute__((__packed__)) teardown;
        struct {
            uint8_t dialog_token;
            uint8_t variable[0];
        } __attribute__((__packed__)) discover_req;
        struct {
            uint8_t target_channel;
            uint8_t oper_class;
            uint8_t variable[0];
        } __attribute__((__packed__)) chan_switch_req;
        struct {
            uint16_t status_code;
            uint8_t variable[0];
        } __attribute__((__packed__)) chan_switch_resp;
    } u;
} __attribute__((__packed__));

/*
 * Peer-to-Peer IE attribute related definitions.
 */
/**
 * enum ieee80211_p2p_attr_id - identifies type of peer-to-peer attribute.
 */
enum ieee80211_p2p_attr_id {
    IEEE80211_P2P_ATTR_STATUS = 0,
    IEEE80211_P2P_ATTR_MINOR_REASON,
    IEEE80211_P2P_ATTR_CAPABILITY,
    IEEE80211_P2P_ATTR_DEVICE_ID,
    IEEE80211_P2P_ATTR_GO_INTENT,
    IEEE80211_P2P_ATTR_GO_CONFIG_TIMEOUT,
    IEEE80211_P2P_ATTR_LISTEN_CHANNEL,
    IEEE80211_P2P_ATTR_GROUP_BSSID,
    IEEE80211_P2P_ATTR_EXT_LISTEN_TIMING,
    IEEE80211_P2P_ATTR_INTENDED_IFACE_ADDR,
    IEEE80211_P2P_ATTR_MANAGABILITY,
    IEEE80211_P2P_ATTR_CHANNEL_LIST,
    IEEE80211_P2P_ATTR_ABSENCE_NOTICE,
    IEEE80211_P2P_ATTR_DEVICE_INFO,
    IEEE80211_P2P_ATTR_GROUP_INFO,
    IEEE80211_P2P_ATTR_GROUP_ID,
    IEEE80211_P2P_ATTR_INTERFACE,
    IEEE80211_P2P_ATTR_OPER_CHANNEL,
    IEEE80211_P2P_ATTR_INVITE_FLAGS,
    /* 19 - 220: Reserved */
    IEEE80211_P2P_ATTR_VENDOR_SPECIFIC = 221,

    IEEE80211_P2P_ATTR_MAX
};

/* Notice of Absence attribute - described in P2P spec 4.1.14 */
/* Typical max value used here */
#define IEEE80211_P2P_NOA_DESC_MAX  4

struct ieee80211_p2p_noa_desc {
    uint8_t count;
    uint32_t duration;
    uint32_t interval;
    uint32_t start_time;
} __attribute__((__packed__));

struct ieee80211_p2p_noa_attr {
    uint8_t index;
    uint8_t oppps_ctwindow;
    struct ieee80211_p2p_noa_desc desc[IEEE80211_P2P_NOA_DESC_MAX];
} __attribute__((__packed__));

#define IEEE80211_P2P_OPPPS_ENABLE_BIT      BIT(7)
#define IEEE80211_P2P_OPPPS_CTWINDOW_MASK   0x7F

/**
 * struct ieee80211_bar - HT Block Ack Request
 *
 * This structure refers to "HT BlockAckReq" as
 * described in 802.11n draft section 7.2.1.7.1
 */
struct ieee80211_bar {
    uint16_t frame_control;
    uint16_t duration;
    __uint8_t ra[ETHER_ADDR_LEN];
    __uint8_t ta[ETHER_ADDR_LEN];
    uint16_t control;
    uint16_t start_seq_num;
} __attribute__((__packed__));

/* 802.11 BAR control masks */
#define IEEE80211_BAR_CTRL_ACK_POLICY_NORMAL    0x0000
#define IEEE80211_BAR_CTRL_MULTI_TID        0x0002
#define IEEE80211_BAR_CTRL_CBMTID_COMPRESSED_BA 0x0004
#define IEEE80211_BAR_CTRL_TID_INFO_MASK    0xf000
#define IEEE80211_BAR_CTRL_TID_INFO_SHIFT   12

#define IEEE80211_HT_MCS_MASK_LEN       10

/**
 * struct ieee80211_mcs_info - MCS information
 * @rx_mask: RX mask
 * @rx_highest: highest supported RX rate. If set represents
 *  the highest supported RX data rate in units of 1 Mbps.
 *  If this field is 0 this value should not be used to
 *  consider the highest RX data rate supported.
 * @tx_params: TX parameters
 */
struct ieee80211_mcs_info {
    uint8_t rx_mask[IEEE80211_HT_MCS_MASK_LEN];
    uint16_t rx_highest;
    uint8_t tx_params;
    uint8_t reserved[3];
} __attribute__((__packed__));

/* 802.11n HT capability MSC set */
#define IEEE80211_HT_MCS_RX_HIGHEST_MASK    0x3ff
#define IEEE80211_HT_MCS_TX_DEFINED     0x01
#define IEEE80211_HT_MCS_TX_RX_DIFF     0x02
/* value 0 == 1 stream etc */
#define IEEE80211_HT_MCS_TX_MAX_STREAMS_MASK    0x0C
#define IEEE80211_HT_MCS_TX_MAX_STREAMS_SHIFT   2
#define     IEEE80211_HT_MCS_TX_MAX_STREAMS 4
#define IEEE80211_HT_MCS_TX_UNEQUAL_MODULATION  0x10

/*
 * 802.11n D5.0 20.3.5 / 20.6 says:
 * - indices 0 to 7 and 32 are single spatial stream
 * - 8 to 31 are multiple spatial streams using equal modulation
 *   [8..15 for two streams, 16..23 for three and 24..31 for four]
 * - remainder are multiple spatial streams using unequal modulation
 */
#define IEEE80211_HT_MCS_UNEQUAL_MODULATION_START 33
#define IEEE80211_HT_MCS_UNEQUAL_MODULATION_START_BYTE \
    (IEEE80211_HT_MCS_UNEQUAL_MODULATION_START / 8)

/**
 * struct ieee80211_ht_cap - HT capabilities
 *
 * This structure is the "HT capabilities element" as
 * described in 802.11n D5.0 7.3.2.57
 */
struct ieee80211_ht_cap {
    uint16_t cap_info;
    uint8_t ampdu_params_info;

    /* 16 bytes MCS information */
    struct ieee80211_mcs_info mcs;

    uint16_t extended_ht_cap_info;
    uint32_t tx_BF_cap_info;
    uint8_t antenna_selection_info;
} __attribute__((__packed__));

/* 802.11n HT capabilities masks (for cap_info) */
#define IEEE80211_HT_CAP_LDPC_CODING        0x0001
#define IEEE80211_HT_CAP_SUP_WIDTH_20_40    0x0002
#define IEEE80211_HT_CAP_SM_PS          0x000C
#define     IEEE80211_HT_CAP_SM_PS_SHIFT    2
#define IEEE80211_HT_CAP_GRN_FLD        0x0010
#define IEEE80211_HT_CAP_SGI_20         0x0020
#define IEEE80211_HT_CAP_SGI_40         0x0040
#define IEEE80211_HT_CAP_TX_STBC        0x0080
#define IEEE80211_HT_CAP_RX_STBC        0x0300
#define     IEEE80211_HT_CAP_RX_STBC_SHIFT  8
#define IEEE80211_HT_CAP_DELAY_BA       0x0400
#define IEEE80211_HT_CAP_MAX_AMSDU      0x0800
#define IEEE80211_HT_CAP_DSSSCCK40      0x1000
#define IEEE80211_HT_CAP_RESERVED       0x2000
#define IEEE80211_HT_CAP_40MHZ_INTOLERANT   0x4000
#define IEEE80211_HT_CAP_LSIG_TXOP_PROT     0x8000

/* 802.11n HT extended capabilities masks (for extended_ht_cap_info) */
#define IEEE80211_HT_EXT_CAP_PCO        0x0001
#define IEEE80211_HT_EXT_CAP_PCO_TIME       0x0006
#define     IEEE80211_HT_EXT_CAP_PCO_TIME_SHIFT 1
#define IEEE80211_HT_EXT_CAP_MCS_FB     0x0300
#define     IEEE80211_HT_EXT_CAP_MCS_FB_SHIFT   8
#define IEEE80211_HT_EXT_CAP_HTC_SUP        0x0400
#define IEEE80211_HT_EXT_CAP_RD_RESPONDER   0x0800

/* 802.11n HT capability AMPDU settings (for ampdu_params_info) */
#define IEEE80211_HT_AMPDU_PARM_FACTOR      0x03
#define IEEE80211_HT_AMPDU_PARM_DENSITY     0x1C
#define     IEEE80211_HT_AMPDU_PARM_DENSITY_SHIFT   2

/*
 * Maximum length of AMPDU that the STA can receive in high-throughput (HT).
 * Length = 2 ^ (13 + max_ampdu_length_exp) - 1 (octets)
 */
enum ieee80211_max_ampdu_length_exp {
    IEEE80211_HT_MAX_AMPDU_8K = 0,
    IEEE80211_HT_MAX_AMPDU_16K = 1,
    IEEE80211_HT_MAX_AMPDU_32K = 2,
    IEEE80211_HT_MAX_AMPDU_64K = 3
};

/*
 * Maximum length of AMPDU that the STA can receive in VHT.
 * Length = 2 ^ (13 + max_ampdu_length_exp) - 1 (octets)
 */
enum ieee80211_vht_max_ampdu_length_exp {
    IEEE80211_VHT_MAX_AMPDU_8K = 0,
    IEEE80211_VHT_MAX_AMPDU_16K = 1,
    IEEE80211_VHT_MAX_AMPDU_32K = 2,
    IEEE80211_VHT_MAX_AMPDU_64K = 3,
    IEEE80211_VHT_MAX_AMPDU_128K = 4,
    IEEE80211_VHT_MAX_AMPDU_256K = 5,
    IEEE80211_VHT_MAX_AMPDU_512K = 6,
    IEEE80211_VHT_MAX_AMPDU_1024K = 7
};

#define IEEE80211_HT_MAX_AMPDU_FACTOR 13

/* Minimum MPDU start spacing */
enum ieee80211_min_mpdu_spacing {
    IEEE80211_HT_MPDU_DENSITY_NONE = 0, /* No restriction */
    IEEE80211_HT_MPDU_DENSITY_0_25 = 1, /* 1/4 usec */
    IEEE80211_HT_MPDU_DENSITY_0_5 = 2,  /* 1/2 usec */
    IEEE80211_HT_MPDU_DENSITY_1 = 3,    /* 1 usec */
    IEEE80211_HT_MPDU_DENSITY_2 = 4,    /* 2 usec */
    IEEE80211_HT_MPDU_DENSITY_4 = 5,    /* 4 usec */
    IEEE80211_HT_MPDU_DENSITY_8 = 6,    /* 8 usec */
    IEEE80211_HT_MPDU_DENSITY_16 = 7    /* 16 usec */
};

/**
 * struct ieee80211_ht_operation - HT operation IE
 *
 * This structure is the "HT operation element" as
 * described in 802.11n-2009 7.3.2.57
 */
struct ieee80211_ht_operation {
    uint8_t primary_chan;
    uint8_t ht_param;
    uint16_t operation_mode;
    uint16_t stbc_param;
    uint8_t basic_set[16];
} __attribute__((__packed__));

/* for ht_param */
#define IEEE80211_HT_PARAM_CHA_SEC_OFFSET       0x03
#define     IEEE80211_HT_PARAM_CHA_SEC_NONE     0x00
#define     IEEE80211_HT_PARAM_CHA_SEC_ABOVE    0x01
#define     IEEE80211_HT_PARAM_CHA_SEC_BELOW    0x03
#define IEEE80211_HT_PARAM_CHAN_WIDTH_ANY       0x04
#define IEEE80211_HT_PARAM_RIFS_MODE            0x08

/* for operation_mode */
#define IEEE80211_HT_OP_MODE_PROTECTION         0x0003
#define     IEEE80211_HT_OP_MODE_PROTECTION_NONE        0
#define     IEEE80211_HT_OP_MODE_PROTECTION_NONMEMBER   1
#define     IEEE80211_HT_OP_MODE_PROTECTION_20MHZ       2
#define     IEEE80211_HT_OP_MODE_PROTECTION_NONHT_MIXED 3
#define IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT       0x0004
#define IEEE80211_HT_OP_MODE_NON_HT_STA_PRSNT       0x0010

/* for stbc_param */
#define IEEE80211_HT_STBC_PARAM_DUAL_BEACON     0x0040
#define IEEE80211_HT_STBC_PARAM_DUAL_CTS_PROT       0x0080
#define IEEE80211_HT_STBC_PARAM_STBC_BEACON     0x0100
#define IEEE80211_HT_STBC_PARAM_LSIG_TXOP_FULLPROT  0x0200
#define IEEE80211_HT_STBC_PARAM_PCO_ACTIVE      0x0400
#define IEEE80211_HT_STBC_PARAM_PCO_PHASE       0x0800


/* block-ack parameters */
#define IEEE80211_ADDBA_PARAM_AMSDU_MASK 0x0001
#define IEEE80211_ADDBA_PARAM_POLICY_MASK 0x0002
#define IEEE80211_ADDBA_PARAM_TID_MASK 0x003C
#define IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK 0xFFC0
#define IEEE80211_DELBA_PARAM_TID_MASK 0xF000
#define IEEE80211_DELBA_PARAM_INITIATOR_MASK 0x0800

/*
 * A-PMDU buffer sizes
 * According to IEEE802.11n spec size varies from 8K to 64K (in powers of 2)
 */
#define IEEE80211_MIN_AMPDU_BUF 0x8
#define IEEE80211_MAX_AMPDU_BUF 0x40


/* Spatial Multiplexing Power Save Modes (for capability) */
#define WLAN_HT_CAP_SM_PS_STATIC    0
#define WLAN_HT_CAP_SM_PS_DYNAMIC   1
#define WLAN_HT_CAP_SM_PS_INVALID   2
#define WLAN_HT_CAP_SM_PS_DISABLED  3

/* for SM power control field lower two bits */
#define WLAN_HT_SMPS_CONTROL_DISABLED   0
#define WLAN_HT_SMPS_CONTROL_STATIC 1
#define WLAN_HT_SMPS_CONTROL_DYNAMIC    3

/**
 * struct ieee80211_vht_mcs_info - VHT MCS information
 * @rx_mcs_map: RX MCS map 2 bits for each stream, total 8 streams
 * @rx_highest: Indicates highest long GI VHT PPDU data rate
 *  STA can receive. Rate expressed in units of 1 Mbps.
 *  If this field is 0 this value should not be used to
 *  consider the highest RX data rate supported.
 *  The top 3 bits of this field are reserved.
 * @tx_mcs_map: TX MCS map 2 bits for each stream, total 8 streams
 * @tx_highest: Indicates highest long GI VHT PPDU data rate
 *  STA can transmit. Rate expressed in units of 1 Mbps.
 *  If this field is 0 this value should not be used to
 *  consider the highest TX data rate supported.
 *  The top 3 bits of this field are reserved.
 */
struct ieee80211_vht_mcs_info {
    uint16_t rx_mcs_map;
    uint16_t rx_highest;
    uint16_t tx_mcs_map;
    uint16_t tx_highest;
} __attribute__((__packed__));

/**
 * enum ieee80211_vht_mcs_support - VHT MCS support definitions
 * @IEEE80211_VHT_MCS_SUPPORT_0_7: MCSes 0-7 are supported for the
 *  number of streams
 * @IEEE80211_VHT_MCS_SUPPORT_0_8: MCSes 0-8 are supported
 * @IEEE80211_VHT_MCS_SUPPORT_0_9: MCSes 0-9 are supported
 * @IEEE80211_VHT_MCS_NOT_SUPPORTED: This number of streams isn't supported
 *
 * These definitions are used in each 2-bit subfield of the @rx_mcs_map
 * and @tx_mcs_map fields of &struct ieee80211_vht_mcs_info, which are
 * both split into 8 subfields by number of streams. These values indicate
 * which MCSes are supported for the number of streams the value appears
 * for.
 */
enum ieee80211_vht_mcs_support {
    IEEE80211_VHT_MCS_SUPPORT_0_7   = 0,
    IEEE80211_VHT_MCS_SUPPORT_0_8   = 1,
    IEEE80211_VHT_MCS_SUPPORT_0_9   = 2,
    IEEE80211_VHT_MCS_NOT_SUPPORTED = 3,
};

/**
 * struct ieee80211_vht_cap - VHT capabilities
 *
 * This structure is the "VHT capabilities element" as
 * described in 802.11ac D3.0 8.4.2.160
 * @vht_cap_info: VHT capability info
 * @supp_mcs: VHT MCS supported rates
 */
struct ieee80211_vht_cap {
    uint32_t vht_cap_info;
    struct ieee80211_vht_mcs_info supp_mcs;
} __attribute__((__packed__));

/**
 * enum ieee80211_vht_chanwidth - VHT channel width
 * @IEEE80211_VHT_CHANWIDTH_USE_HT: use the HT operation IE to
 *  determine the channel width (20 or 40 MHz)
 * @IEEE80211_VHT_CHANWIDTH_80MHZ: 80 MHz bandwidth
 * @IEEE80211_VHT_CHANWIDTH_160MHZ: 160 MHz bandwidth
 * @IEEE80211_VHT_CHANWIDTH_80P80MHZ: 80+80 MHz bandwidth
 */
enum ieee80211_vht_chanwidth {
    IEEE80211_VHT_CHANWIDTH_USE_HT      = 0,
    IEEE80211_VHT_CHANWIDTH_80MHZ       = 1,
    IEEE80211_VHT_CHANWIDTH_160MHZ      = 2,
    IEEE80211_VHT_CHANWIDTH_80P80MHZ    = 3,
};

/**
 * struct ieee80211_vht_operation - VHT operation IE
 *
 * This structure is the "VHT operation element" as
 * described in 802.11ac D3.0 8.4.2.161
 * @chan_width: Operating channel width
 * @center_freq_seg1_idx: center freq segment 1 index
 * @center_freq_seg2_idx: center freq segment 2 index
 * @basic_mcs_set: VHT Basic MCS rate set
 */
struct ieee80211_vht_operation {
    uint8_t chan_width;
    uint8_t center_freq_seg0_idx;
    uint8_t center_freq_seg1_idx;
    uint16_t basic_mcs_set;
} __attribute__((__packed__));


/* 802.11ac VHT Capabilities */
#define IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_3895          0x00000000
#define IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_7991          0x00000001
#define IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454         0x00000002
#define IEEE80211_VHT_CAP_MAX_MPDU_MASK             0x00000003
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ        0x00000004
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ   0x00000008
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK          0x0000000C
#define IEEE80211_VHT_CAP_RXLDPC                0x00000010
#define IEEE80211_VHT_CAP_SHORT_GI_80               0x00000020
#define IEEE80211_VHT_CAP_SHORT_GI_160              0x00000040
#define IEEE80211_VHT_CAP_TXSTBC                0x00000080
#define IEEE80211_VHT_CAP_RXSTBC_1              0x00000100
#define IEEE80211_VHT_CAP_RXSTBC_2              0x00000200
#define IEEE80211_VHT_CAP_RXSTBC_3              0x00000300
#define IEEE80211_VHT_CAP_RXSTBC_4              0x00000400
#define IEEE80211_VHT_CAP_RXSTBC_MASK               0x00000700
#define IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE         0x00000800
#define IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE         0x00001000
#define IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT                  13
#define IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK           \
        (7 << IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT)
#define IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT     16
#define IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK      \
        (7 << IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT)
#define IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE         0x00080000
#define IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE         0x00100000
#define IEEE80211_VHT_CAP_VHT_TXOP_PS               0x00200000
#define IEEE80211_VHT_CAP_HTC_VHT               0x00400000
#define IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT  23
#define IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK   \
        (7 << IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT)
#define IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_UNSOL_MFB 0x08000000
#define IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB   0x0c000000
#define IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN            0x10000000
#define IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN            0x20000000

/* Authentication algorithms */
#define WLAN_AUTH_OPEN 0
#define WLAN_AUTH_SHARED_KEY 1
#define WLAN_AUTH_FT 2
#define WLAN_AUTH_SAE 3
#define WLAN_AUTH_LEAP 128

#define WLAN_AUTH_CHALLENGE_LEN 128

#define WLAN_CAPABILITY_ESS     (1<<0)
#define WLAN_CAPABILITY_IBSS        (1<<1)

/*
 * A mesh STA sets the ESS and IBSS capability bits to zero.
 * however, this holds true for p2p probe responses (in the p2p_find
 * phase) as well.
 */
#define WLAN_CAPABILITY_IS_STA_BSS(cap) \
    (!((cap) & (WLAN_CAPABILITY_ESS | WLAN_CAPABILITY_IBSS)))

#define WLAN_CAPABILITY_CF_POLLABLE (1<<2)
#define WLAN_CAPABILITY_CF_POLL_REQUEST (1<<3)
#define WLAN_CAPABILITY_PRIVACY     (1<<4)
#define WLAN_CAPABILITY_SHORT_PREAMBLE  (1<<5)
#define WLAN_CAPABILITY_PBCC        (1<<6)
#define WLAN_CAPABILITY_CHANNEL_AGILITY (1<<7)

/* 802.11h */
#define WLAN_CAPABILITY_SPECTRUM_MGMT   (1<<8)
#define WLAN_CAPABILITY_QOS     (1<<9)
#define WLAN_CAPABILITY_SHORT_SLOT_TIME (1<<10)
#define WLAN_CAPABILITY_APSD        (1<<11)
#define WLAN_CAPABILITY_RADIO_MEASURE   (1<<12)
#define WLAN_CAPABILITY_DSSS_OFDM   (1<<13)
#define WLAN_CAPABILITY_DEL_BACK    (1<<14)
#define WLAN_CAPABILITY_IMM_BACK    (1<<15)

/* DMG (60gHz) 802.11ad */
/* type - bits 0..1 */
#define WLAN_CAPABILITY_DMG_TYPE_MASK       (3<<0)
#define WLAN_CAPABILITY_DMG_TYPE_IBSS       (1<<0) /* Tx by: STA */
#define WLAN_CAPABILITY_DMG_TYPE_PBSS       (2<<0) /* Tx by: PCP */
#define WLAN_CAPABILITY_DMG_TYPE_AP     (3<<0) /* Tx by: AP */

#define WLAN_CAPABILITY_DMG_CBAP_ONLY       (1<<2)
#define WLAN_CAPABILITY_DMG_CBAP_SOURCE     (1<<3)
#define WLAN_CAPABILITY_DMG_PRIVACY     (1<<4)
#define WLAN_CAPABILITY_DMG_ECPAC       (1<<5)

#define WLAN_CAPABILITY_DMG_SPECTRUM_MGMT   (1<<8)
#define WLAN_CAPABILITY_DMG_RADIO_MEASURE   (1<<12)

/* measurement */
#define IEEE80211_SPCT_MSR_RPRT_MODE_LATE   (1<<0)
#define IEEE80211_SPCT_MSR_RPRT_MODE_INCAPABLE  (1<<1)
#define IEEE80211_SPCT_MSR_RPRT_MODE_REFUSED    (1<<2)

#define IEEE80211_SPCT_MSR_RPRT_TYPE_BASIC  0
#define IEEE80211_SPCT_MSR_RPRT_TYPE_CCA    1
#define IEEE80211_SPCT_MSR_RPRT_TYPE_RPI    2

/* 802.11g ERP information element */
#define WLAN_ERP_NON_ERP_PRESENT (1<<0)
#define WLAN_ERP_USE_PROTECTION (1<<1)
#define WLAN_ERP_BARKER_PREAMBLE (1<<2)

/* WLAN_ERP_BARKER_PREAMBLE values */
enum {
    WLAN_ERP_PREAMBLE_SHORT = 0,
    WLAN_ERP_PREAMBLE_LONG = 1,
};

/* Band ID, 802.11ad #8.4.1.45 */
enum {
    IEEE80211_BANDID_TV_WS = 0, /* TV white spaces */
    IEEE80211_BANDID_SUB1  = 1, /* Sub-1 GHz (excluding TV white spaces) */
    IEEE80211_BANDID_2G    = 2, /* 2.4 GHz */
    IEEE80211_BANDID_3G    = 3, /* 3.6 GHz */
    IEEE80211_BANDID_5G    = 4, /* 4.9 and 5 GHz */
    IEEE80211_BANDID_60G   = 5, /* 60 GHz */
};

/* Status codes */
enum ieee80211_statuscode {
    WLAN_STATUS_SUCCESS = 0,
    WLAN_STATUS_UNSPECIFIED_FAILURE = 1,
    WLAN_STATUS_CAPS_UNSUPPORTED = 10,
    WLAN_STATUS_REASSOC_NO_ASSOC = 11,
    WLAN_STATUS_ASSOC_DENIED_UNSPEC = 12,
    WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG = 13,
    WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION = 14,
    WLAN_STATUS_CHALLENGE_FAIL = 15,
    WLAN_STATUS_AUTH_TIMEOUT = 16,
    WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA = 17,
    WLAN_STATUS_ASSOC_DENIED_RATES = 18,
    /* 802.11b */
    WLAN_STATUS_ASSOC_DENIED_NOSHORTPREAMBLE = 19,
    WLAN_STATUS_ASSOC_DENIED_NOPBCC = 20,
    WLAN_STATUS_ASSOC_DENIED_NOAGILITY = 21,
    /* 802.11h */
    WLAN_STATUS_ASSOC_DENIED_NOSPECTRUM = 22,
    WLAN_STATUS_ASSOC_REJECTED_BAD_POWER = 23,
    WLAN_STATUS_ASSOC_REJECTED_BAD_SUPP_CHAN = 24,
    /* 802.11g */
    WLAN_STATUS_ASSOC_DENIED_NOSHORTTIME = 25,
    WLAN_STATUS_ASSOC_DENIED_NODSSSOFDM = 26,
    /* 802.11w */
    WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY = 30,
    WLAN_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION = 31,
    /* 802.11i */
    WLAN_STATUS_INVALID_IE = 40,
    WLAN_STATUS_INVALID_GROUP_CIPHER = 41,
    WLAN_STATUS_INVALID_PAIRWISE_CIPHER = 42,
    WLAN_STATUS_INVALID_AKMP = 43,
    WLAN_STATUS_UNSUPP_RSN_VERSION = 44,
    WLAN_STATUS_INVALID_RSN_IE_CAP = 45,
    WLAN_STATUS_CIPHER_SUITE_REJECTED = 46,
    /* 802.11e */
    WLAN_STATUS_UNSPECIFIED_QOS = 32,
    WLAN_STATUS_ASSOC_DENIED_NOBANDWIDTH = 33,
    WLAN_STATUS_ASSOC_DENIED_LOWACK = 34,
    WLAN_STATUS_ASSOC_DENIED_UNSUPP_QOS = 35,
    WLAN_STATUS_REQUEST_DECLINED = 37,
    WLAN_STATUS_INVALID_QOS_PARAM = 38,
    WLAN_STATUS_CHANGE_TSPEC = 39,
    WLAN_STATUS_WAIT_TS_DELAY = 47,
    WLAN_STATUS_NO_DIRECT_LINK = 48,
    WLAN_STATUS_STA_NOT_PRESENT = 49,
    WLAN_STATUS_STA_NOT_QSTA = 50,
    /* 802.11s */
    WLAN_STATUS_ANTI_CLOG_REQUIRED = 76,
    WLAN_STATUS_FCG_NOT_SUPP = 78,
    WLAN_STATUS_STA_NO_TBTT = 78,
    /* 802.11ad */
    WLAN_STATUS_REJECTED_WITH_SUGGESTED_CHANGES = 39,
    WLAN_STATUS_REJECTED_FOR_DELAY_PERIOD = 47,
    WLAN_STATUS_REJECT_WITH_SCHEDULE = 83,
    WLAN_STATUS_PENDING_ADMITTING_FST_SESSION = 86,
    WLAN_STATUS_PERFORMING_FST_NOW = 87,
    WLAN_STATUS_PENDING_GAP_IN_BA_WINDOW = 88,
    WLAN_STATUS_REJECT_U_PID_SETTING = 89,
    WLAN_STATUS_REJECT_DSE_BAND = 96,
    WLAN_STATUS_DENIED_WITH_SUGGESTED_BAND_AND_CHANNEL = 99,
    WLAN_STATUS_DENIED_DUE_TO_SPECTRUM_MANAGEMENT = 103,
};


/* Reason codes */
enum ieee80211_reasoncode {
    WLAN_REASON_UNSPECIFIED = 1,
    WLAN_REASON_PREV_AUTH_NOT_VALID = 2,
    WLAN_REASON_DEAUTH_LEAVING = 3,
    WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY = 4,
    WLAN_REASON_DISASSOC_AP_BUSY = 5,
    WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA = 6,
    WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA = 7,
    WLAN_REASON_DISASSOC_STA_HAS_LEFT = 8,
    WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH = 9,
    /* 802.11h */
    WLAN_REASON_DISASSOC_BAD_POWER = 10,
    WLAN_REASON_DISASSOC_BAD_SUPP_CHAN = 11,
    /* 802.11i */
    WLAN_REASON_INVALID_IE = 13,
    WLAN_REASON_MIC_FAILURE = 14,
    WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT = 15,
    WLAN_REASON_GROUP_KEY_HANDSHAKE_TIMEOUT = 16,
    WLAN_REASON_IE_DIFFERENT = 17,
    WLAN_REASON_INVALID_GROUP_CIPHER = 18,
    WLAN_REASON_INVALID_PAIRWISE_CIPHER = 19,
    WLAN_REASON_INVALID_AKMP = 20,
    WLAN_REASON_UNSUPP_RSN_VERSION = 21,
    WLAN_REASON_INVALID_RSN_IE_CAP = 22,
    WLAN_REASON_IEEE8021X_FAILED = 23,
    WLAN_REASON_CIPHER_SUITE_REJECTED = 24,
    /* TDLS (802.11z) */
    WLAN_REASON_TDLS_TEARDOWN_UNREACHABLE = 25,
    WLAN_REASON_TDLS_TEARDOWN_UNSPECIFIED = 26,
    /* 802.11e */
    WLAN_REASON_DISASSOC_UNSPECIFIED_QOS = 32,
    WLAN_REASON_DISASSOC_QAP_NO_BANDWIDTH = 33,
    WLAN_REASON_DISASSOC_LOW_ACK = 34,
    WLAN_REASON_DISASSOC_QAP_EXCEED_TXOP = 35,
    WLAN_REASON_QSTA_LEAVE_QBSS = 36,
    WLAN_REASON_QSTA_NOT_USE = 37,
    WLAN_REASON_QSTA_REQUIRE_SETUP = 38,
    WLAN_REASON_QSTA_TIMEOUT = 39,
    WLAN_REASON_QSTA_CIPHER_NOT_SUPP = 45,
    /* 802.11s */
    WLAN_REASON_MESH_PEER_CANCELED = 52,
    WLAN_REASON_MESH_MAX_PEERS = 53,
    WLAN_REASON_MESH_CONFIG = 54,
    WLAN_REASON_MESH_CLOSE = 55,
    WLAN_REASON_MESH_MAX_RETRIES = 56,
    WLAN_REASON_MESH_CONFIRM_TIMEOUT = 57,
    WLAN_REASON_MESH_INVALID_GTK = 58,
    WLAN_REASON_MESH_INCONSISTENT_PARAM = 59,
    WLAN_REASON_MESH_INVALID_SECURITY = 60,
    WLAN_REASON_MESH_PATH_ERROR = 61,
    WLAN_REASON_MESH_PATH_NOFORWARD = 62,
    WLAN_REASON_MESH_PATH_DEST_UNREACHABLE = 63,
    WLAN_REASON_MAC_EXISTS_IN_MBSS = 64,
    WLAN_REASON_MESH_CHAN_REGULATORY = 65,
    WLAN_REASON_MESH_CHAN = 66,
};


/* Information Element IDs */
enum ieee80211_eid {
    WLAN_EID_SSID = 0,
    WLAN_EID_SUPP_RATES = 1,
    WLAN_EID_FH_PARAMS = 2, /* reserved now */
    WLAN_EID_DS_PARAMS = 3,
    WLAN_EID_CF_PARAMS = 4,
    WLAN_EID_TIM = 5,
    WLAN_EID_IBSS_PARAMS = 6,
    WLAN_EID_COUNTRY = 7,
    /* 8, 9 reserved */
    WLAN_EID_REQUEST = 10,
    WLAN_EID_QBSS_LOAD = 11,
    WLAN_EID_EDCA_PARAM_SET = 12,
    WLAN_EID_TSPEC = 13,
    WLAN_EID_TCLAS = 14,
    WLAN_EID_SCHEDULE = 15,
    WLAN_EID_CHALLENGE = 16,
    /* 17-31 reserved for challenge text extension */
    WLAN_EID_PWR_CONSTRAINT = 32,
    WLAN_EID_PWR_CAPABILITY = 33,
    WLAN_EID_TPC_REQUEST = 34,
    WLAN_EID_TPC_REPORT = 35,
    WLAN_EID_SUPPORTED_CHANNELS = 36,
    WLAN_EID_CHANNEL_SWITCH = 37,
    WLAN_EID_MEASURE_REQUEST = 38,
    WLAN_EID_MEASURE_REPORT = 39,
    WLAN_EID_QUIET = 40,
    WLAN_EID_IBSS_DFS = 41,
    WLAN_EID_ERP_INFO = 42,
    WLAN_EID_TS_DELAY = 43,
    WLAN_EID_TCLAS_PROCESSING = 44,
    WLAN_EID_HT_CAPABILITY = 45,
    WLAN_EID_QOS_CAPA = 46,
    /* 47 reserved for Broadcom */
    WLAN_EID_RSN = 48,
    WLAN_EID_802_15_COEX = 49,
    WLAN_EID_EXT_SUPP_RATES = 50,
    WLAN_EID_AP_CHAN_REPORT = 51,
    WLAN_EID_NEIGHBOR_REPORT = 52,
    WLAN_EID_RCPI = 53,
    WLAN_EID_MOBILITY_DOMAIN = 54,
    WLAN_EID_FAST_BSS_TRANSITION = 55,
    WLAN_EID_TIMEOUT_INTERVAL = 56,
    WLAN_EID_RIC_DATA = 57,
    WLAN_EID_DSE_REGISTERED_LOCATION = 58,
    WLAN_EID_SUPPORTED_REGULATORY_CLASSES = 59,
    WLAN_EID_EXT_CHANSWITCH_ANN = 60,
    WLAN_EID_HT_OPERATION = 61,
    WLAN_EID_SECONDARY_CHANNEL_OFFSET = 62,
    WLAN_EID_BSS_AVG_ACCESS_DELAY = 63,
    WLAN_EID_ANTENNA_INFO = 64,
    WLAN_EID_RSNI = 65,
    WLAN_EID_MEASUREMENT_PILOT_TX_INFO = 66,
    WLAN_EID_BSS_AVAILABLE_CAPACITY = 67,
    WLAN_EID_BSS_AC_ACCESS_DELAY = 68,
    WLAN_EID_TIME_ADVERTISEMENT = 69,
    WLAN_EID_RRM_ENABLED_CAPABILITIES = 70,
    WLAN_EID_MULTIPLE_BSSID = 71,
    WLAN_EID_BSS_COEX_2040 = 72,
    WLAN_EID_BSS_INTOLERANT_CHL_REPORT = 73,
    WLAN_EID_OVERLAP_BSS_SCAN_PARAM = 74,
    WLAN_EID_RIC_DESCRIPTOR = 75,
    WLAN_EID_MMIE = 76,
    WLAN_EID_ASSOC_COMEBACK_TIME = 77,
    WLAN_EID_EVENT_REQUEST = 78,
    WLAN_EID_EVENT_REPORT = 79,
    WLAN_EID_DIAGNOSTIC_REQUEST = 80,
    WLAN_EID_DIAGNOSTIC_REPORT = 81,
    WLAN_EID_LOCATION_PARAMS = 82,
    WLAN_EID_NON_TX_BSSID_CAP =  83,
    WLAN_EID_SSID_LIST = 84,
    WLAN_EID_MULTI_BSSID_IDX = 85,
    WLAN_EID_FMS_DESCRIPTOR = 86,
    WLAN_EID_FMS_REQUEST = 87,
    WLAN_EID_FMS_RESPONSE = 88,
    WLAN_EID_QOS_TRAFFIC_CAPA = 89,
    WLAN_EID_BSS_MAX_IDLE_PERIOD = 90,
    WLAN_EID_TSF_REQUEST = 91,
    WLAN_EID_TSF_RESPOSNE = 92,
    WLAN_EID_WNM_SLEEP_MODE = 93,
    WLAN_EID_TIM_BCAST_REQ = 94,
    WLAN_EID_TIM_BCAST_RESP = 95,
    WLAN_EID_COLL_IF_REPORT = 96,
    WLAN_EID_CHANNEL_USAGE = 97,
    WLAN_EID_TIME_ZONE = 98,
    WLAN_EID_DMS_REQUEST = 99,
    WLAN_EID_DMS_RESPONSE = 100,
    WLAN_EID_LINK_ID = 101,
    WLAN_EID_WAKEUP_SCHEDUL = 102,
    /* 103 reserved */
    WLAN_EID_CHAN_SWITCH_TIMING = 104,
    WLAN_EID_PTI_CONTROL = 105,
    WLAN_EID_PU_BUFFER_STATUS = 106,
    WLAN_EID_INTERWORKING = 107,
    WLAN_EID_ADVERTISEMENT_PROTOCOL = 108,
    WLAN_EID_EXPEDITED_BW_REQ = 109,
    WLAN_EID_QOS_MAP_SET = 110,
    WLAN_EID_ROAMING_CONSORTIUM = 111,
    WLAN_EID_EMERGENCY_ALERT = 112,
    WLAN_EID_MESH_CONFIG = 113,
    WLAN_EID_MESH_ID = 114,
    WLAN_EID_LINK_METRIC_REPORT = 115,
    WLAN_EID_CONGESTION_NOTIFICATION = 116,
    WLAN_EID_PEER_MGMT = 117,
    WLAN_EID_CHAN_SWITCH_PARAM = 118,
    WLAN_EID_MESH_AWAKE_WINDOW = 119,
    WLAN_EID_BEACON_TIMING = 120,
    WLAN_EID_MCCAOP_SETUP_REQ = 121,
    WLAN_EID_MCCAOP_SETUP_RESP = 122,
    WLAN_EID_MCCAOP_ADVERT = 123,
    WLAN_EID_MCCAOP_TEARDOWN = 124,
    WLAN_EID_GANN = 125,
    WLAN_EID_RANN = 126,
    WLAN_EID_EXT_CAPABILITY = 127,
    /* 128, 129 reserved for Agere */
    WLAN_EID_PREQ = 130,
    WLAN_EID_PREP = 131,
    WLAN_EID_PERR = 132,
    /* 133-136 reserved for Cisco */
    WLAN_EID_PXU = 137,
    WLAN_EID_PXUC = 138,
    WLAN_EID_AUTH_MESH_PEER_EXCH = 139,
    WLAN_EID_MIC = 140,
    WLAN_EID_DESTINATION_URI = 141,
    WLAN_EID_UAPSD_COEX = 142,
    WLAN_EID_WAKEUP_SCHEDULE = 143,
    WLAN_EID_EXT_SCHEDULE = 144,
    WLAN_EID_STA_AVAILABILITY = 145,
    WLAN_EID_DMG_TSPEC = 146,
    WLAN_EID_DMG_AT = 147,
    WLAN_EID_DMG_CAP = 148,
    /* 149 reserved for Cisco */
    WLAN_EID_CISCO_VENDOR_SPECIFIC = 150,
    WLAN_EID_DMG_OPERATION = 151,
    WLAN_EID_DMG_BSS_PARAM_CHANGE = 152,
    WLAN_EID_DMG_BEAM_REFINEMENT = 153,
    WLAN_EID_CHANNEL_MEASURE_FEEDBACK = 154,
    /* 155-156 reserved for Cisco */
    WLAN_EID_AWAKE_WINDOW = 157,
    WLAN_EID_MULTI_BAND = 158,
    WLAN_EID_ADDBA_EXT = 159,
    WLAN_EID_NEXT_PCP_LIST = 160,
    WLAN_EID_PCP_HANDOVER = 161,
    WLAN_EID_DMG_LINK_MARGIN = 162,
    WLAN_EID_SWITCHING_STREAM = 163,
    WLAN_EID_SESSION_TRANSITION = 164,
    WLAN_EID_DYN_TONE_PAIRING_REPORT = 165,
    WLAN_EID_CLUSTER_REPORT = 166,
    WLAN_EID_RELAY_CAP = 167,
    WLAN_EID_RELAY_XFER_PARAM_SET = 168,
    WLAN_EID_BEAM_LINK_MAINT = 169,
    WLAN_EID_MULTIPLE_MAC_ADDR = 170,
    WLAN_EID_U_PID = 171,
    WLAN_EID_DMG_LINK_ADAPT_ACK = 172,
    /* 173 reserved for Symbol */
    WLAN_EID_MCCAOP_ADV_OVERVIEW = 174,
    WLAN_EID_QUIET_PERIOD_REQ = 175,
    /* 176 reserved for Symbol */
    WLAN_EID_QUIET_PERIOD_RESP = 177,
    /* 178-179 reserved for Symbol */
    /* 180 reserved for ISO/IEC 20011 */
    WLAN_EID_EPAC_POLICY = 182,
    WLAN_EID_CLISTER_TIME_OFF = 183,
    WLAN_EID_INTER_AC_PRIO = 184,
    WLAN_EID_SCS_DESCRIPTOR = 185,
    WLAN_EID_QLOAD_REPORT = 186,
    WLAN_EID_HCCA_TXOP_UPDATE_COUNT = 187,
    WLAN_EID_HL_STREAM_ID = 188,
    WLAN_EID_GCR_GROUP_ADDR = 189,
    WLAN_EID_ANTENNA_SECTOR_ID_PATTERN = 190,
    WLAN_EID_VHT_CAPABILITY = 191,
    WLAN_EID_VHT_OPERATION = 192,
    WLAN_EID_EXTENDED_BSS_LOAD = 193,
    WLAN_EID_WIDE_BW_CHANNEL_SWITCH = 194,
    WLAN_EID_VHT_TX_POWER_ENVELOPE = 195,
    WLAN_EID_CHANNEL_SWITCH_WRAPPER = 196,
    WLAN_EID_AID = 197,
    WLAN_EID_QUIET_CHANNEL = 198,
    WLAN_EID_OPMODE_NOTIF = 199,

    WLAN_EID_VENDOR_SPECIFIC = 221,
    WLAN_EID_QOS_PARAMETER = 222,
};

/* Action category code */
enum ieee80211_category {
    WLAN_CATEGORY_SPECTRUM_MGMT = 0,
    WLAN_CATEGORY_QOS = 1,
    WLAN_CATEGORY_DLS = 2,
    WLAN_CATEGORY_BACK = 3,
    WLAN_CATEGORY_PUBLIC = 4,
    WLAN_CATEGORY_RADIO_MEASUREMENT = 5,
    WLAN_CATEGORY_HT = 7,
    WLAN_CATEGORY_SA_QUERY = 8,
    WLAN_CATEGORY_PROTECTED_DUAL_OF_ACTION = 9,
    WLAN_CATEGORY_WNM = 10,
    WLAN_CATEGORY_WNM_UNPROTECTED = 11,
    WLAN_CATEGORY_TDLS = 12,
    WLAN_CATEGORY_MESH_ACTION = 13,
    WLAN_CATEGORY_MULTIHOP_ACTION = 14,
    WLAN_CATEGORY_SELF_PROTECTED = 15,
    WLAN_CATEGORY_DMG = 16,
    WLAN_CATEGORY_WMM = 17,
    WLAN_CATEGORY_FST = 18,
    WLAN_CATEGORY_UNPROT_DMG = 20,
    WLAN_CATEGORY_VHT = 21,
    WLAN_CATEGORY_VENDOR_SPECIFIC_PROTECTED = 126,
    WLAN_CATEGORY_VENDOR_SPECIFIC = 127,
};

/* SPECTRUM_MGMT action code */
enum ieee80211_spectrum_mgmt_actioncode {
    WLAN_ACTION_SPCT_MSR_REQ = 0,
    WLAN_ACTION_SPCT_MSR_RPRT = 1,
    WLAN_ACTION_SPCT_TPC_REQ = 2,
    WLAN_ACTION_SPCT_TPC_RPRT = 3,
    WLAN_ACTION_SPCT_CHL_SWITCH = 4,
};

/* HT action codes */
enum ieee80211_ht_actioncode {
    WLAN_HT_ACTION_NOTIFY_CHANWIDTH = 0,
    WLAN_HT_ACTION_SMPS = 1,
    WLAN_HT_ACTION_PSMP = 2,
    WLAN_HT_ACTION_PCO_PHASE = 3,
    WLAN_HT_ACTION_CSI = 4,
    WLAN_HT_ACTION_NONCOMPRESSED_BF = 5,
    WLAN_HT_ACTION_COMPRESSED_BF = 6,
    WLAN_HT_ACTION_ASEL_IDX_FEEDBACK = 7,
};

/* VHT action codes */
enum ieee80211_vht_actioncode {
    WLAN_VHT_ACTION_COMPRESSED_BF = 0,
    WLAN_VHT_ACTION_GROUPID_MGMT = 1,
    WLAN_VHT_ACTION_OPMODE_NOTIF = 2,
};

/* Self Protected Action codes */
enum ieee80211_self_protected_actioncode {
    WLAN_SP_RESERVED = 0,
    WLAN_SP_MESH_PEERING_OPEN = 1,
    WLAN_SP_MESH_PEERING_CONFIRM = 2,
    WLAN_SP_MESH_PEERING_CLOSE = 3,
    WLAN_SP_MGK_INFORM = 4,
    WLAN_SP_MGK_ACK = 5,
};

/* Mesh action codes */
enum ieee80211_mesh_actioncode {
    WLAN_MESH_ACTION_LINK_METRIC_REPORT,
    WLAN_MESH_ACTION_HWMP_PATH_SELECTION,
    WLAN_MESH_ACTION_GATE_ANNOUNCEMENT,
    WLAN_MESH_ACTION_CONGESTION_CONTROL_NOTIFICATION,
    WLAN_MESH_ACTION_MCCA_SETUP_REQUEST,
    WLAN_MESH_ACTION_MCCA_SETUP_REPLY,
    WLAN_MESH_ACTION_MCCA_ADVERTISEMENT_REQUEST,
    WLAN_MESH_ACTION_MCCA_ADVERTISEMENT,
    WLAN_MESH_ACTION_MCCA_TEARDOWN,
    WLAN_MESH_ACTION_TBTT_ADJUSTMENT_REQUEST,
    WLAN_MESH_ACTION_TBTT_ADJUSTMENT_RESPONSE,
};

/* Security key length */
enum ieee80211_key_len {
    WLAN_KEY_LEN_WEP40 = 5,
    WLAN_KEY_LEN_WEP104 = 13,
    WLAN_KEY_LEN_CCMP = 16,
    WLAN_KEY_LEN_CCMP_256 = 32,
    WLAN_KEY_LEN_TKIP = 32,
    WLAN_KEY_LEN_AES_CMAC = 16,
    WLAN_KEY_LEN_SMS4 = 32,
    WLAN_KEY_LEN_GCMP = 16,
    WLAN_KEY_LEN_GCMP_256 = 32,
    WLAN_KEY_LEN_BIP_CMAC_256 = 32,
    WLAN_KEY_LEN_BIP_GMAC_128 = 16,
    WLAN_KEY_LEN_BIP_GMAC_256 = 32,
};

#define IEEE80211_WEP_IV_LEN        4
#define IEEE80211_WEP_ICV_LEN       4
#define IEEE80211_CCMP_HDR_LEN      8
#define IEEE80211_CCMP_MIC_LEN      8
#define IEEE80211_CCMP_PN_LEN       6
#define IEEE80211_CCMP_256_HDR_LEN  8
#define IEEE80211_CCMP_256_MIC_LEN  16
#define IEEE80211_CCMP_256_PN_LEN   6
#define IEEE80211_TKIP_IV_LEN       8
#define IEEE80211_TKIP_ICV_LEN      4
#define IEEE80211_CMAC_PN_LEN       6
#define IEEE80211_GMAC_PN_LEN       6
#define IEEE80211_GCMP_HDR_LEN      8
#define IEEE80211_GCMP_MIC_LEN      16
#define IEEE80211_GCMP_PN_LEN       6

/* Public action codes */
enum ieee80211_pub_actioncode {
    WLAN_PUB_ACTION_EXT_CHANSW_ANN = 4,
    WLAN_PUB_ACTION_TDLS_DISCOVER_RES = 14,
};

/* TDLS action codes */
enum ieee80211_tdls_actioncode {
    WLAN_TDLS_SETUP_REQUEST = 0,
    WLAN_TDLS_SETUP_RESPONSE = 1,
    WLAN_TDLS_SETUP_CONFIRM = 2,
    WLAN_TDLS_TEARDOWN = 3,
    WLAN_TDLS_PEER_TRAFFIC_INDICATION = 4,
    WLAN_TDLS_CHANNEL_SWITCH_REQUEST = 5,
    WLAN_TDLS_CHANNEL_SWITCH_RESPONSE = 6,
    WLAN_TDLS_PEER_PSM_REQUEST = 7,
    WLAN_TDLS_PEER_PSM_RESPONSE = 8,
    WLAN_TDLS_PEER_TRAFFIC_RESPONSE = 9,
    WLAN_TDLS_DISCOVERY_REQUEST = 10,
};

/* Extended Channel Switching capability to be set in the 1st byte of
 * the @WLAN_EID_EXT_CAPABILITY information element
 */
#define WLAN_EXT_CAPA1_EXT_CHANNEL_SWITCHING    BIT(2)

/* TDLS capabilities in the the 4th byte of @WLAN_EID_EXT_CAPABILITY */
#define WLAN_EXT_CAPA4_TDLS_BUFFER_STA      BIT(4)
#define WLAN_EXT_CAPA4_TDLS_PEER_PSM        BIT(5)
#define WLAN_EXT_CAPA4_TDLS_CHAN_SWITCH     BIT(6)

/* Interworking capabilities are set in 7th bit of 4th byte of the
 * @WLAN_EID_EXT_CAPABILITY information element
 */
#define WLAN_EXT_CAPA4_INTERWORKING_ENABLED BIT(7)

/*
 * TDLS capabililites to be enabled in the 5th byte of the
 * @WLAN_EID_EXT_CAPABILITY information element
 */
#define WLAN_EXT_CAPA5_TDLS_ENABLED BIT(5)
#define WLAN_EXT_CAPA5_TDLS_PROHIBITED  BIT(6)
#define WLAN_EXT_CAPA5_TDLS_CH_SW_PROHIBITED    BIT(7)

#define WLAN_EXT_CAPA8_TDLS_WIDE_BW_ENABLED BIT(5)
#define WLAN_EXT_CAPA8_OPMODE_NOTIF BIT(6)

/* Defines the maximal number of MSDUs in an A-MSDU. */
#define WLAN_EXT_CAPA8_MAX_MSDU_IN_AMSDU_LSB    BIT(7)
#define WLAN_EXT_CAPA9_MAX_MSDU_IN_AMSDU_MSB    BIT(0)

/*
 * Fine Timing Measurement Initiator - bit 71 of @WLAN_EID_EXT_CAPABILITY
 * information element
 */
#define WLAN_EXT_CAPA9_FTM_INITIATOR    BIT(7)

/* TDLS specific payload type in the LLC/SNAP header */
#define WLAN_TDLS_SNAP_RFTYPE   0x2

/* BSS Coex IE information field bits */
#define WLAN_BSS_COEX_INFORMATION_REQUEST   BIT(0)

/**
 * enum - mesh synchronization method identifier
 *
 * @IEEE80211_SYNC_METHOD_NEIGHBOR_OFFSET: the default synchronization method
 * @IEEE80211_SYNC_METHOD_VENDOR: a vendor specific synchronization method
 *  that will be specified in a vendor specific information element
 */
enum {
    IEEE80211_SYNC_METHOD_NEIGHBOR_OFFSET = 1,
    IEEE80211_SYNC_METHOD_VENDOR = 255,
};

/**
 * enum - mesh path selection protocol identifier
 *
 * @IEEE80211_PATH_PROTOCOL_HWMP: the default path selection protocol
 * @IEEE80211_PATH_PROTOCOL_VENDOR: a vendor specific protocol that will
 *  be specified in a vendor specific information element
 */
enum {
    IEEE80211_PATH_PROTOCOL_HWMP = 1,
    IEEE80211_PATH_PROTOCOL_VENDOR = 255,
};

/**
 * enum - mesh path selection metric identifier
 *
 * @IEEE80211_PATH_METRIC_AIRTIME: the default path selection metric
 * @IEEE80211_PATH_METRIC_VENDOR: a vendor specific metric that will be
 *  specified in a vendor specific information element
 */
enum {
    IEEE80211_PATH_METRIC_AIRTIME = 1,
    IEEE80211_PATH_METRIC_VENDOR = 255,
};

/**
 * enum ieee80211_root_mode_identifier - root mesh STA mode identifier
 *
 * These attribute are used by dot11MeshHWMPRootMode to set root mesh STA mode
 *
 * @IEEE80211_ROOTMODE_NO_ROOT: the mesh STA is not a root mesh STA (default)
 * @IEEE80211_ROOTMODE_ROOT: the mesh STA is a root mesh STA if greater than
 *  this value
 * @IEEE80211_PROACTIVE_PREQ_NO_PREP: the mesh STA is a root mesh STA supports
 *  the proactive PREQ with proactive PREP subfield set to 0
 * @IEEE80211_PROACTIVE_PREQ_WITH_PREP: the mesh STA is a root mesh STA
 *  supports the proactive PREQ with proactive PREP subfield set to 1
 * @IEEE80211_PROACTIVE_RANN: the mesh STA is a root mesh STA supports
 *  the proactive RANN
 */
enum ieee80211_root_mode_identifier {
    IEEE80211_ROOTMODE_NO_ROOT = 0,
    IEEE80211_ROOTMODE_ROOT = 1,
    IEEE80211_PROACTIVE_PREQ_NO_PREP = 2,
    IEEE80211_PROACTIVE_PREQ_WITH_PREP = 3,
    IEEE80211_PROACTIVE_RANN = 4,
};

/*
 * IEEE 802.11-2007 7.3.2.9 Country information element
 *
 * Minimum length is 8 octets, ie len must be evenly
 * divisible by 2
 */

/* Although the spec says 8 I'm seeing 6 in practice */
#define IEEE80211_COUNTRY_IE_MIN_LEN    6

/* The Country String field of the element shall be 3 octets in length */
#define IEEE80211_COUNTRY_STRING_LEN    3

/*
 * For regulatory extension stuff see IEEE 802.11-2007
 * Annex I (page 1141) and Annex J (page 1147). Also
 * review 7.3.2.9.
 *
 * When dot11RegulatoryClassesRequired is true and the
 * first_channel/reg_extension_id is >= 201 then the IE
 * compromises of the 'ext' struct represented below:
 *
 *  - Regulatory extension ID - when generating IE this just needs
 *    to be monotonically increasing for each triplet passed in
 *    the IE
 *  - Regulatory class - index into set of rules
 *  - Coverage class - index into air propagation time (Table 7-27),
 *    in microseconds, you can compute the air propagation time from
 *    the index by multiplying by 3, so index 10 yields a propagation
 *    of 10 us. Valid values are 0-31, values 32-255 are not defined
 *    yet. A value of 0 inicates air propagation of <= 1 us.
 *
 *  See also Table I.2 for Emission limit sets and table
 *  I.3 for Behavior limit sets. Table J.1 indicates how to map
 *  a reg_class to an emission limit set and behavior limit set.
 */
#define IEEE80211_COUNTRY_EXTENSION_ID 201

/*
 *  Channels numbers in the IE must be monotonically increasing
 *  if dot11RegulatoryClassesRequired is not true.
 *
 *  If dot11RegulatoryClassesRequired is true consecutive
 *  subband triplets following a regulatory triplet shall
 *  have monotonically increasing first_channel number fields.
 *
 *  Channel numbers shall not overlap.
 *
 *  Note that max_power is signed.
 */
struct ieee80211_country_ie_triplet {
    union {
        struct {
            uint8_t first_channel;
            uint8_t num_channels;
            int8_t max_power;
        } __attribute__((__packed__)) chans;
        struct {
            uint8_t reg_extension_id;
            uint8_t reg_class;
            uint8_t coverage_class;
        } __attribute__((__packed__)) ext;
    };
} __attribute__((__packed__));

enum ieee80211_timeout_interval_type {
    WLAN_TIMEOUT_REASSOC_DEADLINE = 1 /* 802.11r */,
    WLAN_TIMEOUT_KEY_LIFETIME = 2 /* 802.11r */,
    WLAN_TIMEOUT_ASSOC_COMEBACK = 3 /* 802.11w */,
};

/**
 * struct ieee80211_timeout_interval_ie - Timeout Interval element
 * @type: type, see &enum ieee80211_timeout_interval_type
 * @value: timeout interval value
 */
struct ieee80211_timeout_interval_ie {
    uint8_t type;
    uint32_t value;
} __attribute__((__packed__));

/* BACK action code */
enum ieee80211_back_actioncode {
    WLAN_ACTION_ADDBA_REQ = 0,
    WLAN_ACTION_ADDBA_RESP = 1,
    WLAN_ACTION_DELBA = 2,
};

/* BACK (block-ack) parties */
enum ieee80211_back_parties {
    WLAN_BACK_RECIPIENT = 0,
    WLAN_BACK_INITIATOR = 1,
};

/* SA Query action */
enum ieee80211_sa_query_action {
    WLAN_ACTION_SA_QUERY_REQUEST = 0,
    WLAN_ACTION_SA_QUERY_RESPONSE = 1,
};


/* cipher suite selectors */
#define WLAN_CIPHER_SUITE_USE_GROUP 0x000FAC00
#define WLAN_CIPHER_SUITE_WEP40     0x000FAC01
#define WLAN_CIPHER_SUITE_TKIP      0x000FAC02
/* reserved:                0x000FAC03 */
#define WLAN_CIPHER_SUITE_CCMP      0x000FAC04
#define WLAN_CIPHER_SUITE_WEP104    0x000FAC05
#define WLAN_CIPHER_SUITE_AES_CMAC  0x000FAC06
#define WLAN_CIPHER_SUITE_GCMP      0x000FAC08
#define WLAN_CIPHER_SUITE_GCMP_256  0x000FAC09
#define WLAN_CIPHER_SUITE_CCMP_256  0x000FAC0A
#define WLAN_CIPHER_SUITE_BIP_GMAC_128  0x000FAC0B
#define WLAN_CIPHER_SUITE_BIP_GMAC_256  0x000FAC0C
#define WLAN_CIPHER_SUITE_BIP_CMAC_256  0x000FAC0D

#define WLAN_CIPHER_SUITE_SMS4      0x00147201

/* AKM suite selectors */
#define WLAN_AKM_SUITE_8021X        0x000FAC01
#define WLAN_AKM_SUITE_PSK      0x000FAC02
#define WLAN_AKM_SUITE_8021X_SHA256 0x000FAC05
#define WLAN_AKM_SUITE_PSK_SHA256   0x000FAC06
#define WLAN_AKM_SUITE_TDLS     0x000FAC07
#define WLAN_AKM_SUITE_SAE      0x000FAC08
#define WLAN_AKM_SUITE_FT_OVER_SAE  0x000FAC09

#define WLAN_MAX_KEY_LEN        32

#define WLAN_PMKID_LEN          16

#define WLAN_OUI_WFA            0x506f9a
#define WLAN_OUI_TYPE_WFA_P2P       9
#define WLAN_OUI_MICROSOFT      0x0050f2
#define WLAN_OUI_TYPE_MICROSOFT_WPA 1
#define WLAN_OUI_TYPE_MICROSOFT_WMM 2
#define WLAN_OUI_TYPE_MICROSOFT_WPS 4

/*
 * WMM/802.11e Tspec Element
 */
#define IEEE80211_WMM_IE_TSPEC_TID_MASK     0x0F
#define IEEE80211_WMM_IE_TSPEC_TID_SHIFT    1

enum ieee80211_tspec_status_code {
    IEEE80211_TSPEC_STATUS_ADMISS_ACCEPTED = 0,
    IEEE80211_TSPEC_STATUS_ADDTS_INVAL_PARAMS = 0x1,
};

struct ieee80211_tspec_ie {
    uint8_t element_id;
    uint8_t len;
    uint8_t oui[3];
    uint8_t oui_type;
    uint8_t oui_subtype;
    uint8_t version;
    uint16_t tsinfo;
    uint8_t tsinfo_resvd;
    uint16_t nominal_msdu;
    uint16_t max_msdu;
    uint32_t min_service_int;
    uint32_t max_service_int;
    uint32_t inactivity_int;
    uint32_t suspension_int;
    uint32_t service_start_time;
    uint32_t min_data_rate;
    uint32_t mean_data_rate;
    uint32_t peak_data_rate;
    uint32_t max_burst_size;
    uint32_t delay_bound;
    uint32_t min_phy_rate;
    uint16_t sba;
    uint16_t medium_time;
} __attribute__((__packed__));

/**
 * ieee80211_get_qos_ctl - get pointer to qos control bytes
 * @hdr: the frame
 *
 * The qos ctrl bytes come after the frame_control, duration, seq_num
 * and 3 or 4 addresses of length ETHER_ADDR_LEN.
 * 3 addr: 2 + 2 + 2 + 3*6 = 24
 * 4 addr: 2 + 2 + 2 + 4*6 = 30
 */
static inline uint8_t *ieee80211_get_qos_ctl(struct ieee80211_hdr *hdr)
{
    if (ieee80211_has_a4(hdr->frame_control))
        return (uint8_t *)hdr + 30;
    else
        return (uint8_t *)hdr + 24;
}

/**
 * ieee80211_get_SA - get pointer to SA
 * @hdr: the frame
 *
 * Given an 802.11 frame, this function returns the offset
 * to the source address (SA). It does not verify that the
 * header is long enough to contain the address, and the
 * header must be long enough to contain the frame control
 * field.
 */
static inline uint8_t *ieee80211_get_SA(struct ieee80211_hdr *hdr)
{
    if (ieee80211_has_a4(hdr->frame_control))
        return hdr->addr4;
    if (ieee80211_has_fromds(hdr->frame_control))
        return hdr->addr3;
    return hdr->addr2;
}

/**
 * ieee80211_get_DA - get pointer to DA
 * @hdr: the frame
 *
 * Given an 802.11 frame, this function returns the offset
 * to the destination address (DA). It does not verify that
 * the header is long enough to contain the address, and the
 * header must be long enough to contain the frame control
 * field.
 */
static inline uint8_t *ieee80211_get_DA(struct ieee80211_hdr *hdr)
{
    if (ieee80211_has_tods(hdr->frame_control))
        return hdr->addr3;
    else
        return hdr->addr1;
}

/**
 * _ieee80211_is_robust_mgmt_frame - check if frame is a robust management frame
 * @hdr: the frame (buffer must include at least the first octet of payload)
 */
static inline bool _ieee80211_is_robust_mgmt_frame(struct ieee80211_hdr *hdr)
{
    if (ieee80211_is_disassoc(hdr->frame_control) ||
        ieee80211_is_deauth(hdr->frame_control))
        return true;

    if (ieee80211_is_action(hdr->frame_control)) {
        uint8_t *category;

        /*
         * Action frames, excluding Public Action frames, are Robust
         * Management Frames. However, if we are looking at a Protected
         * frame, skip the check since the data may be encrypted and
         * the frame has already been found to be a Robust Management
         * Frame (by the other end).
         */
        if (ieee80211_has_protected(hdr->frame_control))
            return true;
        category = ((uint8_t *) hdr) + 24;
        return *category != WLAN_CATEGORY_PUBLIC &&
            *category != WLAN_CATEGORY_HT &&
            *category != WLAN_CATEGORY_WNM_UNPROTECTED &&
            *category != WLAN_CATEGORY_SELF_PROTECTED &&
            *category != WLAN_CATEGORY_UNPROT_DMG &&
            *category != WLAN_CATEGORY_VHT &&
            *category != WLAN_CATEGORY_VENDOR_SPECIFIC;
    }

    return false;
}

/**
 * ieee80211_is_robust_mgmt_frame - check if skb contains a robust mgmt frame
 * @skb: the skb containing the frame, length will be checked
 */
static inline bool ieee80211_is_robust_mgmt_frame(struct sk_buff *skb)
{
     if (skb->data_len < IEEE80211_MIN_ACTION_SIZE)
         return false;
     return _ieee80211_is_robust_mgmt_frame((struct ieee80211_hdr *)skb->buf_addr);
}

/**
 * ieee80211_is_public_action - check if frame is a public action frame
 * @hdr: the frame
 * @len: length of the frame
 */
static inline bool ieee80211_is_public_action(struct ieee80211_hdr *hdr,
                          size_t len)
{
    struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)hdr;

    if (len < IEEE80211_MIN_ACTION_SIZE)
        return false;
    if (!ieee80211_is_action(hdr->frame_control))
        return false;
    return mgmt->u.action.category == WLAN_CATEGORY_PUBLIC;
}

/**
 * _ieee80211_is_group_privacy_action - check if frame is a group addressed
 * privacy action frame
 * @hdr: the frame
 */
static inline bool _ieee80211_is_group_privacy_action(struct ieee80211_hdr *hdr)
{
    struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)hdr;

    if (!ieee80211_is_action(hdr->frame_control) ||
        !is_multicast_ether_addr((struct ether_addr *)hdr->addr1))
        return false;

    return mgmt->u.action.category == WLAN_CATEGORY_MESH_ACTION ||
           mgmt->u.action.category == WLAN_CATEGORY_MULTIHOP_ACTION;
}

/**
 * ieee80211_is_group_privacy_action - check if frame is a group addressed
 * privacy action frame
 * @skb: the skb containing the frame, length will be checked
 */
static inline bool ieee80211_is_group_privacy_action(struct sk_buff *skb)
{
     if (skb->data_len < IEEE80211_MIN_ACTION_SIZE)
         return false;
     return _ieee80211_is_group_privacy_action((struct ieee80211_hdr*)skb->buf_addr);
}

/**
 * ieee80211_tu_to_usec - convert time units (TU) to microseconds
 * @tu: the TUs
 */
static inline unsigned long ieee80211_tu_to_usec(unsigned long tu)
{
    return 1024 * tu;
}

/**
 * ieee80211_check_tim - check if AID bit is set in TIM
 * @tim: the TIM IE
 * @tim_len: length of the TIM IE
 * @aid: the AID to look for
 */
static inline bool ieee80211_check_tim(const struct ieee80211_tim_ie *tim,
                       uint8_t tim_len, uint16_t aid)
{
    uint8_t mask;
    uint8_t index, indexn1, indexn2;

    if (unlikely(!tim || tim_len < sizeof(*tim)))
        return false;

    aid &= 0x3fff;
    index = aid / 8;
    mask  = 1 << (aid & 7);

    indexn1 = tim->bitmap_ctrl & 0xfe;
    indexn2 = tim_len + indexn1 - 4;

    if (index < indexn1 || index > indexn2)
        return false;

    index -= indexn1;

    return !!(tim->virtual_map[index] & mask);
}

/**
 * ieee80211_get_tdls_action - get tdls packet action (or -1, if not tdls packet)
 * @skb: the skb containing the frame, length will not be checked
 * @hdr_size: the size of the ieee80211_hdr that starts at skb->data
 *
 * This function assumes the frame is a data frame, and that the network header
 * is in the correct place.
 */
static inline int ieee80211_get_tdls_action(struct sk_buff *skb, uint32_t hdr_size)
{
    // if (!skb_is_nonlinear(skb) &&
    //     skb->len > (skb_network_offset(skb) + 2)) {
    //     /* Point to where the indication of TDLS should start */
    //     const uint8_t *tdls_data = skb_network_header(skb) - 2;

    //     if (get_unaligned_be16(tdls_data) == ETH_P_TDLS &&
    //         tdls_data[2] == WLAN_TDLS_SNAP_RFTYPE &&
    //         tdls_data[3] == WLAN_CATEGORY_TDLS)
    //         return tdls_data[4];
    // }

    return -1;
}

/* convert time units */
#define TU_TO_JIFFIES(x)    (usecs_to_jiffies((x) * 1024))
#define TU_TO_EXP_TIME(x)   (jiffies + TU_TO_JIFFIES(x))

/**
 * ieee80211_action_contains_tpc - checks if the frame contains TPC element
 * @skb: the skb containing the frame, length will be checked
 *
 * This function checks if it's either TPC report action frame or Link
 * Measurement report action frame as defined in IEEE Std. 802.11-2012 8.5.2.5
 * and 8.5.7.5 accordingly.
 */
static inline bool ieee80211_action_contains_tpc(struct sk_buff *skb)
{
    struct ieee80211_mgmt *mgmt = NULL; // (void *)skb->data;

    // if (!ieee80211_is_action(mgmt->frame_control))
    //     return false;

    // if (skb->len < IEEE80211_MIN_ACTION_SIZE +
    //            sizeof(mgmt->u.action.u.tpc_report))
    //     return false;

    /*
     * TPC report - check that:
     * category = 0 (Spectrum Management) or 5 (Radio Measurement)
     * spectrum management action = 3 (TPC/Link Measurement report)
     * TPC report EID = 35
     * TPC report element length = 2
     *
     * The spectrum management's tpc_report struct is used here both for
     * parsing tpc_report and radio measurement's link measurement report
     * frame, since the relevant part is identical in both frames.
     */
    if (mgmt->u.action.category != WLAN_CATEGORY_SPECTRUM_MGMT &&
        mgmt->u.action.category != WLAN_CATEGORY_RADIO_MEASUREMENT)
        return false;

    /* both spectrum mgmt and link measurement have same action code */
    if (mgmt->u.action.u.tpc_report.action_code !=
        WLAN_ACTION_SPCT_TPC_RPRT)
        return false;

    if (mgmt->u.action.u.tpc_report.tpc_elem_id != WLAN_EID_TPC_REPORT ||
        mgmt->u.action.u.tpc_report.tpc_elem_length !=
        sizeof(struct ieee80211_tpc_report_ie))
        return false;

    return true;
}

#endif /* LINUX_IEEE80211_H */

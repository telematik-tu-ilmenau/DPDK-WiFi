
/* Wrapper for linux kernel types, macros and functions (header file). */

#ifndef ATH10K_OSDEP
#define ATH10K_OSDEP

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <math.h>
#include <assert.h>

#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include <rte_spinlock.h>
#include <rte_common.h>
#include <errno.h>
#include <rte_io.h>
#include <rte_cycles.h>

#include <sys/queue.h>

#include <rte_ieee80211.h>
#include <rte_types.h>

#define PHY_NAME "phy"

// TODO from Linux GPL, include/uapi/linux/pci_regs.h
#define PCI_EXP_LNKCTL          16      /* Link Control */
#define PCI_EXP_LNKCTL_ASPMC    0x0003  /* ASPM Control */

/* Type definitions. */
typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;

typedef uint8_t     __u8;
typedef uint16_t    __u16;
typedef uint32_t    __u32;

typedef uint16_t    __le16;
typedef uint32_t    __le32;
typedef uint64_t    __le64;

typedef int8_t      s8;
typedef int16_t     s16;
typedef int32_t     s32;

typedef int32_t __s32;

typedef uint64_t    dma_addr_t; // 32 bits might be enough? But 64 should not do any harm

#define INT_MAX ((int)~0U)
#define INT_MIN (-INT_MAX - 1)

typedef struct {
	u8 b[16];
} uuid_le;

// can be used for log debugging
#define lockdep_assert_held(x) assert(rte_spinlock_is_locked(x) == 1)

/* Macros and function prototypes. */
#define __cpu_to_le16(x) (rte_cpu_to_le_16((x)))
#define __le16_to_cpu(x) (rte_le_to_cpu_16((x)))
#define __cpu_to_le32(x) (rte_cpu_to_le_32((x)))
#define __le32_to_cpu(x) (rte_le_to_cpu_32((x)))
#define __cpu_to_le64(x) (rte_cpu_to_le_64((x)))
#define __le64_to_cpu(x) (rte_le_to_cpu_64((x)))
#define le16_to_cpu __le16_to_cpu
#define cpu_to_le16 __cpu_to_le16
#define le32_to_cpu __le32_to_cpu
#define cpu_to_le32 __cpu_to_le32
#define __be16  uint16_t
#define __be32  uint32_t
#define BIT(n) (1 << (n))

/* Don't change this without changing skb_csum_unnecessary! */
#define CHECKSUM_NONE		0
#define CHECKSUM_UNNECESSARY	1
#define CHECKSUM_COMPLETE	2
#define CHECKSUM_PARTIAL	3

/* Maximum value in skb->csum_level */
#define SKB_MAX_CSUM_LEVEL	3

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

// #define ATH10K_DBG_HTC 0

static inline __u32 __le32_to_cpup(const __le32 *p) {
	return (__u32)*p;
}
#define le32_to_cpup __le32_to_cpup

#define iowrite32(v, addr) rte_write32((v), (addr))
#define ioread32(addr) rte_read32(addr)

/**
 * ffs - find first set bit in word
 * @x: the word to search
 *
 * This is defined the same way as the libc and compiler builtin ffs
 * routines, therefore differs in spirit from the other bitops.
 *
 * ffs(value) returns 0 if value is 0 or the position of the first
 * set bit if value is nonzero. The first (least significant) bit
 * is at position 1.
 */
static inline int __ffs(int x)
{
	int r;

	/*
	 * AMD64 says BSFL won't clobber the dest reg if x==0; Intel64 says the
	 * dest reg is undefined if x==0, but their CPU architect says its
	 * value is written to set it to the same as before, except that the
	 * top 32 bits will be cleared.
	 *
	 * We cannot do this on 32 bits because at the very least some
	 * 486 CPUs did not behave this way.
	 */
	asm("bsfl %1,%0"
	    : "=r" (r)
	    : "rm" (x), "0" (-1));
	return r;
}

/**
 * __ffs64 - find first set bit in a 64 bit word
 * @word: The 64 bit word
 *
 * On 64 bit arches this is a synomyn for __ffs
 * The result is not defined if no bits are set, so check that @word
 * is non-zero before calling this.
 */
static inline unsigned long __ffs64(u64 word)
{
	#if __i386__
		if (((u32)word) == 0UL)
			return __ffs((u32)(word >> 32)) + 32;
	#endif
	return __ffs((unsigned long)word);
}


#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define __packed __attribute__((__packed__))
#define __aligned(x) __attribute__((aligned(x)))
#define uninitialized_var(x) x = x

/* The following defines seem to exist just for kernel debugging purposos, so we throw them out.*/
#define __iomem
#define BUILD_BUG_ON(condition) (condition)
#define WARN_ONCE(condition, msg) (condition, msg)
#define WARN_ON(condition) (condition)
#define WARN_ON_ONCE(condition) (condition)
#define might_sleep()

// IEEE 802.11 definitions
#define IEEE80211_MAX_SSID_LEN 32

/* U-APSD queues for WMM IEs sent by STA */
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_VO	(1<<0)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_VI	(1<<1)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_BK	(1<<2)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_BE	(1<<3)
#define IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK	0x0f

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#define __bitwise __bitwise__

#define __force

#define ENOTSUPP EOPNOTSUPP

#define roundup(x, y) (                                 \
		{                                                       \
		const typeof(y) __y = y;                        \
		(((x) + (__y - 1)) / __y) * __y;                \
		}                                                       \
		)

#define rounddown(x, y) (                               \
		{                                                       \
		typeof(x) __x = (x);                            \
		__x - (__x % (y));                              \
		}                                                       \
		)

#define max(x, y) ({                            \
		typeof(x) _max1 = (x);                  \
		typeof(y) _max2 = (y);                  \
		(void) (&_max1 == &_max2);              \
		_max1 > _max2 ? _max1 : _max2; })

#define typecheck(type,x) \
	({	type __dummy; \
	 typeof(x) __dummy2; \
	 (void)(&__dummy == &__dummy2); \
	 1; \
	 })


static inline int
is_power_of_2(unsigned long n)
{
	return n != 0 && ((n & (n-1)) == 0);
}

#define time_after(a,b) (		\
		typecheck(unsigned long, a) && 	\
		typecheck(unsigned long, b) && 	\
		((long)((b) - (a)) < 0)		\
		)

#define time_before(a,b)        time_after(b,a)

#define ETH_ALEN 6
#define ETH_ADDR_LEN	6

#define udelay(x) usleep(x)
#define msleep(x) usleep(x * 1000)
#define mdelay(x) udelay(x * 1000)

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define BITS_PER_BYTE 8
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define DECLARE_BITMAP(name,bits) unsigned long name[BITS_TO_LONGS(bits)]

#define BITS_PER_LONG 32 /* I'm sorry for the poor guy porting this to amd64. */

#define BITMAP_LAST_WORD_MASK(n)    (~0UL >> (BITS_PER_LONG - (n)))

#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1)

		// The following defines should be checked against kernel defs
		// just proof of concept atm TODO

		/* Receive Descriptor - Advanced */
		/*
		   union ath10k_adv_rx_desc {
		   struct {
		   __le64 pkt_addr;
		   __le64 hdr_addr;
		   } read;
		   struct {
		   struct {
		   union {
		   __le32 data;
		   struct {
		   __le16 pkt_info;
		   __le16 hdr_info;
		   } hs_rss;
		   } lo_dword;
		   union {
		   __le32 rss;
		   struct {
		   __le16 ip_id;
		   __le16 csum;
		   } csum_ip;
		   } hi_dword;
		   } lower;
		   struct {
		   __le32 status_error;/
		   __le16 length;
		   __le16 vlan;
		   } upper;
		   } wb;
		   };
		   */

struct ath10k_rx_desc {
	__le64 buffer_addr; /* Address of the descriptor's data buffer */
	__le16 length;      /* Length of data DMAed into data buffer */
	__le16 csum; /* Packet checksum */
	u8  status;  /* Descriptor status */
	u8  errors;  /* Descriptor Errors */
	__le16 special;
};

/* Transmit Descriptor - Advanced */
/*
   union ath10k_adv_tx_desc {
   struct {
   __le64 buffer_addr;
   __le32 cmd_type_len;
   __le32 olinfo_status;
   } read;
   struct {
   __le64 rsvd;
   __le32 nxtseq_seed;
   __le32 status;
   } wb;
   };
   */

/* Offload data descriptor */
struct ath10k_data_desc {
	__le64 buffer_addr;  /* Address of the descriptor's buffer address */
	union {
		__le32 data;
		struct {
			__le16 length;  /* Data buffer length */
			u8 typ_len_ext;
			u8 cmd;
		} flags;
	} lower;
	union {
		__le32 data;
		struct {
			u8 status;  /* Descriptor status */
			u8 popts;  /* Packet Options */
			__le16 special;
		} fields;
	} upper;
};



#define ATH10K_MIN_RING_DESC 32
#define ATH10K_MAX_RING_DESC 4096

#define ATH10K_ALIGN 128

/*
#define IGB_RXD_ALIGN   (ATH10K_ALIGN / sizeof(union ath10k_adv_rx_desc))
#define IGB_TXD_ALIGN   (ATH10K_ALIGN / sizeof(union ath10k_adv_tx_desc))
*/

#define ATH10K_RXD_ALIGN    (ATH10K_ALIGN / sizeof(struct ath10k_rx_desc))
#define ATH10K_TXD_ALIGN    (ATH10K_ALIGN / sizeof(struct ath10k_data_desc))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)

// TODO end


/* Functions. */
static inline u32 __raw_readl(const volatile void *addr) {
	return *(const volatile u32 *) addr;
}

static inline u32 readl(const volatile void *addr) {
	return __le32_to_cpu(__raw_readl(addr));
}

static inline void __raw_writel(u32 b, volatile void *addr) {
	*(volatile u32 *) addr = b;
}

static inline void *kmalloc(size_t size, gfp_t flags) {
	return rte_malloc(NULL, size, 0);
}

static inline void kfree(void *mem) {
	rte_free(mem);
}

static inline void *kzalloc(size_t size, gfp_t flags) {
	return rte_zmalloc(NULL, size, 0);
}

static inline void *kmemdup(const void *src, size_t len, gfp_t gfp){
	void *p = kmalloc(len, gfp);
	if (p)
		rte_memcpy(p, src, len);
	return p;
}

static inline uint32_t roundup_pow_of_two(uint32_t n) { // TODO faster impl for this, test if it works
	uint32_t i = 1;

	while(i < n) {
		i *= 2;
	}

	return i;
}

#define MAX_ERRNO       4095

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline bool IS_ERR(const void *ptr) {
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline long PTR_ERR(const void *ptr) {
	return (long) ptr;
}

static inline void *ERR_PTR(long error) {
	return (void *) error;
}

static inline void skb_reserve(struct sk_buff *skb, int len) {
	skb->data_off += len;
}

struct pci_dev {
	struct device dev;
};

struct pci_device_id {
	__u32 vendor, device;           /* Vendor and device ID or PCI_ANY_ID*/
	__u32 subvendor, subdevice;     /* Subsystem ID's or PCI_ANY_ID */
	__u32 class, class_mask;        /* (class,subclass,prog-if) triplet */
	unsigned long driver_data;     /* Data private to the driver */
};

typedef rte_spinlock_t spinlock_t;

#define ETHTOOL_FWVERS_LEN 32

struct reg_dmn_pair_mapping {
	u16 reg_domain;
	u16 reg_5ghz_ctl;
	u16 reg_2ghz_ctl;
};

struct ath_regulatory {
	char alpha2[2];
	// enum nl80211_dfs_regions region;
	u16 country_code;
	u16 max_power_level;
	u16 current_rd;
	int16_t power_limit;
	struct reg_dmn_pair_mapping *regpair;
};

struct ath_common {
	void *ah;
	void *priv;
	// int debug_mask;
	// enum ath_device_state state;
	unsigned long op_flags;

	// struct ath_ani ani;

	u16 cachelsz;
	u16 curaid;
	u8 macaddr[ETH_ALEN];
	u8 curbssid[ETH_ALEN];
	u8 bssidmask[ETH_ALEN];

	u32 rx_bufsize;

	u32 keymax;
	// DECLARE_BITMAP(keymap, ATH_KEYMAX);
	// DECLARE_BITMAP(tkip_keymap, ATH_KEYMAX);
	// DECLARE_BITMAP(ccmp_keymap, ATH_KEYMAX);
	// enum ath_crypt_caps crypt_caps;

	unsigned int clockrate;

	// spinlock_t cc_lock;
	// struct ath_cycle_counters cc_ani;
	// struct ath_cycle_counters cc_survey;

	struct ath_regulatory regulatory;
	struct ath_regulatory reg_world_copy;
	// const struct ath_ops *ops;
	// const struct ath_bus_ops *bus_ops;

	bool btcoex_enabled;
	bool disable_ani;
	bool bt_ant_diversity;

	int last_rssi;	
	// struct ieee80211_supported_band sbands[IEEE80211_NUM_BANDS];
};

void tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data);
void tasklet_schedule(struct tasklet_struct *t);

#define DECLARE_TASKLET(name, func, data) \
	struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }

#define DECLARE_TASKLET_DISABLED(name, func, data) \
	struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }

int scnprintf(char *buf, size_t size, const char *format, ...);

size_t ilog2(size_t x);

/*
 * Find the first set bit in a memory region.
 */
static inline unsigned long find_first_bit(const unsigned long *addr, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(BITS_PER_LONG-1)) {
		if ((tmp = *(p++)))
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;

	tmp = (*p) & (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
		return result + size;	/* Nope. */
found:
	return result + __ffs(tmp);
}

static inline int bitmap_empty(const unsigned long *src, unsigned nbits)
{
	return find_first_bit(src, nbits) == nbits;
}

#endif

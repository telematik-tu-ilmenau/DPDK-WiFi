#ifndef RTE_TYPES_H
#define RTE_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_timer.h>
#include <sys/queue.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <assert.h>

#define HZ (1000)

typedef uint64_t netdev_features_t;

enum {
    NETIF_F_SG_BIT,         /* Scatter/gather IO. */
    NETIF_F_IP_CSUM_BIT,        /* Can checksum TCP/UDP over IPv4. */
    __UNUSED_NETIF_F_1,
    NETIF_F_HW_CSUM_BIT,        /* Can checksum all the packets. */
    NETIF_F_IPV6_CSUM_BIT,      /* Can checksum TCP/UDP over IPV6 */
    NETIF_F_HIGHDMA_BIT,        /* Can DMA to high memory. */
    NETIF_F_FRAGLIST_BIT,       /* Scatter/gather IO. */
    NETIF_F_HW_VLAN_CTAG_TX_BIT,    /* Transmit VLAN CTAG HW acceleration */
    NETIF_F_HW_VLAN_CTAG_RX_BIT,    /* Receive VLAN CTAG HW acceleration */
    NETIF_F_HW_VLAN_CTAG_FILTER_BIT,/* Receive filtering on VLAN CTAGs */
    NETIF_F_VLAN_CHALLENGED_BIT,    /* Device cannot handle VLAN packets */
    NETIF_F_GSO_BIT,        /* Enable software GSO. */
    NETIF_F_LLTX_BIT,       /* LockLess TX - deprecated. Please */
                    /* do not use LLTX in new drivers */
    NETIF_F_NETNS_LOCAL_BIT,    /* Does not change network namespaces */
    NETIF_F_GRO_BIT,        /* Generic receive offload */
    NETIF_F_LRO_BIT,        /* large receive offload */

    /**/NETIF_F_GSO_SHIFT,      /* keep the order of SKB_GSO_* bits */
    NETIF_F_TSO_BIT         /* ... TCPv4 segmentation */
        = NETIF_F_GSO_SHIFT,
    NETIF_F_UFO_BIT,        /* ... UDPv4 fragmentation */
    NETIF_F_GSO_ROBUST_BIT,     /* ... ->SKB_GSO_DODGY */
    NETIF_F_TSO_ECN_BIT,        /* ... TCP ECN support */
    NETIF_F_TSO_MANGLEID_BIT,   /* ... IPV4 ID mangling allowed */
    NETIF_F_TSO6_BIT,       /* ... TCPv6 segmentation */
    NETIF_F_FSO_BIT,        /* ... FCoE segmentation */
    NETIF_F_GSO_GRE_BIT,        /* ... GRE with TSO */
    NETIF_F_GSO_GRE_CSUM_BIT,   /* ... GRE with csum with TSO */
    NETIF_F_GSO_IPXIP4_BIT,     /* ... IP4 or IP6 over IP4 with TSO */
    NETIF_F_GSO_IPXIP6_BIT,     /* ... IP4 or IP6 over IP6 with TSO */
    NETIF_F_GSO_UDP_TUNNEL_BIT, /* ... UDP TUNNEL with TSO */
    NETIF_F_GSO_UDP_TUNNEL_CSUM_BIT,/* ... UDP TUNNEL with TSO & CSUM */
    NETIF_F_GSO_PARTIAL_BIT,    /* ... Only segment inner-most L4
                     *     in hardware and all other
                     *     headers in software.
                     */
    NETIF_F_GSO_TUNNEL_REMCSUM_BIT, /* ... TUNNEL with TSO & REMCSUM */
    NETIF_F_GSO_SCTP_BIT,       /* ... SCTP fragmentation */
    NETIF_F_GSO_ESP_BIT,        /* ... ESP with TSO */
    /**/NETIF_F_GSO_LAST =      /* last bit, see GSO_MASK */
        NETIF_F_GSO_ESP_BIT,

    NETIF_F_FCOE_CRC_BIT,       /* FCoE CRC32 */
    NETIF_F_SCTP_CRC_BIT,       /* SCTP checksum offload */
    NETIF_F_FCOE_MTU_BIT,       /* Supports max FCoE MTU, 2158 bytes*/
    NETIF_F_NTUPLE_BIT,     /* N-tuple filters supported */
    NETIF_F_RXHASH_BIT,     /* Receive hashing offload */
    NETIF_F_RXCSUM_BIT,     /* Receive checksumming offload */
    NETIF_F_NOCACHE_COPY_BIT,   /* Use no-cache copyfromuser */
    NETIF_F_LOOPBACK_BIT,       /* Enable loopback */
    NETIF_F_RXFCS_BIT,      /* Append FCS to skb pkt data */
    NETIF_F_RXALL_BIT,      /* Receive errored frames too */
    NETIF_F_HW_VLAN_STAG_TX_BIT,    /* Transmit VLAN STAG HW acceleration */
    NETIF_F_HW_VLAN_STAG_RX_BIT,    /* Receive VLAN STAG HW acceleration */
    NETIF_F_HW_VLAN_STAG_FILTER_BIT,/* Receive filtering on VLAN STAGs */
    NETIF_F_HW_L2FW_DOFFLOAD_BIT,   /* Allow L2 Forwarding in Hardware */

    NETIF_F_HW_TC_BIT,      /* Offload TC infrastructure */
    NETIF_F_HW_ESP_BIT,     /* Hardware ESP transformation offload */
    NETIF_F_HW_ESP_TX_CSUM_BIT, /* ESP with TX checksum offload */

    /*
     * Add your fresh new feature above and remember to update
     * netdev_features_strings[] in net/core/ethtool.c and maybe
     * some feature mask #defines below. Please also describe it
     * in Documentation/networking/netdev-features.txt.
     */

    /**/NETDEV_FEATURE_COUNT
};

/* copy'n'paste compression ;) */
#define __NETIF_F_BIT(bit)  ((netdev_features_t)1 << (bit))
#define __NETIF_F(name)     __NETIF_F_BIT(NETIF_F_##name##_BIT)
#define NETIF_F_HW_CSUM     __NETIF_F(HW_CSUM)

/* TODO stuff which needs to be done properly. */
// Sources for skbuff
// http://www.makelinux.net/ldd3/chp-17-sect-10
// http://stackoverflow.com/questions/34065936/linux-kernel-alloc-skb-vs-dev-alloc-skb-vs-netdev-alloc-skb
#define sk_buff rte_mbuf
#define skb_dma_addr(skb) (rte_mbuf_data_dma_addr(skb))
#define skb_data(skb) (rte_pktmbuf_mtod(skb, unsigned char*))
#define skb_len(skb) (rte_pktmbuf_data_len(skb))
#define skb_tail_pointer(skb) (rte_pktmbuf_mtod(skb, unsigned char*) + skb_len(skb))
#define skb_tailroom(skb) (rte_pktmbuf_tailroom(skb))
// #define skb_put(skb, nbytes) (rte_pktmbuf_append(skb, nbytes))
static inline char* skb_put(struct rte_mbuf *skb, uint16_t nbytes) {
    void* tail = (char *)skb->buf_addr + skb->data_off + skb->data_len;
    skb->data_len = (uint16_t)(skb->data_len + nbytes);
    skb->pkt_len  = (skb->pkt_len + nbytes);
    return (char*) tail;
}
static inline char* skb_pull(struct rte_mbuf *skb, uint16_t len) {
    skb->data_len = (uint16_t)(skb->data_len - len);
    skb->data_off += len;
    skb->pkt_len  = (skb->pkt_len - len);
    return (char *)skb->buf_addr + skb->data_off;
}
static inline char* skb_push(struct rte_mbuf *skb, uint16_t len) {
    skb->data_off -= len;
    skb->data_len = (uint16_t)(skb->data_len + len);
    skb->pkt_len  = (skb->pkt_len + len);
    return (char *)skb->buf_addr + skb->data_off;
}
#define skb_free(skb) (rte_mbuf_raw_free(skb)) // TODO: check again if we can make it that easy

static inline void skb_trim(struct rte_mbuf *m, uint16_t len) {
    if(rte_pktmbuf_data_len(m) > len) {
         size_t trim_len = rte_pktmbuf_data_len(m) - len;
         m->data_len = (uint16_t)(m->data_len - trim_len);
         m->pkt_len  = (m->pkt_len - trim_len);
    }
}

static inline void* skb_put_data(struct rte_mbuf* skb, const void* data, unsigned int len) {
    void* tmp = skb_put(skb, len);
    rte_memcpy(tmp, data, len);
    return tmp;
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef LIST_HEAD(sk_buff_queue, sk_buff) skb_queue_t;
typedef TAILQ_HEAD(sk_buff_tailq, sk_buff) skb_tailq_t;
typedef LIST_HEAD(ieee80211_chanctx_list, ieee80211_chanctx) ieee80211_chanctx_list_t;

static inline unsigned int get_skb_tailq_len(skb_tailq_t* q) {
    unsigned int len = 0;
    struct sk_buff* unused;
    TAILQ_FOREACH(unused, q, pointers_tailq) {
        ++len;
    }
    return len;
}

static inline void purge_skb_tailq(skb_tailq_t* q) {
    while(TAILQ_EMPTY(q) == false) {
        struct sk_buff* to_free = TAILQ_FIRST(q);
        TAILQ_REMOVE(q, to_free, pointers_tailq);
        skb_free(to_free);
    }
}

typedef struct {
    int counter;
} atomic_t;

typedef enum {
    GFP_KERNEL,
    GFP_ATOMIC,
    __GFP_NOWARN
} gfp_t;

/**
 * struct device - The basic device structure
 * @parent: The device's "parent" device, the device to which it is attached.
 *      In most cases, a parent device is some sort of bus or host
 *      controller. If parent is NULL, the device, is a top-level device,
 *      which is not usually what you want.
 * @p:      Holds the private data of the driver core portions of the device.
 *      See the comment of the struct device_private for detail.
 * @kobj:   A top-level, abstract class from which other classes are derived.
 * @init_name:  Initial name of the device.
 * @type:   The type of device.
 *      This identifies the device type and carries type-specific
 *      information.
 * @mutex:  Mutex to synchronize calls to its driver.
 * @bus:    Type of bus device is on.
 * @driver: Which driver has allocated this
 * @platform_data: Platform data specific to the device.
 *      Example: For devices on custom boards, as typical of embedded
 *      and SOC based hardware, Linux often uses platform_data to point
 *      to board-specific structures describing devices and how they
 *      are wired.  That can include what ports are available, chip
 *      variants, which GPIO pins act in what additional roles, and so
 *      on.  This shrinks the "Board Support Packages" (BSPs) and
 *      minimizes board-specific #ifdefs in drivers.
 * @driver_data: Private pointer for driver specific info.
 * @power:  For device power management.
 *      See Documentation/power/devices.txt for details.
 * @pm_domain:  Provide callbacks that are executed during system suspend,
 *      hibernation, system resume and during runtime PM transitions
 *      along with subsystem-level and driver-level callbacks.
 * @pins:   For device pin management.
 *      See Documentation/pinctrl.txt for details.
 * @msi_list:   Hosts MSI descriptors
 * @msi_domain: The generic MSI domain this device is using.
 * @numa_node:  NUMA node this device is close to.
 * @dma_mask:   Dma mask (if dma'ble device).
 * @coherent_dma_mask: Like dma_mask, but for alloc_coherent mapping as not all
 *      hardware supports 64-bit addresses for consistent allocations
 *      such descriptors.
 * @dma_pfn_offset: offset of DMA memory range relatively of RAM
 * @dma_parms:  A low level driver may set these to teach IOMMU code about
 *      segment limitations.
 * @dma_pools:  Dma pools (if dma'ble device).
 * @dma_mem:    Internal for coherent mem override.
 * @cma_area:   Contiguous memory area for dma allocations
 * @archdata:   For arch-specific additions.
 * @of_node:    Associated device tree node.
 * @fwnode: Associated device node supplied by platform firmware.
 * @devt:   For creating the sysfs "dev".
 * @id:     device instance
 * @devres_lock: Spinlock to protect the resource of the device.
 * @devres_head: The resources list of the device.
 * @knode_class: The node used to add the device to the class list.
 * @class:  The class of the device.
 * @groups: Optional attribute groups.
 * @release:    Callback to free the device after all references have
 *      gone away. This should be set by the allocator of the
 *      device (i.e. the bus driver that discovered the device).
 * @iommu_group: IOMMU group the device belongs to.
 * @iommu_fwspec: IOMMU-specific properties supplied by firmware.
 *
 * @offline_disabled: If set, the device is permanently online.
 * @offline:    Set after successful invocation of bus type's .offline().
 *
 * At the lowest level, every device in a Linux system is represented by an
 * instance of struct device. The device structure contains the information
 * that the device model core needs to model the system. Most subsystems,
 * however, track additional information about the devices they host. As a
 * result, it is rare for devices to be represented by bare device structures;
 * instead, that structure, like kobject structures, is usually embedded within
 * a higher-level representation of the device.
 */
struct device {
    struct device       *parent;
//
//    struct device_private   *p;
//
//    struct kobject kobj;
    const char      *init_name; /* initial name of the device */
//    const struct device_type *type;
//
//    struct mutex        mutex;  /* mutex to synchronize calls to
//                     * its driver.
//                     */
//
//    struct bus_type *bus;       /* type of bus device is on */
//    struct device_driver *driver;   /* which driver has allocated this
//                       device */
    void        *platform_data; /* Platform specific data, device
//                       core doesn't touch it */
//    void        *driver_data;   /* Driver data, set and get with
//                       dev_set/get_drvdata */
//    struct dev_pm_info  power;
//    struct dev_pm_domain    *pm_domain;
//
//#ifdef CONFIG_GENERIC_MSI_IRQ_DOMAIN
//    struct irq_domain   *msi_domain;
//#endif
//#ifdef CONFIG_PINCTRL
//    struct dev_pin_info *pins;
//#endif
//#ifdef CONFIG_GENERIC_MSI_IRQ
//    struct list_head    msi_list;
//#endif
//
//#ifdef CONFIG_NUMA
//    int     numa_node;  /* NUMA node this device is close to */
//#endif
//    u64     *dma_mask;  /* dma mask (if dma'able device) */
//    u64     coherent_dma_mask;/* Like dma_mask, but for
//                         alloc_coherent mappings as
//                         not all hardware supports
//                         64 bit addresses for consistent
//                         allocations such descriptors. */
//    unsigned long   dma_pfn_offset;
//
//    struct device_dma_parameters *dma_parms;
//
//    struct list_head    dma_pools;  /* dma pools (if dma'ble) */
//
//    struct dma_coherent_mem *dma_mem; /* internal for coherent mem
//                         override */
//#ifdef CONFIG_DMA_CMA
//    struct cma *cma_area;       /* contiguous memory area for dma
//                       allocations */
//#endif
//    /* arch specific additions */
//    struct dev_archdata archdata;
//
//    struct device_node  *of_node; /* associated device tree node */
//    struct fwnode_handle    *fwnode; /* firmware device node */
//
//    dev_t           devt;   /* dev_t, creates the sysfs "dev" */
//    u32         id; /* device instance */
//
//    spinlock_t      devres_lock;
//    struct list_head    devres_head;
//
//    struct klist_node   knode_class;
//    struct class        *class;
//    const struct attribute_group **groups;  /* optional groups */
//
//    void    (*release)(struct device *dev);
//    struct iommu_group  *iommu_group;
//    struct iommu_fwspec *iommu_fwspec;
//
//    bool            offline_disabled:1;
//    bool            offline:1;
};

typedef struct {
    long long counter;
} atomic_long_t;

struct tasklet_struct
{
    struct tasklet_struct *next;
    unsigned long state;
    atomic_t count;
    void (*func)(unsigned long);
    unsigned long data;
};

struct list_head {
    struct list_head *next, *prev;
};


#define COMPAT_LIST_HEAD(n) \
struct list_head n = { \
    .prev = &n, \
    .next = &n \
}

#define INIT_LIST_HEAD(p) \
do { \
    struct list_head *__p298 = (p); \
    __p298->next = __p298; \
    __p298->prev = __p298->next; \
} while (0)

/**
 * list_entry - get the struct for this entry
 * @ptr:    the &struct list_head pointer.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:    the list head to take the element from.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)

/**
 * list_last_entry - get the last element from a list
 * @ptr:    the list head to take the element from.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_last_entry(ptr, type, member) \
    list_entry((ptr)->prev, type, member)

/**
 * list_first_entry_or_null - get the first element from a list
 * @ptr:    the list head to take the element from.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_head within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
#define list_first_entry_or_null(ptr, type, member) \
    (!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)

/**
 * list_next_entry - get the next element in list
 * @pos:    the type * to cursor
 * @member: the name of the list_head within the struct.
 */
#define list_next_entry(pos, member) \
    list_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * list_prev_entry - get the prev element in list
 * @pos:    the type * to cursor
 * @member: the name of the list_head within the struct.
 */
#define list_prev_entry(pos, member) \
    list_entry((pos)->member.prev, typeof(*(pos)), member)

/**
 * list_for_each    -   iterate over a list
 * @pos:    the &struct list_head to use as a loop cursor.
 * @head:   the head for your list.
 */
#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_prev   -   iterate over a list backwards
 * @pos:    the &struct list_head to use as a loop cursor.
 * @head:   the head for your list.
 */
#define list_for_each_prev(pos, head) \
    for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:    the &struct list_head to use as a loop cursor.
 * @n:      another &struct list_head to use as temporary storage
 * @head:   the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
        pos = n, n = pos->next)

/**
 * list_for_each_prev_safe - iterate over a list backwards safe against removal of list entry
 * @pos:    the &struct list_head to use as a loop cursor.
 * @n:      another &struct list_head to use as temporary storage
 * @head:   the head for your list.
 */
#define list_for_each_prev_safe(pos, n, head) \
    for (pos = (head)->prev, n = pos->prev; \
         pos != (head); \
         pos = n, n = pos->prev)

/**
 * list_for_each_entry  -   iterate over list of given type
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the list_head within the struct.
 */
#define list_for_each_entry(pos, head, member)              \
    for (pos = list_first_entry(head, typeof(*pos), member);    \
         &pos->member != (head);                    \
         pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the list_head within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member)          \
    for (pos = list_last_entry(head, typeof(*pos), member);     \
         &pos->member != (head);                    \
         pos = list_prev_entry(pos, member))

/**
 * list_prepare_entry - prepare a pos entry for use in list_for_each_entry_continue()
 * @pos:    the type * to use as a start point
 * @head:   the head of the list
 * @member: the name of the list_head within the struct.
 *
 * Prepares a pos entry for use as a start point in list_for_each_entry_continue().
 */
#define list_prepare_entry(pos, head, member) \
    ((pos) ? : list_entry(head, typeof(*pos), member))

/**
 * list_for_each_entry_continue - continue iteration over list of given type
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the list_head within the struct.
 *
 * Continue to iterate over list of given type, continuing after
 * the current position.
 */
#define list_for_each_entry_continue(pos, head, member)         \
    for (pos = list_next_entry(pos, member);            \
         &pos->member != (head);                    \
         pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_continue_reverse - iterate backwards from the given point
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the list_head within the struct.
 *
 * Start to iterate over list of given type backwards, continuing after
 * the current position.
 */
#define list_for_each_entry_continue_reverse(pos, head, member)     \
    for (pos = list_prev_entry(pos, member);            \
         &pos->member != (head);                    \
         pos = list_prev_entry(pos, member))

/**
 * list_for_each_entry_from - iterate over list of given type from the current point
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the list_head within the struct.
 *
 * Iterate over list of given type, continuing from current position.
 */
#define list_for_each_entry_from(pos, head, member)             \
    for (; &pos->member != (head);                  \
         pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:    the type * to use as a loop cursor.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_head within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)          \
    for (pos = list_first_entry(head, typeof(*pos), member),    \
        n = list_next_entry(pos, member);           \
         &pos->member != (head);                    \
         pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_continue - continue list iteration safe against removal
 * @pos:    the type * to use as a loop cursor.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_head within the struct.
 *
 * Iterate over list of given type, continuing after current point,
 * safe against removal of list entry.
 */
#define list_for_each_entry_safe_continue(pos, n, head, member)         \
    for (pos = list_next_entry(pos, member),                \
        n = list_next_entry(pos, member);               \
         &pos->member != (head);                        \
         pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_from - iterate over list from current point safe against removal
 * @pos:    the type * to use as a loop cursor.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_head within the struct.
 *
 * Iterate over list of given type from current point, safe against
 * removal of list entry.
 */
#define list_for_each_entry_safe_from(pos, n, head, member)             \
    for (n = list_next_entry(pos, member);                  \
         &pos->member != (head);                        \
         pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_reverse - iterate backwards over list safe against removal
 * @pos:    the type * to use as a loop cursor.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_head within the struct.
 *
 * Iterate backwards over list of given type, safe against removal
 * of list entry.
 */
#define list_for_each_entry_safe_reverse(pos, n, head, member)      \
    for (pos = list_last_entry(head, typeof(*pos), member),     \
        n = list_prev_entry(pos, member);           \
         &pos->member != (head);                    \
         pos = n, n = list_prev_entry(n, member))

/**
 * list_safe_reset_next - reset a stale list_for_each_entry_safe loop
 * @pos:    the loop cursor used in the list_for_each_entry_safe loop
 * @n:      temporary storage used in list_for_each_entry_safe
 * @member: the name of the list_head within the struct.
 *
 * list_safe_reset_next is not safe to use in general if the list may be
 * modified concurrently (eg. the lock is dropped in the loop body). An
 * exception to this is if the cursor element (pos) is pinned in the list,
 * and list_safe_reset_next is called after re-taking the lock and before
 * completing the current iteration of the loop body.
 */
#define list_safe_reset_next(pos, n, member)                \
    n = list_next_entry(pos, member)

static inline bool __list_del_entry_valid(struct list_head *entry)
{
    return true;
}

#define WRITE_ONCE(x, val) x=(val)

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
    next->prev = prev;
    WRITE_ONCE(prev->next, next);
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void __list_del_entry(struct list_head *entry)
{
    if (!__list_del_entry_valid(entry))
        return;

    __list_del(entry->prev, entry->next);
}

/**
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void list_del_init(struct list_head *entry)
{
    __list_del_entry(entry);
    INIT_LIST_HEAD(entry);
}

static inline void __list_add(struct list_head *newEl,
                  struct list_head *prev,
                  struct list_head *next)
{
    next->prev = newEl;
    newEl->next = next;
    newEl->prev = prev;
    prev->next = newEl;
}

/**
 * list_add_tail - add a new entry
 * @newEl: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *newEl, struct list_head *head)
{
    __list_add(newEl, head->prev, head);
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int list_empty(const struct list_head *head)
{
    return head->next == head;
}

struct timer_list {
    /*
     * All fields that change during normal runtime grouped to the
     * same cacheline
     */
    struct list_head entry;
    unsigned long expires;
    struct tvec_base *base;

    void (*function)(unsigned long);
    unsigned long data;

    int slack;

#ifdef CONFIG_TIMER_STATS
    int start_pid;
    void *start_site;
    char start_comm[16];
#endif
#ifdef CONFIG_LOCKDEP
    struct lockdep_map lockdep_map;
#endif
    struct rte_timer tim;
};

struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);

struct work_struct {
    atomic_long_t data;
    struct list_head entry;
    work_func_t func;
};

struct delayed_work {
    struct work_struct work;
    struct timer_list timer;

    /* target workqueue and CPU ->timer uses to queue ->work */
    struct workqueue_struct *wq;
    int cpu;
};

#ifdef __cplusplus
}
#endif

#endif /* RTE_TYPES_H */

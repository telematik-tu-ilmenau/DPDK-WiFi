#ifndef RTE_GENERAL_H
#define RTE_GENERAL_H

#include "rte_types.h"
#include <assert.h>

#define BUG_ON(x) assert(!(x))

void hexDumpRaw(const void *addr, int len);

#define __aligned(x) __attribute__((aligned(x)))

#define __ALIGN_KERNEL_MASK(x, mask)    (((x) + (mask)) & ~(mask))
#define __ALIGN_KERNEL(x, a)            __ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define ALIGN(x, a)                     __ALIGN_KERNEL((x), (a))
#define PTR_ALIGN(p, a)         ((typeof(p))ALIGN((unsigned long)(p), (a)))

#define BITS_PER_BYTE 8
#define BITS_PER_LONG 32 /* I'm sorry for the poor guy porting this to amd64. */
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
#define BIT(n) (1 << (n))
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)

#define U32_MAX ((uint32_t)~0U);

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

#define ETH_ALEN 6
#define ETH_ADDR_LEN    6
#define ETHTOOL_FWVERS_LEN 32

#define IFNAMSIZ 16

static inline int test_bit(int nr, const volatile unsigned long *addr) {
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

static __inline__ void __clear_bit (int nr, volatile void *addr) {
    *((volatile uint32_t *) addr + (nr >> 5)) &= ~(1 << (nr & 31));
}

static inline void set_bit(int nr, volatile unsigned long *addr) {
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

    *p  |= mask;
}

#define __set_bit(a, b) set_bit(a,b)

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

    *p &= ~mask;
}

static inline void atomic_set(atomic_t *v, int i) {
    v->counter = i;
}

static inline void atomic_inc(atomic_t *v) {
    ++(v->counter);
}

static inline int atomic_inc_return(atomic_t *v) {
    return ++(v->counter);
}

static inline void atomic_dec(atomic_t *v) {
    --(v->counter);
}

static inline int atomic_dec_return(atomic_t *v) {
    return --(v->counter);
}

struct workqueue_struct {
};

static inline void queue_work(struct workqueue_struct *wq, struct work_struct *ws) {
    ws->func(ws);
}

#define min_t(type, x, y) ({                    \
        type __min1 = (x);                      \
        type __min2 = (y);                      \
        __min1 < __min2 ? __min1: __min2; })

#endif /* RTE_GENERAL_H */

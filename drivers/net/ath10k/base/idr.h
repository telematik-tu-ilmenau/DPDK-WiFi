#ifndef _IDR_H_
#define _IDR_H_

#include "ath10k_osdep.h"
#include <rte_spinlock.h>

#define BIT(n) (1 << n)
#define SET_BIT(n,d) (d |= BIT(n))
#define CLEAR_BIT(n,d) (d &= ~(BIT(n)))
#define TEST_BIT(n,d) ((d >> n) & 1)

typedef uint32_t IDXBase_t;
#define BaseTypeBytes sizeof(IDXBase_t)
#define BaseTypeBit (8 * BaseTypeBytes)
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

struct idr {
    rte_spinlock_t lock;
    int lastUsedArrayIdx;
    unsigned int idxArraySize;
    IDXBase_t* idx;
    unsigned int maxIDs;
    void** ptrs;
};

void idr_init(struct idr *idr, unsigned int size);
int idr_alloc(struct idr *idr, void *ptr, int start, int end);
void* idr_find(struct idr *idr, int id);
int idr_for_each(struct idr *idr, int (*fn)(int id, void *p, void *data), void *data);
void idr_remove(struct idr *idr, int id);
void idr_destroy(struct idr *idr);

#endif

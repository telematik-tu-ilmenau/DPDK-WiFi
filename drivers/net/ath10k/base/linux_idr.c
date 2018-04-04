#include "idr.h"

void idr_init(struct idr *idr, unsigned int size) {
    idr->lastUsedArrayIdx = 0;
    rte_spinlock_init(&idr->lock);
    idr->maxIDs = size;
    idr->idxArraySize = DIV_ROUND_UP(idr->maxIDs,BaseTypeBit);
    idr->idx = rte_zmalloc(NULL, idr->idxArraySize * sizeof(BaseTypeBytes), 0);
    idr->ptrs = rte_zmalloc(NULL, idr->maxIDs * sizeof(void*), 0);
}

int idr_alloc_locked(struct idr *idr, void *ptr, int start, int end) {
    for(int i = 0; i < idr->idxArraySize; ++i) {
        assert(idr->lastUsedArrayIdx < idr->idxArraySize);
        int bitPos = __builtin_ffs(~(idr->idx[idr->lastUsedArrayIdx]));
        if(bitPos > 0) {
            bitPos -= 1;
            SET_BIT(bitPos, idr->idx[idr->lastUsedArrayIdx]);
            int id = idr->lastUsedArrayIdx * BaseTypeBit + bitPos;
            if(id >= idr->maxIDs) {
                idr->lastUsedArrayIdx = 0;
                continue;
            }
            idr->ptrs[id] = ptr;
            return id;
        } else {
            idr->lastUsedArrayIdx += 1;
            if(idr->lastUsedArrayIdx == idr->idxArraySize) {
                idr->lastUsedArrayIdx = 0;
            }
        }
    }
    return -1;
}

int idr_alloc(struct idr *idr, void *ptr, int start, int end) {
    int retval;

    rte_spinlock_lock(&idr->lock);
    retval = idr_alloc_locked(idr, ptr, start, end);
    rte_spinlock_unlock(&idr->lock);

    return retval;
}

void* idr_find_locked(struct idr *idr, int id) {
    if(TEST_BIT(id % BaseTypeBit, idr->idx[id / BaseTypeBit]) != 0) {
        return idr->ptrs[id];
    } else {
        return NULL;
    }
}

void* idr_find(struct idr *idr, int id) {
    void* retval;

    rte_spinlock_lock(&idr->lock);
    retval = idr_find_locked(idr, id);
    rte_spinlock_unlock(&idr->lock);

    return retval;
}

int idr_for_each(struct idr *idr, int (*fn)(int id, void *p, void *data), void *data) {
    int id = 0;
    for(int i = 0; i < idr->idxArraySize; ++i) {
        for(int j = 0; j < BaseTypeBit; ++j) {
            if(TEST_BIT(j, idr->idx[i]) != 0) {
                int err = fn(id, idr->ptrs[id], data);
                if(err) {
                    return err;
                }
            }
            if(++id == idr->maxIDs) {
                return 0;
            }
        }
    }
    return 0;
}

void idr_remove_locked(struct idr *idr, int id) {
    CLEAR_BIT(id % BaseTypeBit, idr->idx[id / BaseTypeBit]);
}

void idr_remove(struct idr *idr, int id) {
    rte_spinlock_lock(&idr->lock);
    idr_remove_locked(idr, id);
    rte_spinlock_unlock(&idr->lock);
}

void idr_destroy(struct idr *idr) {
    rte_free(idr->idx);
    rte_free(idr->ptrs);
}

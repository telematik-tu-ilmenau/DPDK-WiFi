#include "dma.h"
#include "core.h"
#include "debug.h"

#include <rte_ethdev.h>
#include <rte_memzone.h>
#include <rte_ethdev.h>

#include <assert.h>

struct rte_memzone *dma_alloc_coherent(struct ath10k *ar, size_t size, const char *ring_name, int id, int socket_id) {
    struct rte_memzone *memz;
    // ath10k_dbg(ar, ATH10K_DBG_BOOT, "start dma alloc for %s %i and size %u\n", ring_name, id, size);

    memz = rte_eth_dma_zone_reserve(ar->dev, ring_name, id, size, 0, socket_id);
    if (!memz) {
        ath10k_warn(ar, "dma memory allocation failed %s\n", ring_name);
        return ERR_PTR(-ENOMEM);
    }

    if (memz->addr == NULL) {
        ath10k_warn(ar, "addr is null\n");
    }

    // ath10k_dbg(ar, ATH10K_DBG_BOOT, "DMA done resulted in phy: 0x%x addr: 0x%x name: %s addr_64: 0x%x\n", (int)memz->phys_addr, memz->addr, memz->name, memz->addr_64);

    return memz;
}

struct rte_memzone *dma_zalloc_coherent(struct ath10k *ar, size_t size, const char *ring_name, int id, int socket_id) {
    struct rte_memzone *r = dma_alloc_coherent(ar, size, ring_name, id, socket_id);
    memset(r->addr, 0, r->len);
    return r;
}

void dma_free_coherent(struct ath10k *ar, struct rte_memzone *memz) {
    // ath10k_dbg(ar, ATH10K_DBG_BOOT, "DMA free of phy: 0x%x addr: 0x%x name: %s addr_64: 0x%x\n", (int)memz->phys_addr, memz->addr, memz->name, memz->addr_64);
    int ret;
    assert(memz != NULL);
    rte_memzone_free(memz);
}

#pragma once

#include "ath10k_osdep.h"

#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_memzone.h>
#include <rte_memory.h>

struct ath10k;

struct rte_memzone *dma_alloc_coherent(struct ath10k *ar, size_t size, const char *ring_name, int id, int socket_id);
struct rte_memzone *dma_zalloc_coherent(struct ath10k *ar, size_t size, const char *ring_name, int id, int socket_id);

void dma_free_coherent(struct ath10k *ar, struct rte_memzone *memz);

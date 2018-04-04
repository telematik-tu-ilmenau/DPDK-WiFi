#pragma once

#include "ath10k_osdep.h"
#include <rte_ethdev.h>
#include <sys/stat.h>

struct firmware {
    size_t size;
    const u8 *data;
};

int request_firmware(const struct firmware **firmware_p, const char *name, struct rte_eth_dev *device);

void release_firmware(const struct firmware *fw);

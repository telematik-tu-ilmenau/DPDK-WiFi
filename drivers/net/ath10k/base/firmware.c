#include "firmware.h"

#include <rte_malloc.h>
#include <rte_log.h>

#include <sys/stat.h>

#define PATH_MAX 4096

static off_t filesize(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    } else {
        return -1;
    }
}

int request_firmware(const struct firmware **firmware_p, const char *name, struct rte_eth_dev *device) {
    *firmware_p = NULL;
    int ret = 0;

    const char* fw_path = "/lib/firmware";

    char *path = malloc(PATH_MAX);
    if(!path) {
        RTE_LOG(ERR, PMD, "Coud not allocate memory for firmware path.\n");
        ret = -ENOMEM;
        goto err_ret;
    }

    snprintf(path, PATH_MAX, "%s/%s\0", fw_path, name);

    off_t size = filesize(path);
    if(size < 0) {
        RTE_LOG(DEBUG, PMD, "Could not get firmware file size for %s.\n", path);
        ret = -EIO;
        goto err_free_path;
    }

    char* buffer = rte_zmalloc(NULL, size, 0);
    if(!buffer) {
        RTE_LOG(ERR, PMD, "Coud not allocate memory for firmware %s.\n", path);
        ret = -ENOMEM;
        goto err_free_path;
    }

    RTE_LOG(INFO, PMD, "Reading %" PRIi64 " bytes of firmware from %s.\n", (int64_t) size, path);
    
    FILE* file_pointer = fopen(path, "rb");
    if(!file_pointer) {
        RTE_LOG(ERR, PMD, "Coud not open firmware file.\n");
        ret = -EIO;
        goto err_free_buffer;
    }

    size_t bytes_read = fread(buffer, sizeof(u8), size, file_pointer);
    if (bytes_read != size) {
        RTE_LOG(ERR, PMD, "Coud not read complete firmware.\n");
        ret = -EIO;
        goto err_close_fp;
    }

    struct firmware* fw = rte_zmalloc(NULL, sizeof(struct firmware), 0);
    fw->data = buffer;
    fw->size = size;
    *firmware_p = fw;

    RTE_LOG(DEBUG, PMD, "Reading firmware completed.\n");

err_close_fp:
    fclose(file_pointer);
    if(ret == 0) {
        goto err_free_path;
    }
err_free_buffer:
    rte_free(buffer);
err_free_path:
    free(path);
err_ret:
    return ret;
}

void release_firmware(const struct firmware *fw) {
    if(fw != NULL) {
        if(fw->data != NULL)
            rte_free(fw->data);
        rte_free(fw);
    }
}

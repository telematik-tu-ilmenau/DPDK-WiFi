#include "ath10k_osdep.h"

#include <stdio.h>
#include <stdarg.h>

#include "pci.h"

int scnprintf(char *buf, size_t size, const char *format, ...) {
    va_list args;
    int ret;
    
    va_start(args, format);
    ret = vsnprintf(buf, size, format, args);
    va_end(args);

    if(ret < size) {
        return ret;
    } else {
        return size;
    }
}

size_t ilog2(size_t x) {
    return (size_t) (log(x)/log(2));
}


#include "rte_general.h"

void hexDumpRaw(const void *addr, int len) {
    unsigned char* pc = (unsigned char*) addr;
    unsigned char res[3 * len + 1];
    res[3 * len] = '\0';
    printf("000000");
    for(unsigned int i = 0; i < len; i++) {
        sprintf((char *)res + i * 3, " %02X", pc[i]);
    }
    printf("%s\n", res);
}

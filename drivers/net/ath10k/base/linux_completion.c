#include "linux_completion.h"

#include <rte_types.h>
#include <rte_cycles.h>

unsigned long wait_for_completion_timeout(struct completion *x, unsigned long timeout) {
    // TODO: correct timeout conversion from jiffies to hz
    uint64_t to = rte_get_timer_cycles() + rte_get_timer_hz() * timeout / HZ;
    while(!x->done && to > rte_get_timer_cycles());

    if (x->done && to > rte_get_timer_cycles())
        return timeout;
    else
        return 0;
}

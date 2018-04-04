#pragma once

#ifndef _LINUX_COMPLETION_H_
#define _LINUX_COMPLETION_H_

#include "sleepqueue.h"
#include <stdint.h>
#include <stdbool.h>

struct completion {
    volatile unsigned int done;
    struct sleepqueue wait;
};

static inline void init_completion(struct completion *x)
{
    x->done = 0;
    sleepqueue_init(&x->wait);
}

static inline void reinit_completion(struct completion *x)
{
    x->done = 0;
}

static inline bool completion_done(struct completion *x)
{
    return x->done ? true : false;
}

static inline void complete(struct completion *x)
{
    x->done++;
}

unsigned long wait_for_completion_timeout(struct completion *x, unsigned long timeout);

#endif

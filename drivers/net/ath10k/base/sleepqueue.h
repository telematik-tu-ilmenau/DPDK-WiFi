#ifndef _SLEEPQUEUE_H
#define _SLEEPQUEUE_H

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <pthread.h>

struct sleepqueue {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

void sleepqueue_init(struct sleepqueue *sq);
void sleepqueue_sleep(struct sleepqueue *sq);
void sleepqueue_wake_one(struct sleepqueue *sq);
void sleepqueue_wake_all(struct sleepqueue *sq);

#endif

#include "sleepqueue.h"
#include <assert.h>

void sleepqueue_init(struct sleepqueue *sq) {
    assert(sq != NULL);
    pthread_mutex_init(&sq->mutex, NULL);
    pthread_cond_init(&sq->cond, NULL);
}

void sleepqueue_sleep(struct sleepqueue *sq) {
    pthread_mutex_lock(&sq->mutex);
    pthread_cond_wait(&sq->cond, &sq->mutex);
    pthread_mutex_unlock(&sq->mutex);
}

void sleepqueue_wake_one(struct sleepqueue *sq) {
    pthread_mutex_lock(&sq->mutex);
    pthread_cond_signal(&sq->cond);
    pthread_mutex_unlock(&sq->mutex);
}

void sleepqueue_wake_all(struct sleepqueue *sq) {
    pthread_mutex_lock(&sq->mutex);
    pthread_cond_broadcast(&sq->cond);
    pthread_mutex_unlock(&sq->mutex);
}

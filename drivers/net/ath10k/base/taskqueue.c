/*-
 * Copyright (c) 2000 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include "taskqueue.h"

#include <rte_malloc.h>
#include <rte_ring.h>
#include <stdbool.h>
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <pthread.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <assert.h>
#include <time.h>

void task_create(struct task *task, task_fn_t func) {
    task_create_arg(task, func, (void *)task);
}

void task_create_arg(struct task *task, task_fn_t func, void *arg) {
    task->func = func;
    task->arg = arg;
}

struct taskqueue {
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    pthread_condattr_t cond_attr;
    struct rte_ring *ring;
    bool running;
};

static void* taskqueue_func(void *arg) {
    struct taskqueue *tq = (struct taskqueue*) arg;
    struct timespec tw;
    int ret;

    while(tq->running == true) {
        pthread_mutex_lock(&tq->mutex);

        if (rte_ring_empty(tq->ring)) {
            clock_gettime(CLOCK_MONOTONIC, &tw);
            tw.tv_sec += 1;
            ret = pthread_cond_timedwait(&tq->cond, &tq->mutex, &tw);

            // maybe timeout
            if (ret != 0) {
                pthread_mutex_unlock(&tq->mutex);
                continue;
            }
        }
        struct task *task;
        rte_ring_dequeue(tq->ring, (void**) &task);
        pthread_mutex_unlock(&tq->mutex);

        task->func(task->arg);
    }

    return NULL;
}

struct taskqueue *taskqueue_create(const char* name) {
    struct taskqueue *tq = NULL;
    int ret;
    char thread_name[RTE_MAX_THREAD_NAME_LEN];

    tq = rte_zmalloc("taskqueue", sizeof(struct taskqueue), 0);
    if (tq == NULL)
        goto err_return;

    tq->running = true;

    ret = pthread_mutex_init(&tq->mutex, NULL);
    if (ret != 0)
        goto err_alloc;

    pthread_condattr_init(&tq->cond_attr);
    pthread_condattr_setclock(&tq->cond_attr, CLOCK_MONOTONIC);
    ret = pthread_cond_init(&tq->cond, &tq->cond_attr);
    if (ret != 0)
        goto err_mutex;

    tq->ring = rte_ring_create(name, 512, SOCKET_ID_ANY, 0);
    if (tq->ring == NULL)
        goto err_cond;

    ret = pthread_create(&tq->thread, NULL, taskqueue_func, tq);
    if (ret != 0)
        goto err_ring;

    /* Set thread_name for aid in debugging. */
    snprintf(thread_name, RTE_MAX_THREAD_NAME_LEN, name);
    ret = rte_thread_setname(tq->thread, thread_name);
    if (ret != 0) {
        RTE_LOG(DEBUG, EAL,
        "Failed to set thread name for taskqueue handling\n");
    }

    return tq;

err_ring:
    rte_ring_free(tq->ring);
err_cond:
    pthread_cond_destroy(&tq->cond);
err_mutex:
    pthread_mutex_destroy(&tq->mutex);
err_alloc:
    rte_free(tq);
err_return:
    return NULL;
}

void taskqueue_free(struct taskqueue *tq) {
    if(tq != NULL) {
        int ret;
        tq->running = false;

        ret = pthread_join(tq->thread, NULL);
        assert(ret == 0);

        pthread_mutex_destroy(&tq->mutex);
        pthread_cond_destroy(&tq->cond);
        pthread_condattr_destroy(&tq->cond_attr);
        rte_ring_free(tq->ring);
        rte_free(tq);
    }
}

void taskqueue_flush(struct taskqueue *tq) {
    void *elem;

    pthread_mutex_lock(&tq->mutex);
    while(!rte_ring_empty(tq->ring))
        rte_ring_dequeue(tq->ring, (void**) &elem);
    pthread_mutex_unlock(&tq->mutex);
}

int taskqueue_enqueue(struct taskqueue *tq, struct task *task) {
    if(tq == NULL)
        return -1;

    pthread_mutex_lock(&tq->mutex);
    rte_ring_enqueue(tq->ring, task);
    pthread_cond_signal((&tq->cond));
    pthread_mutex_unlock(&tq->mutex);

    return 0;
}

int taskqueue_enqueue_sync(struct taskqueue *tq, struct task *task) {
    task->func(task->arg);

    return 0;
}

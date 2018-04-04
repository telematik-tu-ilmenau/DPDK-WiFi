#pragma once

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
 * $FreeBSD$ sys/_task.h, sys/taskqueue.h
 */

#ifndef _TASKQUEUE_H
#define _TASKQUEUE_H

typedef void task_fn_t(void *context);

struct task {
    // STAILQ_ENTRY(task) ta_link; /* (q) link for queue */
    // uint16_t ta_pending;        /* (q) count times queued */
    // u_short ta_priority;        /* (c) Priority */
    task_fn_t *func;         /* (c) task handler */
    void    *arg;        /* (c) argument for handler */
};

void task_create(struct task *task, task_fn_t func);
void task_create_arg(struct task *task, task_fn_t func, void *arg);

struct taskqueue *taskqueue_create(const char* name);
void taskqueue_flush(struct taskqueue *tq);
void taskqueue_free(struct taskqueue *tq);
int taskqueue_enqueue(struct taskqueue *queue, struct task *task);
int taskqueue_enqueue_sync(struct taskqueue *queue, struct task *task);

#endif

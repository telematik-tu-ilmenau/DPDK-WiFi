/*
 * Copyright (c) 2016 Qualcomm Atheros, Inc
 *
 * GPL v2
 *
 * Based on net/sched/sch_fq_codel.c
 */
#ifndef __NET_SCHED_FQ_IMPL_H
#define __NET_SCHED_FQ_IMPL_H

#include "fq.h"
#include <sys/queue.h>
// #include "flow_dissector.h"

/* functions that are embedded into includer */

static struct sk_buff *fq_flow_dequeue(struct fq *fq,
				       struct fq_flow *flow)
{
	struct fq_tin *tin = flow->tin;
	struct fq_flow *i;
	struct sk_buff *skb;

	// lockdep_assert_held(&fq->lock);

	// skb = __skb_dequeue(&flow->queue);
	skb = TAILQ_FIRST(&flow->queue);
	TAILQ_REMOVE(&flow->queue, skb, pointers_tailq);
	if (!skb)
		return NULL;

	tin->backlog_bytes -= skb_len(skb);
	tin->backlog_packets--;
	flow->backlog -= skb_len(skb);
	fq->backlog--;
	fq->memory_usage -= skb->buf_len; // former truesize .. hopefully

	if (flow->backlog == 0) {
		// list_del_init(&flow->backlogchain);
		TAILQ_REMOVE(&fq->backlogs, flow, pointers_backlogchain);
	} else {
		i = flow;

		// list_for_each_entry_continue(i, &fq->backlogs, backlogchain)
		// 	if (i->backlog < flow->backlog)
		// 		break;
		// }
		while(true) {
		    if (i->backlog < flow->backlog)
                break;
		    if(TAILQ_NEXT(i, pointers_backlogchain) == NULL)
		        break;
		    i = TAILQ_NEXT(i, pointers_backlogchain);
		}

		// list_move_tail(&flow->backlogchain, &i->backlogchain);
		TAILQ_REMOVE(&fq->backlogs, flow, pointers_backlogchain);
		TAILQ_INSERT_AFTER(&fq->backlogs, i, flow, pointers_backlogchain);
	}

	return skb;
}

static struct sk_buff *fq_tin_dequeue(struct fq *fq,
				      struct fq_tin *tin,
				      fq_tin_dequeue_t dequeue_func)
{
	struct fq_flow *flow;
	// struct list_head *head;
	fq_flow_list_t* head;
	struct sk_buff *skb;

	// lockdep_assert_held(&fq->lock);

begin:
	head = &tin->new_flows;
	// if (list_empty(head)) {
	if (TAILQ_EMPTY(head)) {
		head = &tin->old_flows;
		// if (list_empty(head))
		if (TAILQ_EMPTY(head))
			return NULL;
	}

	// flow = list_first_entry(head, struct fq_flow, flowchain);
	flow = TAILQ_FIRST(head);

	if (flow->deficit <= 0) {
		flow->deficit += fq->quantum;
		// list_move_tail(&flow->flowchain, &tin->old_flows);
		TAILQ_REMOVE(head, flow, pointers_flowchain);
		TAILQ_INSERT_TAIL(&tin->old_flows, flow, pointers_flowchain);
		goto begin;
	}

	skb = dequeue_func(fq, tin, flow);
	if (!skb) {
		/* force a pass through old_flows to prevent starvation */
		if ((head == &tin->new_flows) &&
		    !TAILQ_EMPTY(&tin->old_flows)) {
			// list_move_tail(&flow->flowchain, &tin->old_flows);
		    TAILQ_REMOVE(head, flow, pointers_flowchain);
		    TAILQ_INSERT_TAIL(&tin->old_flows, flow, pointers_flowchain);
		} else {
			// list_del_init(&flow->flowchain);
		    TAILQ_REMOVE(head, flow, pointers_flowchain);
			flow->tin = NULL;
		}
		goto begin;
	}

	flow->deficit -= skb_len(skb);
	tin->tx_bytes += skb_len(skb);
	tin->tx_packets++;

	return skb;
}

static struct fq_flow *fq_flow_classify(struct fq *fq,
					struct fq_tin *tin,
					struct sk_buff *skb,
					fq_flow_get_default_t get_default_func)
{
	struct fq_flow *flow;
	uint32_t hash;
	uint32_t idx;

	// lockdep_assert_held(&fq->lock);

	// struct flow_keys keys;
	// memset(&keys, 0, sizeof(keys));
    // __skb_flow_dissect(skb, &flow_keys_dissector, &keys, NULL, 0, 0, 0, FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);
	// hash = __flow_hash_from_keys(keys, fq->perturbation);
	// just take the random seed for now .. TODO: check if that necessarily needs to be more elaborate
	hash = fq->perturbation;
	idx = (uint32_t)(((uint64_t) hash * fq->flows_cnt) >> 32);
	flow = &fq->flows[idx];

	if (flow->tin && flow->tin != tin) {
		flow = get_default_func(fq, tin, idx, skb);
		tin->collisions++;
		fq->collisions++;
	}

	if (!flow->tin)
		tin->flows++;

	return flow;
}

static void fq_recalc_backlog(struct fq *fq,
			      struct fq_tin *tin,
			      struct fq_flow *flow)
{
	struct fq_flow *i;

//	if (list_empty(&flow->backlogchain))
//		list_add_tail(&flow->backlogchain, &fq->backlogs);
	if(flow->pointers_backlogchain.tqe_next == NULL && flow->pointers_backlogchain.tqe_prev == NULL) {
	    TAILQ_INSERT_TAIL(&fq->backlogs, flow, pointers_backlogchain);
	}

	i = flow;
//	list_for_each_entry_continue_reverse(i, &fq->backlogs, backlogchain)
//		if (i->backlog > flow->backlog)
//			break;
	while(true) {
	    if (i->backlog > flow->backlog)
	        break;
        if(TAILQ_PREV(i, fq_flow_list, pointers_backlogchain) == NULL)
            break;
        i = TAILQ_PREV(i, fq_flow_list, pointers_backlogchain);
    }

	// list_move(&flow->backlogchain, &i->backlogchain);
	TAILQ_REMOVE(&fq->backlogs, flow, pointers_backlogchain);
	TAILQ_INSERT_AFTER(&fq->backlogs, i, flow, pointers_backlogchain);
}

static void fq_tin_enqueue(struct fq *fq,
			   struct fq_tin *tin,
			   struct sk_buff *skb,
			   fq_skb_free_t free_func,
			   fq_flow_get_default_t get_default_func)
{
	struct fq_flow *flow;

	// lockdep_assert_held(&fq->lock);

	flow = fq_flow_classify(fq, tin, skb, get_default_func);

	flow->tin = tin;
	flow->backlog += skb_len(skb);
	tin->backlog_bytes += skb_len(skb);
	tin->backlog_packets++;
	fq->memory_usage += skb->buf_len; // former truesize .. hopefully
	fq->backlog++;

	fq_recalc_backlog(fq, tin, flow);

	// if (list_empty(&flow->flowchain)) {
	if(flow->pointers_flowchain.tqe_next == NULL && flow->pointers_flowchain.tqe_prev == NULL) {
		flow->deficit = fq->quantum;
		// list_add_tail(&flow->flowchain, &tin->new_flows);
		TAILQ_INSERT_TAIL(&tin->new_flows, flow, pointers_flowchain);
	}

	// __skb_queue_tail(&flow->queue, skb);
	TAILQ_INSERT_TAIL(&flow->queue, skb, pointers_tailq);

	if (fq->backlog > fq->limit || fq->memory_usage > fq->memory_limit) {
//		flow = list_first_entry_or_null(&fq->backlogs,
//						struct fq_flow,
//						backlogchain);
	    if(TAILQ_EMPTY(&fq->backlogs) == true) {
	        flow = NULL;
	    } else {
	        flow = TAILQ_FIRST(&fq->backlogs);
	    }
		if (!flow)
			return;

		skb = fq_flow_dequeue(fq, flow);
		if (!skb)
			return;

		free_func(fq, flow->tin, flow, skb);

		flow->tin->overlimit++;
		fq->overlimit++;
		if (fq->memory_usage > fq->memory_limit)
			fq->overmemory++;
	}
}

static void fq_flow_reset(struct fq *fq,
			  struct fq_flow *flow,
			  fq_skb_free_t free_func)
{
	struct sk_buff *skb;

	while ((skb = fq_flow_dequeue(fq, flow)))
		free_func(fq, flow->tin, flow, skb);

//	if (!list_empty(&flow->flowchain))
//		list_del_init(&flow->flowchain);
	if(!(flow->pointers_flowchain.tqe_next == NULL && flow->pointers_flowchain.tqe_prev == NULL)) {
	    // TODO that should be done more efficient .. might need modification of structs
	    struct fq_flow* it;
	    TAILQ_FOREACH(it, &flow->tin->new_flows, pointers_flowchain) {
	        if(it == flow) {
	            TAILQ_REMOVE(&flow->tin->new_flows, flow, pointers_flowchain);
	            break;
	        }
	    }
	    TAILQ_FOREACH(it, &flow->tin->old_flows, pointers_flowchain) {
            if(it == flow) {
                TAILQ_REMOVE(&flow->tin->old_flows, flow, pointers_flowchain);
                break;
            }
        }
	}

//	if (!list_empty(&flow->backlogchain))
//		list_del_init(&flow->backlogchain);
	if(!(flow->pointers_backlogchain.tqe_next == NULL && flow->pointers_backlogchain.tqe_prev == NULL)) {
	    TAILQ_REMOVE(&fq->backlogs, flow, pointers_backlogchain);
	}

	flow->tin = NULL;

	// WARN_ON_ONCE(flow->backlog);
}

static void fq_tin_reset(struct fq *fq,
			 struct fq_tin *tin,
			 fq_skb_free_t free_func)
{
	// struct list_head *head;
	fq_flow_list_t* head;
	struct fq_flow *flow;

	for (;;) {
		head = &tin->new_flows;
		// if (list_empty(head)) {
		if(TAILQ_EMPTY(head)) {
			head = &tin->old_flows;
			if (TAILQ_EMPTY(head))
				break;
		}

		// flow = list_first_entry(head, struct fq_flow, flowchain);
		flow = TAILQ_FIRST(head);
		fq_flow_reset(fq, flow, free_func);
	}

	// WARN_ON_ONCE(tin->backlog_bytes);
	// WARN_ON_ONCE(tin->backlog_packets);
}

static void fq_flow_init(struct fq_flow *flow)
{
//	INIT_LIST_HEAD(&flow->flowchain);
//	INIT_LIST_HEAD(&flow->backlogchain);
//	__skb_queue_head_init(&flow->queue);
	TAILQ_INIT(&flow->queue);
}

static void fq_tin_init(struct fq_tin *tin)
{
	// INIT_LIST_HEAD(&tin->new_flows);
	TAILQ_INIT(&tin->new_flows);
	// INIT_LIST_HEAD(&tin->old_flows);
	TAILQ_INIT(&tin->old_flows);
}

static int fq_init(struct fq *fq, int flows_cnt)
{
	int i;

	memset(fq, 0, sizeof(fq[0]));
	// INIT_LIST_HEAD(&fq->backlogs);
	TAILQ_INIT(&fq->backlogs);
	// spin_lock_init(&fq->lock);
	uint32_t __max1 = flows_cnt;
	uint32_t __max2 = 1;
    fq->flows_cnt = __max1 > __max2 ? __max1 : __max2;
	fq->perturbation = (uint32_t) rte_rand();;
	fq->quantum = 300;
	fq->limit = 8192;
	fq->memory_limit = 16 << 20; /* 16 MBytes */

	// fq->flows = kcalloc(fq->flows_cnt, sizeof(fq->flows[0]), GFP_KERNEL);
	fq->flows = rte_malloc(NULL, fq->flows_cnt * sizeof(fq->flows[0]), 0);
	if (!fq->flows)
		return -ENOMEM;

	for (i = 0; i < fq->flows_cnt; i++)
		fq_flow_init(&fq->flows[i]);

	return 0;
}

static void fq_reset(struct fq *fq,
		     fq_skb_free_t free_func)
{
	int i;

	for (i = 0; i < fq->flows_cnt; i++)
		fq_flow_reset(fq, &fq->flows[i], free_func);

	// kfree(fq->flows);
	rte_free(fq->flows);
	fq->flows = NULL;
}

#endif

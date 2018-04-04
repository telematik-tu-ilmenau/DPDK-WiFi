/*
 * Copyright (c) 2016 Qualcomm Atheros, Inc
 *
 * GPL v2
 *
 * Based on net/sched/sch_fq_codel.c
 */
#ifndef __NET_SCHED_FQ_H
#define __NET_SCHED_FQ_H

#include "rte_types.h"

struct fq_tin;
struct fq_flow;
typedef TAILQ_HEAD(fq_flow_list, fq_flow) fq_flow_list_t;

/**
 * struct fq_flow - per traffic flow queue
 *
 * @tin: owner of this flow. Used to manage collisions, i.e. when a packet
 *	hashes to an index which points to a flow that is already owned by a
 *	different tin the packet is destined to. In such case the implementer
 *	must provide a fallback flow
 * @flowchain: can be linked to fq_tin's new_flows or old_flows. Used for DRR++
 *	(deficit round robin) based round robin queuing similar to the one
 *	found in net/sched/sch_fq_codel.c
 * @backlogchain: can be linked to other fq_flow and fq. Used to keep track of
 *	fat flows and efficient head-dropping if packet limit is reached
 * @queue: sk_buff queue to hold packets
 * @backlog: number of bytes pending in the queue. The number of packets can be
 *	found in @queue.qlen
 * @deficit: used for DRR++
 */
struct fq_flow {
	struct fq_tin *tin;
	// struct list_head flowchain;
	TAILQ_ENTRY(fq_flow) pointers_flowchain;
	// struct list_head backlogchain;
	TAILQ_ENTRY(fq_flow) pointers_backlogchain;
	skb_tailq_t queue;
	uint32_t backlog;
	int deficit;
};

/**
 * struct fq_tin - a logical container of fq_flows
 *
 * Used to group fq_flows into a logical aggregate. DRR++ scheme is used to
 * pull interleaved packets out of the associated flows.
 *
 * @new_flows: linked list of fq_flow
 * @old_flows: linked list of fq_flow
 */
struct fq_tin {
    fq_flow_list_t new_flows;
    fq_flow_list_t old_flows;
	uint32_t backlog_bytes;
	uint32_t backlog_packets;
	uint32_t overlimit;
	uint32_t collisions;
	uint32_t flows;
	uint32_t tx_bytes;
	uint32_t tx_packets;
};

/**
 * struct fq - main container for fair queuing purposes
 *
 * @backlogs: linked to fq_flows. Used to maintain fat flows for efficient
 *	head-dropping when @backlog reaches @limit
 * @limit: max number of packets that can be queued across all flows
 * @backlog: number of packets queued across all flows
 */
struct fq {
	struct fq_flow *flows;
	// struct list_head backlogs;
	fq_flow_list_t backlogs;
	// spinlock_t lock;
	uint32_t flows_cnt;
	uint32_t perturbation;
	uint32_t limit;
	uint32_t memory_limit;
	uint32_t memory_usage;
	uint32_t quantum;
	uint32_t backlog;
	uint32_t overlimit;
	uint32_t overmemory;
	uint32_t collisions;
};

typedef struct sk_buff *fq_tin_dequeue_t(struct fq *,
					 struct fq_tin *,
					 struct fq_flow *flow);

typedef void fq_skb_free_t(struct fq *,
			   struct fq_tin *,
			   struct fq_flow *,
			   struct sk_buff *);

typedef struct fq_flow *fq_flow_get_default_t(struct fq *,
					      struct fq_tin *,
					      int idx,
					      struct sk_buff *);

#endif

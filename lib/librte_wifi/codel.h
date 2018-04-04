#ifndef __NET_SCHED_CODEL_H
#define __NET_SCHED_CODEL_H

/*
 * Codel - The Controlled-Delay Active Queue Management algorithm
 *
 *  Copyright (C) 2011-2012 Kathleen Nichols <nichols@pollere.com>
 *  Copyright (C) 2011-2012 Van Jacobson <van@pollere.net>
 *  Copyright (C) 2012 Michael D. Taht <dave.taht@bufferbloat.net>
 *  Copyright (C) 2012,2015 Eric Dumazet <edumazet@google.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

//#include <linux/types.h>
//#include <linux/ktime.h>
//#include <linux/skbuff.h>
//#include <net/pkt_sched.h>
//#include <net/inet_ecn.h>

#include <rte_time.h>

/* Controlling Queue Delay (CoDel) algorithm
 * =========================================
 * Source : Kathleen Nichols and Van Jacobson
 * http://queue.acm.org/detail.cfm?id=2209336
 *
 * Implemented on linux by Dave Taht and Eric Dumazet
 */

/* Parameters used to convert the timespec values: */
/* Taken from time64.h .. but its pretty obvious */
#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL

/* CoDel uses a 1024 nsec clock, encoded in uint32_t
 * This gives a range of 2199 seconds, because of signed compares
 */
typedef uint32_t codel_time_t;
typedef int32_t codel_tdiff_t;
#define CODEL_SHIFT 10
#define MS2TIME(a) ((a * NSEC_PER_MSEC) >> CODEL_SHIFT)

static inline codel_time_t codel_get_time(void)
{
	// uint64_t ns = ktime_get_ns();
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    uint64_t ns = rte_timespec_to_ns(&ts);
	return ns >> CODEL_SHIFT;
}

/* Dealing with timer wrapping, according to RFC 1982, as desc in wikipedia:
 *  https://en.wikipedia.org/wiki/Serial_number_arithmetic#General_Solution
 * codel_time_after(a,b) returns true if the time a is after time b.
 */
#define typecheck(type,x) \
    ({  type __dummy; \
     typeof(x) __dummy2; \
     (void)(&__dummy == &__dummy2); \
     1; \
     })
#define codel_time_after(a, b)						\
	(typecheck(codel_time_t, a) &&					\
	 typecheck(codel_time_t, b) &&					\
	 ((int32_t)((a) - (b)) > 0))
#define codel_time_before(a, b) 	codel_time_after(b, a)

#define codel_time_after_eq(a, b)					\
	(typecheck(codel_time_t, a) &&					\
	 typecheck(codel_time_t, b) &&					\
	 ((int32_t)((a) - (b)) >= 0))
#define codel_time_before_eq(a, b)	codel_time_after_eq(b, a)

static inline uint32_t codel_time_to_us(codel_time_t val)
{
	uint64_t valns = ((uint64_t)val << CODEL_SHIFT);

	do_div(valns, NSEC_PER_USEC);
	return (uint32_t)valns;
}

/**
 * struct codel_params - contains codel parameters
 * @target:	target queue size (in time units)
 * @ce_threshold:  threshold for marking packets with ECN CE
 * @interval:	width of moving time window
 * @mtu:	device mtu, or minimal queue backlog in bytes.
 * @ecn:	is Explicit Congestion Notification enabled
 */
struct codel_params {
	codel_time_t	target;
	codel_time_t	ce_threshold;
	codel_time_t	interval;
	uint32_t		mtu;
	bool		ecn;
};

/**
 * struct codel_vars - contains codel variables
 * @count:		how many drops we've done since the last time we
 *			entered dropping state
 * @lastcount:		count at entry to dropping state
 * @dropping:		set to true if in dropping state
 * @rec_inv_sqrt:	reciprocal value of sqrt(count) >> 1
 * @first_above_time:	when we went (or will go) continuously above target
 *			for interval
 * @drop_next:		time to drop next packet, or when we dropped last
 * @ldelay:		sojourn time of last dequeued packet
 */
struct codel_vars {
	uint32_t		count;
	uint32_t		lastcount;
	bool		dropping;
	uint16_t		rec_inv_sqrt;
	codel_time_t	first_above_time;
	codel_time_t	drop_next;
	codel_time_t	ldelay;
};

#define REC_INV_SQRT_BITS (8 * sizeof(uint16_t)) /* or sizeof_in_bits(rec_inv_sqrt) */
/* needed shift to get a Q0.32 number from rec_inv_sqrt */
#define REC_INV_SQRT_SHIFT (32 - REC_INV_SQRT_BITS)

/**
 * struct codel_stats - contains codel shared variables and stats
 * @maxpacket:	largest packet we've seen so far
 * @drop_count:	temp count of dropped packets in dequeue()
 * @drop_len:	bytes of dropped packets in dequeue()
 * ecn_mark:	number of packets we ECN marked instead of dropping
 * ce_mark:	number of packets CE marked because sojourn time was above ce_threshold
 */
struct codel_stats {
	uint32_t		maxpacket;
	uint32_t		drop_count;
	uint32_t		drop_len;
	uint32_t		ecn_mark;
	uint32_t		ce_mark;
};

#define CODEL_DISABLED_THRESHOLD INT_MAX

typedef uint32_t (*codel_skb_len_t)(const struct sk_buff *skb);
typedef codel_time_t (*codel_skb_time_t)(const struct sk_buff *skb);
typedef void (*codel_skb_drop_t)(struct sk_buff *skb, void *ctx);
typedef struct sk_buff * (*codel_skb_dequeue_t)(struct codel_vars *vars,
						void *ctx);

#endif

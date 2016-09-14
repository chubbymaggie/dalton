#include "tcp_vegas.h"
#include "tcp_reno.h"
#include "timing.h"

#include "../state.h"
#include "../net_info_keeper.h"
#include "../batch_creator.h"

#include "../../timespec_utils.h"

#include <asm/div64.h>

#define V_PARAM_SHIFT 1

static int alpha = 2 << V_PARAM_SHIFT;
static int beta =  4 << V_PARAM_SHIFT;
static int gamma = 1 << V_PARAM_SHIFT;

/*
  Implementation of TCP-vegas for PortBunny
*/


static void vegas_enable(void *this,
			 struct scan_job_t *scan_job,
			 struct flood_state_timing_context *tcontext)
{
	struct tcp_vegas_state *vegas = this;
	struct flood_state_context *context = scan_job->state_context;
	s64 cur_cwnd_packets = tcontext->cur_cwnd;
	do_div(cur_cwnd_packets, CWND_BLOWUP_FACTOR);
	
	/* Reset vegas-parameters */	

	vegas->doing_vegas_now = 1;		
	vegas->ack_counter_at_start = context->net_info_keeper->ack_counter;
	vegas->cwnd_at_start = tcontext->cur_cwnd;	
	vegas->cntRTT = 0;		
	vegas->minRTT = VEGAS_DEFAULT_BATCH_TIMEOUT_NS;
	

}

static void vegas_on_drop(struct scan_job_t *scan_job,
			  void *this,
			  struct flood_state_timing_context *tcontext,
			  struct net_info_keeper *keeper,
			  struct sniffed_packet_descr_t *pdescr)
{
		
	//reno_on_drop(scan_job, this, tcontext, keeper, pdescr);
	
	/* Got no answer, decrease cwnd and ccthresh */		

	
	tcontext->cwnd_before_drop = tcontext->cur_cwnd;
	tcontext->ccthresh_before_drop = tcontext->cur_ccthresh;       
	
	tcontext->cur_ccthresh = (keeper->nactive_packets / 2) * CWND_BLOWUP_FACTOR;		
		
		
	//tcontext->cur_cwnd = 2 * CWND_BLOWUP_FACTOR;		
	
	if(tcontext->cur_ccthresh < 2*CWND_BLOWUP_FACTOR)
		tcontext->cur_ccthresh = 2*CWND_BLOWUP_FACTOR;			
	
	tcontext->cur_cwnd = tcontext->cur_ccthresh;
		
	vegas_enable(this, scan_job, tcontext);
}

/*
static void vegas_disable(void *this)
{
	struct tcp_vegas_state *vegas = this;
	vegas->doing_vegas_now = 0;
}
*/

static void *vegas_constructor(struct scan_job_t *scan_job,
			      struct flood_state_timing_context *tcontext)
{
	struct tcp_vegas_state *this = kmalloc(sizeof(struct tcp_vegas_state),
					       GFP_KERNEL);

	if(!this) return NULL;

	this->baseRTT = VEGAS_DEFAULT_BATCH_TIMEOUT_NS;
	
	tcontext->cur_timeout = DEFAULT_BATCH_TIMEOUT_NS;	
	tcontext->cur_batch_size = DEFAULT_BATCH_SIZE;	
	tcontext->cur_cwnd = VEGAS_INITIAL_CWND;	
	tcontext->cur_ccthresh = VEGAS_INITIAL_CCTHRESH;	
	
	vegas_enable(this, scan_job, tcontext);

	return this;

}


static void vegas_destructor(struct scan_job_t *scan_job,
			     void *this,
			     struct flood_state_timing_context *tcontext)
{
	if(this)
		kfree(this);
	
}

/* Perform rtt-sampling needed for vegas */

static void vegas_on_update_timeout(struct scan_job_t *scan_job,
				    void *this,
				    struct flood_state_timing_context *tcontext,
				    struct net_info_keeper *net_info_keeper,
				    struct timespec *time_received,
				    struct timespec *time_sent)
{
	/* calculate round-trip-time */
	struct timespec rtt;	
	s64 rtt_nsec;	
	struct tcp_vegas_state *vegas = this;


	if(timespec_compare(time_received, time_sent) < 0){		
		printk("NULL-time\n");
		return;
	}	
	
	rtt = timespec_sub( *time_received,
			    *time_sent );
	
	rtt_nsec = timespec_to_ns( &rtt );
	
	
	if(rtt_nsec < vegas->baseRTT){
		vegas->baseRTT = rtt_nsec;		
	}
	
	if(vegas->minRTT > rtt_nsec){
		vegas->minRTT = rtt_nsec;		
	}
	
	vegas->cntRTT++;
	
	reno_on_update_timeout(scan_job, NULL, tcontext, net_info_keeper, time_received, time_sent);	

}

static void vegas_on_rcv(struct scan_job_t *scan_job,
			 void *this,
			 struct flood_state_timing_context *tcontext,
			 struct packet_batch *batch)

{	
        struct flood_state_context *context = scan_job->state_context;	
	struct tcp_vegas_state *vegas = this;	
	
	
	/* We only want to adjust the cwnd once per 1/samplig-rate. */
	
	u64 nacks_received = (context->net_info_keeper->ack_counter
			      - vegas->ack_counter_at_start) * CWND_BLOWUP_FACTOR;
	
	nacks_received *= (VEGAS_DEFAULT_BATCH_SIZE + 1);

	if(!vegas->doing_vegas_now)
		return reno_on_rcv(this, NULL, tcontext, batch);	
	

	if( nacks_received  >= vegas->cwnd_at_start){
		
		s64 cur_cwnd_packets = tcontext->cur_cwnd;
		s64 target_cwnd, diff;
		s64 old_cwnd_packets = vegas->cwnd_at_start; 
		do_div(cur_cwnd_packets, CWND_BLOWUP_FACTOR);
		do_div(old_cwnd_packets, CWND_BLOWUP_FACTOR);

		
		if(vegas->cntRTT <= 2){			
			/* not enough samples yet, use reno. */
			return reno_on_rcv(scan_job, this, tcontext, batch);
		}
		
		/* minRTT is the minimum rtt measured during this
		 * epoch. Based on minRTT, we decide how to
		 * adjust the congestion-window.
		 */
		
		/* calculate actual rate and expected rate: */
		
		do_div(nacks_received, CWND_BLOWUP_FACTOR);
		target_cwnd = 
			(nacks_received * vegas->baseRTT) << V_PARAM_SHIFT;	
		do_div(target_cwnd, vegas->minRTT);
				
		
		diff = (old_cwnd_packets << V_PARAM_SHIFT) - target_cwnd;		
		
		if(tcontext->cur_cwnd < tcontext->cur_ccthresh){
			/* slow start */
			batch_creator_set_cur_batch_size(context->creator, 9);
			
			if(diff > gamma){				
				tcontext->cur_ccthresh = 2 * CWND_BLOWUP_FACTOR;
				
				if((target_cwnd >> V_PARAM_SHIFT) + 1 < cur_cwnd_packets)
					tcontext->cur_cwnd = ((target_cwnd >> V_PARAM_SHIFT) + 1) * CWND_BLOWUP_FACTOR;
			}

			return reno_on_rcv(this, NULL, tcontext, batch);
			
		}else{
			s64 next_cwnd_packets;

			/* congestion avoidance */
			if(!context->nrescanned_filtered)
				batch_creator_set_cur_batch_size(context->creator, 12);
			
			
			if(diff > beta)
				next_cwnd_packets = old_cwnd_packets - (VEGAS_DEFAULT_BATCH_SIZE + 1);
			else if(diff < alpha){				
				next_cwnd_packets = old_cwnd_packets + (VEGAS_DEFAULT_BATCH_SIZE + 1);
			}
			else
				next_cwnd_packets = old_cwnd_packets;
			
			
			if(next_cwnd_packets > cur_cwnd_packets)
				tcontext->cur_cwnd += CWND_BLOWUP_FACTOR;
			else if(next_cwnd_packets < tcontext->cur_cwnd)
				tcontext->cur_cwnd -= CWND_BLOWUP_FACTOR;
			
			if(tcontext->cur_cwnd < 2 * CWND_BLOWUP_FACTOR)
				tcontext->cur_cwnd = 2 * CWND_BLOWUP_FACTOR;
			
			
		}


		/* set next sampling-interval */	
		
		vegas->ack_counter_at_start = context->net_info_keeper->ack_counter;
		vegas->minRTT = VEGAS_DEFAULT_BATCH_TIMEOUT_NS;
		vegas->cwnd_at_start = tcontext->cur_cwnd;		
		vegas->cntRTT = 0;
		

	}

	
}


struct timing_algo tcp_vegas = {
	.on_rcv = &vegas_on_rcv,
	.on_drop = &vegas_on_drop,
	.on_update_timeout = &vegas_on_update_timeout,
	.on_late_response = &reno_on_late_response,
	.constructor = &vegas_constructor,
	.destructor = &vegas_destructor,
};

#include "tcp_reno.h"
#include "timing.h"

#include "../state.h"
#include "../net_info_keeper.h"

#include "../../timespec_utils.h"

#include <asm/div64.h>

/*
  Implementation of TCP-Reno for PortBunny
*/

static void quick_start_rcv(struct flood_state_timing_context *tcontext)
{	
	
	/* Got an answer , increase cwnd */
	/* cwnd += 1 probe */
	
	tcontext->cur_cwnd += CWND_BLOWUP_FACTOR;					
	
}

static void congestion_avoidance_rcv(struct flood_state_timing_context *tcontext)
{
				
	/* Got an answer. */
	
	/* cwnd += 1/cwnd */
				
	s64 cur_cwnd = tcontext->cur_cwnd;
	s64 cwnd_blowup = CWND_BLOWUP_FACTOR;
		
	do_div(cur_cwnd, CWND_BLOWUP_FACTOR);
	do_div(cwnd_blowup, cur_cwnd);
	
	tcontext->cur_cwnd += cwnd_blowup;
		
}


void reno_update_timeout(struct tcp_reno_state *this,
			 struct flood_state_timing_context *tcontext,
			 struct net_info_keeper *net_info_keeper)
{
	
	if(net_info_keeper->rtt_average == -1)
		tcontext->cur_timeout = DEFAULT_BATCH_TIMEOUT_NS;
				
	/* update the timeout to be 2*(average + 4 * deviation) */
  	
	tcontext->cur_timeout =  ((net_info_keeper->rtt_average >> 3)
				  + net_info_keeper->rtt_deviation );
	
}


/********************************************/

void reno_on_rcv(struct scan_job_t *scan_job,
		 void *this,
		 struct flood_state_timing_context *tcontext,
		 struct packet_batch *batch)

{	
        /* Depending on the current cwnd and threshold, determine
	 * what congestion-control-state we are in.
	 */
	
	if(tcontext->cur_cwnd < tcontext->cur_ccthresh)
		quick_start_rcv(tcontext);
	else
		congestion_avoidance_rcv(tcontext);		
		
}

void reno_on_update_timeout(struct scan_job_t *scan_job,
			    void *this,
			    struct flood_state_timing_context *tcontext,
			    struct net_info_keeper *net_info_keeper,
			    struct timespec *time_received,
			    struct timespec *time_sent)
{
	
		
	if(net_info_keeper)
		reno_update_timeout(this, tcontext, net_info_keeper);
	
	
}

void reno_on_drop(struct scan_job_t *scan_job,
		  void *unused,
		  struct flood_state_timing_context *tcontext,
		  struct net_info_keeper *keeper,
		  struct sniffed_packet_descr_t *pdescr)
{
	

	/* Got no answer, decrease cwnd and ccthresh */		
	
	tcontext->cwnd_before_drop = tcontext->cur_cwnd;
	tcontext->ccthresh_before_drop = tcontext->cur_ccthresh;       
	
	tcontext->cur_ccthresh = (keeper->nactive_packets / 2) * CWND_BLOWUP_FACTOR;		
		
	// do_div(tcontext->cur_cwnd,2);
	
	tcontext->cur_cwnd = 2 * CWND_BLOWUP_FACTOR;

	//if(tcontext->cur_cwnd < 2*CWND_BLOWUP_FACTOR)		 
	//tcontext->cur_cwnd = 2 * CWND_BLOWUP_FACTOR;
	
	if(tcontext->cur_ccthresh < 2*CWND_BLOWUP_FACTOR)
		tcontext->cur_ccthresh = 2*CWND_BLOWUP_FACTOR;				
	
}



static void *reno_constructor(struct scan_job_t *scan_job,
			      struct flood_state_timing_context *tcontext)
{
	struct tcp_reno_state *this = kmalloc(sizeof(struct tcp_reno_state),
					      GFP_KERNEL);
	
	if(!this) return NULL;

	printk("starting RENO\n");
	
	
	/* Now initialize timing-context */

	tcontext->cur_timeout = DEFAULT_BATCH_TIMEOUT_NS;	
	tcontext->cur_batch_size = DEFAULT_BATCH_SIZE;
	
	tcontext->cur_cwnd = INITIAL_CWND;	
	tcontext->cur_ccthresh = INITIAL_CCTHRESH;	

	return this;
	
}

static void reno_destructor(struct scan_job_t *scan_job, void *this,
			    struct flood_state_timing_context *tcontext)
{
	if(this)
		kfree(this);
	
}

void reno_on_late_response(struct scan_job_t *scan_job, void *unused,
			   struct flood_state_timing_context *tcontext)
{			
	
	tcontext->cur_cwnd = tcontext->cwnd_before_drop;
	tcontext->cur_ccthresh = tcontext->ccthresh_before_drop;		
	
	if(tcontext->cur_cwnd < 2 * CWND_BLOWUP_FACTOR)
		tcontext->cur_cwnd = 2 * CWND_BLOWUP_FACTOR;
	if(tcontext->cur_ccthresh < 2 * CWND_BLOWUP_FACTOR )
		tcontext->cur_ccthresh = 2 * CWND_BLOWUP_FACTOR;

}

struct timing_algo tcp_reno = {
	.on_rcv = &reno_on_rcv,
	.on_drop = &reno_on_drop,
	.on_update_timeout = &reno_on_update_timeout,
	.on_late_response = &reno_on_late_response,
	.constructor = &reno_constructor,
	.destructor = &reno_destructor,
};

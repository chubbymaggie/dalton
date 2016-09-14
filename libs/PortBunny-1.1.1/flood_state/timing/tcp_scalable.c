#include "tcp_scalable.h"
#include "timing.h"

#include "../state.h"
#include "../net_info_keeper.h"

#include "../../timespec_utils.h"

#include <asm/div64.h>

/*
  Implementation of TCP-Scalable for PortBunny
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
	
	/* cwnd = cwnd + 0.01 */
	
	/* not clean because it assumes that CWND_BLOWUP_FACTOR = 10000*/
	
	tcontext->cur_cwnd += 100 ;	
		
}


void scalable_update_timeout(struct tcp_scalable_state *this,
			 struct flood_state_timing_context *tcontext,
			 struct net_info_keeper *net_info_keeper)
{
	
	if(net_info_keeper->rtt_average == -1)
		tcontext->cur_timeout = SCALE_DEFAULT_BATCH_TIMEOUT_NS;
				
	/* update the timeout to be 2*(average + 4 * deviation) */
  	
	tcontext->cur_timeout =  ((net_info_keeper->rtt_average >> 3)
				  + net_info_keeper->rtt_deviation );
	
}


/********************************************/

void scalable_on_rcv(struct scan_job_t *scan_job,
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

void scalable_on_update_timeout(struct scan_job_t *scan_job,
			    void *this,
			    struct flood_state_timing_context *tcontext,
			    struct net_info_keeper *net_info_keeper,
			    struct timespec *time_received,
			    struct timespec *time_sent)
{
	
		
	if(net_info_keeper)
		scalable_update_timeout(this, tcontext, net_info_keeper);
	
	
}

void scalable_on_drop(struct scan_job_t *scan_job,
		  void *unused,
		  struct flood_state_timing_context *tcontext,
		  struct net_info_keeper *keeper,
		  struct sniffed_packet_descr_t *pdescr)
{
	/* Got no answer, decrease cwnd and ccthresh */		
	
	tcontext->cwnd_before_drop = tcontext->cur_cwnd;
	tcontext->ccthresh_before_drop = tcontext->cur_ccthresh;       
	
	tcontext->cur_ccthresh = (keeper->nactive_packets / 2) * CWND_BLOWUP_FACTOR;		
		
	
	
	tcontext->cur_cwnd *= 7;
	do_div(tcontext->cur_cwnd, 8);	
	
	if(tcontext->cur_cwnd < 2* CWND_BLOWUP_FACTOR)
		tcontext->cur_cwnd = 2* CWND_BLOWUP_FACTOR;

	
	if(tcontext->cur_ccthresh < 2*CWND_BLOWUP_FACTOR)
		tcontext->cur_ccthresh = 2*CWND_BLOWUP_FACTOR;				
	
}



static void *scalable_constructor(struct scan_job_t *scan_job,
			      struct flood_state_timing_context *tcontext)
{
	struct tcp_scalable_state *this = kmalloc(sizeof(struct tcp_scalable_state),
					      GFP_KERNEL);
	
	if(!this) return NULL;
	
	
	/* Now initialize timing-context */

	tcontext->cur_timeout = SCALE_DEFAULT_BATCH_TIMEOUT_NS;	
	tcontext->cur_batch_size = SCALE_DEFAULT_BATCH_SIZE;
	
	tcontext->cur_cwnd = SCALE_INITIAL_CWND;	
	tcontext->cur_ccthresh = SCALE_INITIAL_CCTHRESH;	

	return this;
	
}

static void scalable_destructor(struct scan_job_t *scan_job, void *this,
			    struct flood_state_timing_context *tcontext)
{
	if(this)
		kfree(this);
	
}

void scalable_on_late_response(struct scan_job_t *scan_job, void *unused,
			   struct flood_state_timing_context *tcontext)
{			
	
	tcontext->cur_cwnd = tcontext->cwnd_before_drop;
	tcontext->cur_ccthresh = tcontext->ccthresh_before_drop;		
	
	if(tcontext->cur_cwnd < 2 * CWND_BLOWUP_FACTOR)
		tcontext->cur_cwnd = 2 * CWND_BLOWUP_FACTOR;
	if(tcontext->cur_ccthresh < 2 * CWND_BLOWUP_FACTOR )
		tcontext->cur_ccthresh = 2 * CWND_BLOWUP_FACTOR;

}

struct timing_algo tcp_scalable = {
	.on_rcv = &scalable_on_rcv,
	.on_drop = &scalable_on_drop,
	.on_update_timeout = &scalable_on_update_timeout,
	.on_late_response = &scalable_on_late_response,
	.constructor = &scalable_constructor,
	.destructor = &scalable_destructor,
};

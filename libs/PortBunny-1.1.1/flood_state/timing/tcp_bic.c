#include "tcp_bic.h"
#include "tcp_reno.h"
#include "../net_info_keeper.h"

static s64 bic_beta;

static void output_bic_state(struct tcp_bic_state *bic,
			     struct flood_state_timing_context *tcontext)
{
	printk("=================\n");
	
	printk("last_max_cwnd: %lld\n", bic->last_max_cwnd);
	printk("max_cwnd: %lld\n", bic->max_cwnd);
	printk("min_cwnd: %lld\n", bic->min_cwnd);
	printk("target_cwnd: %lld\n", bic->target_cwnd);
	printk("ss_cwnd: %lld\n", bic->ss_cwnd);
	printk("ss_target: %lld\n", bic->ss_target);	

	printk("cur_cwnd: %lld\n", tcontext->cur_cwnd);

	printk("=================\n");
}

static void bic_enable(void *this,
			 struct scan_job_t *scan_job,
			 struct flood_state_timing_context *tcontext)
{	
	
}

static void bic_on_drop(struct scan_job_t *scan_job,
			  void *this,
			  struct flood_state_timing_context *tcontext,
			  struct net_info_keeper *keeper,
			  struct sniffed_packet_descr_t *pdescr)
{	
	struct tcp_bic_state *bic = this;
	
	
	printk("BIC on-drop\n");
	
	if(BIC_LOW_WINDOW <= tcontext->cur_cwnd){
		
		printk("cwnd bigger than/equal to LOW_WINDOW.\n");
		
		/* save last maximum cwnd and set 
		 * maximum cwnd to current cwnd */
		
		bic->last_max_cwnd = bic->max_cwnd;
		bic->max_cwnd = tcontext->cur_cwnd;
		
		/* save information for late-response-handling */

		tcontext->cwnd_before_drop = tcontext->cur_cwnd;
		tcontext->ccthresh_before_drop = tcontext->cur_ccthresh;
		
		tcontext->cur_cwnd *= (CWND_BLOWUP_FACTOR - bic_beta); 
		do_div(tcontext->cur_cwnd, CWND_BLOWUP_FACTOR);
		
		
		bic->min_cwnd = tcontext->cur_cwnd;
		
		if(bic->last_max_cwnd > bic->max_cwnd){
			/* fast convergence */
			bic->max_cwnd = (bic->max_cwnd + bic->min_cwnd);
			do_div(bic->max_cwnd, 2);			
		}
		
		bic->target_cwnd = bic->max_cwnd + bic->min_cwnd;
		do_div(bic->target_cwnd, 2);		

	}else{
		
		/* Got no answer, decrease cwnd */		
		
		printk("cwnd smaller than LOW_WINDOW\n");

		tcontext->cwnd_before_drop = tcontext->cur_cwnd;
		tcontext->ccthresh_before_drop = tcontext->cur_ccthresh;
		tcontext->cur_cwnd = 2 * CWND_BLOWUP_FACTOR;				
		
	}


	if(tcontext->cur_cwnd > bic->max_cwnd){
		printk("caught bug in on-drop\n");
		tcontext->cur_cwnd = bic->max_cwnd;
	}
		

	//output_bic_state(this, tcontext);
	
	
}

static void *bic_constructor(struct scan_job_t *scan_job,
			     struct flood_state_timing_context *tcontext)
{
	struct tcp_bic_state *this = kmalloc(sizeof(struct tcp_bic_state),
					       GFP_KERNEL);
	
	if(!this) return NULL;

	/* initialization */
	
	bic_beta = (819 * CWND_BLOWUP_FACTOR);
	do_div(bic_beta, 1024);

	memset(this, 0, sizeof(struct tcp_bic_state));
	
	this->max_cwnd = BIC_DEFAULT_MAX_WIN;
	this->last_max_cwnd = this->max_cwnd;
	this->min_cwnd = 2 * CWND_BLOWUP_FACTOR; 
	this->target_cwnd = this->max_cwnd + this->min_cwnd ;
	do_div(this->target_cwnd, 2);
	
	bic_enable(this, scan_job, tcontext);	
	printk("TCP-BIC started\n");
	
	//output_bic_state(this, tcontext);

	return this;

}


static void bic_destructor(struct scan_job_t *scan_job,
			     void *this,
			     struct flood_state_timing_context *tcontext)
{
	if(this)
		kfree(this);
	
}

static void bic_on_update_timeout(struct scan_job_t *scan_job,
				    void *this,
				    struct flood_state_timing_context *tcontext,
				    struct net_info_keeper *net_info_keeper,
				    struct timespec *time_received,
				    struct timespec *time_sent)
{
	
	if(net_info_keeper)
		reno_update_timeout(this, tcontext, net_info_keeper);
	
}

static void bic_on_rcv(struct scan_job_t *scan_job,
			 void *this,
			 struct flood_state_timing_context *tcontext,
			 struct packet_batch *batch)
{
	
	struct tcp_bic_state *bic = this;
	
	//output_bic_state(this, tcontext);

	
	if(BIC_LOW_WINDOW > tcontext->cur_cwnd){
		
		/* do normal reno if BIC_LOW_WINDOW has not been reached */
		
		s64 cur_cwnd = tcontext->cur_cwnd;
		s64 cwnd_blowup = CWND_BLOWUP_FACTOR;
		
		printk("reno...\n");

		do_div(cur_cwnd, CWND_BLOWUP_FACTOR);
		do_div(cwnd_blowup, cur_cwnd);
		
		tcontext->cur_cwnd += cwnd_blowup;
		return;
	}

	/* actual BIC-code starts here */
	
	
	if(!bic->bic_slow_start){				
		printk("BIC congestion-avoidance\n");		
				
				

		if(bic->target_cwnd  - tcontext->cur_cwnd < BIC_SMAX){
			
			printk("t - c = %lld - %lld\n", bic->target_cwnd, tcontext->cur_cwnd);
			
			s64 add = bic->target_cwnd - tcontext->cur_cwnd;
			do_div(add, tcontext->cur_cwnd);			
			tcontext->cur_cwnd += add;						
		
		}else{
			
			s64 cur_cwnd = tcontext->cur_cwnd;
			s64 cwnd_blowup = CWND_BLOWUP_FACTOR;			
			s64 bic_smax = BIC_SMAX;
			
			do_div(cur_cwnd, CWND_BLOWUP_FACTOR);
			do_div(bic_smax, CWND_BLOWUP_FACTOR);			
			do_div(cwnd_blowup, cur_cwnd);						

			tcontext->cur_cwnd += bic_smax * cwnd_blowup;						
			
		}
				
		if(bic->max_cwnd > tcontext->cur_cwnd){
			bic->min_cwnd = tcontext->cur_cwnd;
			
			printk("(max+min)/2: %lld, %lld\n", bic->max_cwnd, bic->min_cwnd);
			bic->target_cwnd = (bic->max_cwnd + bic->min_cwnd);
			do_div(bic->target_cwnd, 2 );			
		}else{
			printk("next round will be slow-start\n");
			bic->bic_slow_start = TRUE;
			bic->ss_cwnd = 2*CWND_BLOWUP_FACTOR;
			bic->ss_target = tcontext->cur_cwnd + CWND_BLOWUP_FACTOR;
			bic->max_cwnd = BIC_DEFAULT_MAX_WIN;
		}				
	}else{
		s64 add = bic->ss_cwnd;
		s64 cur_cwnd = tcontext->cur_cwnd;
		do_div(cur_cwnd, CWND_BLOWUP_FACTOR);
		printk("BIC slow-start\n");
		
		do_div(add, cur_cwnd);			
		tcontext->cur_cwnd += add;		
		
		if(tcontext->cur_cwnd >= bic->ss_target){
			bic->ss_cwnd *= 2;
			bic->ss_target = tcontext->cur_cwnd + bic->ss_cwnd;
		}
		
		if(bic->ss_cwnd >= BIC_SMAX)
			bic->bic_slow_start = FALSE;
		
	}
	
	
	if(tcontext->cur_cwnd < 2 * CWND_BLOWUP_FACTOR){
		tcontext->cur_cwnd = 2 * CWND_BLOWUP_FACTOR;
		printk("hit\n");
	}



	if(tcontext->cur_cwnd > bic->max_cwnd){
		printk("caught bug in on-drop\n");
		tcontext->cur_cwnd = bic->max_cwnd;
	}

	//output_bic_state(this, tcontext);

	
}

void bic_on_late_response(struct scan_job_t *scan_job, void *unused,
			   struct flood_state_timing_context *tcontext)
{			
	
}

struct timing_algo tcp_bic = {
	.on_rcv = &bic_on_rcv,
	.on_drop = &bic_on_drop,
	.on_update_timeout = &bic_on_update_timeout,
	.on_late_response = &bic_on_late_response,
	.constructor = &bic_constructor,
	.destructor = &bic_destructor,
};

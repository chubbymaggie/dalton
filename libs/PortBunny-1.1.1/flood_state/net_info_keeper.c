
#include "net_info_keeper.h"
#include "../timespec_utils.h"

void net_info_keeper_update_rtt(struct net_info_keeper *this,
				struct timespec *rtt_sample)
{

	const unsigned int AVERAGE_GAIN_RECIPROCAL = 3;
	const unsigned int DEVIATION_GAIN_RECIPROCAL = 2;	
	
	s64 rtt_nsec = 0;
	s64 rtt_error;	
	
	struct s64_sample_t *new_rtt_sample;
	struct s64_sample_t *new_cwnd_sample;

	rtt_nsec = timespec_to_ns( rtt_sample );	
	
	/*
	  rtts bigger than 10 seconds are usually caused by SYN-ACK resends
	  from the target and aren't rtts but rather the rtt + the
	  amount of time the target chose to wait until it resends the
	  SYN-ACK.
	 
	  We want to ignore these responses for timeout-calculation.
 
	 */

	if(rtt_sample->tv_sec >= 10){
		printk("rtt bigger than 10 seconds encountered, discarding\n");
		return;
	}
	
	/* update latest rtt sample*/
			
	this->latest_rtt_sample = rtt_nsec;

	/* calculate new average round-trip-time ('rtt') */
	
	if(this->rtt_average == -1)
		this->rtt_average = 0;
	
	/* Update global maximum and minimum */

	if(this->rtt_max == -1 || rtt_nsec > this->rtt_max)				
		this->rtt_max = rtt_nsec;
	if(this->rtt_min == -1 || rtt_nsec < this->rtt_min){
		this->rtt_min = rtt_nsec;		
	}

	
	rtt_error = rtt_nsec - (this->rtt_average >> AVERAGE_GAIN_RECIPROCAL);					
	this->rtt_average += rtt_error;
	
	/* calculate new trigger-deviation */
	
	if(rtt_error < 0)
		rtt_error = -rtt_error;
	
	rtt_error -= (this->rtt_deviation >> DEVIATION_GAIN_RECIPROCAL);
	this->rtt_deviation += rtt_error;	
		       	
	/* create rtt-sample */

	
	new_rtt_sample =
		create_s64_sample(rtt_nsec);
	
	if(!new_rtt_sample)
		return;
	
	
	/* save rtt- and cwnd- samples */
	
	queue_add_limited(this->rtt_samples, new_rtt_sample,
			  (delete_data_func) del_s64_sample, NRTT_SAMPLES);
	
	new_cwnd_sample  = create_s64_sample(this->nactive_packets);
	
	if(!new_cwnd_sample)
		return;
	
	queue_add_limited(this->cwnd_samples, new_cwnd_sample,
			  (delete_data_func) del_s64_sample, NCWND_SAMPLES);		
	
	

}


struct net_info_keeper *create_net_info_keeper(void)
{
	struct net_info_keeper *this = 
		kmalloc(sizeof(struct net_info_keeper), GFP_KERNEL);

	if(!this)
		return NULL;
	
	memset(this, 0, sizeof(struct net_info_keeper));
	
	this->rtt_average = -1;
	this->rtt_max = 0;
	this->rtt_min = -1;
	
	this->drop_score_queue = create_queue(NULL, GFP_KERNEL, FALSE);
	this->rtt_samples = create_queue(NULL, GFP_KERNEL, FALSE);
	this->cwnd_samples = create_queue(NULL, GFP_KERNEL, FALSE);
	
	if(!this->drop_score_queue || !this->rtt_samples || !this->cwnd_samples){
		kfree(this);
		return NULL;
	}
	
	
	return this;
}

void delete_net_info_keeper(struct net_info_keeper *this)
{
	
	if(this->drop_score_queue)
		delete_queue(this->drop_score_queue, (delete_data_func) del_drop_score);
	
	if(this->rtt_samples)
		delete_queue(this->rtt_samples, (delete_data_func) del_s64_sample);
	
	if(this->cwnd_samples)
		delete_queue(this->cwnd_samples, (delete_data_func) del_s64_sample);	
	
	kfree(this);

}

void net_info_keeper_on_probe_rcv(struct net_info_keeper *this,
				  struct packet_batch *batch,
				  struct sniffed_packet_descr_t *pdescr)
{
	
}

void net_info_keeper_on_sent(struct net_info_keeper *this,
			     struct packet_batch *batch)
{
	/* update the number of active packets */			
	
	this->nactive_packets += (batch->size_of_batch + 1);

	/* update the number of packets sent */
	
	this->sent_counter += (batch->size_of_batch + 1);

}


void net_info_keeper_on_trigger_rcv(struct net_info_keeper *this,
				    struct packet_batch *batch)
{
			
	this->nactive_packets -= (batch->size_of_batch + 1);	
	this->ack_counter += (batch->size_of_batch + 1);		
	
}

void net_info_keeper_on_timeout(struct net_info_keeper *this,
				struct packet_batch *batch)
{		
	s64 score;
	struct drop_score_t *new_score;
	
	struct queue_node_t *root;
	struct list_head *p;
	struct queue_node_t *entry;
	boolean is_rate_limiter = TRUE;
	u32 q_len = queue_length(this->drop_score_queue);

	this->nactive_packets -= (batch->size_of_batch + 1);
		
	
	/* a drop has occured. Calculate the current drop-score
	 * and save it in the list of drop-score samples */	

	/* 1. approach for drop-score calculation */

	
	score = this->rtt_average - this->rtt_min;
	if(this->rtt_min != 0)
		do_div(score, this->rtt_min);
			
	new_score = create_drop_score((u32) score);	

	if(!new_score)
		return;
	
	/* if queue has maximum length, we will have to discard
	 * and element
	 */
	
	if(q_len == NDROP_SCORE_SAMPLES)
		this->nsamples_discarded++;
	
	queue_add_limited(this->drop_score_queue, new_score,
			  (delete_data_func) del_drop_score, NDROP_SCORE_SAMPLES);		
		
	root = get_root(this->drop_score_queue);
	

	/* if drop-score is beneath 2 for all drop-scores in the list,
	 * decide that this is a rate-limiter.
	 */

	list_for_each(p, &root->list){
		struct drop_score_t *elem;
		entry = list_entry(p, struct queue_node_t, list);		
		elem = entry->data;
		
		if(elem->score >= 2){
			is_rate_limiter = FALSE;
			break;
		}		
	}
	
	/* Only report a rate-limiter if we have had more than 20 samples */
	
	if(is_rate_limiter && this->nsamples_discarded > 20)
		this->is_rate_limiter = TRUE;
	
	
	/* reset rtt_min/rtt_max*/

	this->rtt_min = this->rtt_average;
	this->rtt_max = this->rtt_average;

	/* delete all rtt- and cwnd-samples */	

	queue_clear(this->rtt_samples, (delete_data_func) del_s64_sample);
	queue_clear(this->cwnd_samples, (delete_data_func) del_s64_sample);
	
}


struct drop_score_t *create_drop_score(u32 score)
{
	struct drop_score_t *this = kmalloc(sizeof(struct drop_score_t), GFP_KERNEL);

	if(!this) return NULL;

	this->score = score;
	
	return this;	
	
}

void del_drop_score(struct drop_score_t *this)
{
	if(!this)
		return;
		
	kfree(this);	

}


struct s64_sample_t *create_s64_sample(s64 rtt_sample)
{
	struct s64_sample_t *this = kmalloc(sizeof(struct s64_sample_t), GFP_KERNEL);
	
	if(!this) return NULL;

	this->sample = rtt_sample;

	return this;	
	
}

void del_s64_sample(struct s64_sample_t *this)
{
	if(!this)
		return;
	
	kfree(this);	

}

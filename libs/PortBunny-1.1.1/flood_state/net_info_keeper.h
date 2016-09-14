#ifndef _NET_INFO_KEEPER_H
#define _NET_INFO_KEEPER_H

#include "packet_batch.h"


#define NDROP_SCORE_SAMPLES 6
#define NRTT_SAMPLES       20
#define NCWND_SAMPLES      NRTT_SAMPLES

/** \addtogroup NetInfoKeeper
    
    Keeps information about the network's
    performance based on all events handed
    to it by the scan-job-manager.
    
    This information will then be processed
    by the timing-algorithm to change
    the timing-context which is the set of 
    timing-rules used to perform the scan.
    
    @{    
 */


/**
   net_info_keeper instance.
*/

struct net_info_keeper{
	
	/* average and deviation estimators 
	 * calculated from all data collected
	 */
	
	s64 rtt_average;
	s64 rtt_deviation;
	
	/* maximum rtt for this epoch */
	s64 rtt_max;
	
	/* minimum rtt for this epoch */
	s64 rtt_min;
	
	
	u32 nactive_packets;	
	
	s64 latest_rtt_sample;

	/**
	   RTT-drop-scores are quantities calculated
	   from the current average RTT and the minimum
	   RTT observed. The higher the drop-score, the
	   higher the rtt-gain was when the drop occured.
	*/
	
	struct queue_t *drop_score_queue;
	u32 nsamples_discarded;
	
	boolean is_rate_limiter;	
	
	struct queue_t *rtt_samples;
	struct queue_t *cwnd_samples;


	/** contains the number of packets sent */
	u64 sent_counter;	
	/** contains the number of packets acknowledged */
	u64 ack_counter;

};

struct drop_score_t{
	u32 score;
};

struct s64_sample_t{
	s64 sample;	
};


struct drop_score_t *create_drop_score(u32 score);
void del_drop_score(struct drop_score_t *this);

struct s64_sample_t *create_s64_sample(s64 sample);
void del_s64_sample(struct s64_sample_t *this);


struct net_info_keeper *create_net_info_keeper(void);
void delete_net_info_keeper(struct net_info_keeper *this);

void net_info_keeper_on_probe_rcv(struct net_info_keeper *this,
				  struct packet_batch *batch,
				  struct sniffed_packet_descr_t *pdescr);

void net_info_keeper_on_sent(struct net_info_keeper *this,
			     struct packet_batch *batch);

void net_info_keeper_on_trigger_rcv(struct net_info_keeper *this,
				    struct packet_batch *batch);

void net_info_keeper_on_timeout(struct net_info_keeper *this,
				struct packet_batch *batch);

void net_info_keeper_update_rtt(struct net_info_keeper *this,
				struct timespec *rtt_sample);


/**
   @{    
*/
	
#endif

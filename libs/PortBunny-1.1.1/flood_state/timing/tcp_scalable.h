#ifndef _PBUNNY_TCP_SCALABLE_H_
#define _PBUNNY_TCP_SCALABLE_H_

#include "timing.h"


#define SCALE_CWND_QUICK_START_INC                1

#define SCALE_INITIAL_CWND                        (2 * CWND_BLOWUP_FACTOR)
#define SCALE_INITIAL_CCTHRESH                    (60 * CWND_BLOWUP_FACTOR)


#define SCALE_DEFAULT_BATCH_TIMEOUT_NS    1000000000 /* 1s */
#define SCALE_DEFAULT_BATCH_SIZE                   9

struct tcp_scalable_state
{
	int unused;
};

void scalable_on_rcv(struct scan_job_t *scan_job,
		 void *this,
		 struct flood_state_timing_context *tcontext,
		 struct packet_batch *batch);

void scalable_on_drop(struct scan_job_t *scan_job,
		  void *unused,
		  struct flood_state_timing_context *tcontext,
		  struct net_info_keeper *keeper,
		  struct sniffed_packet_descr_t *pdescr);

void scalable_on_late_response(struct scan_job_t *scan_job, void *unused,
			   struct flood_state_timing_context *tcontext);


void scalable_update_timeout(struct tcp_scalable_state *this,
			 struct flood_state_timing_context *tcontext,
			 struct net_info_keeper *net_info_keeper);

void scalable_on_update_timeout(struct scan_job_t *scan_job,
			    void *this,
			    struct flood_state_timing_context *tcontext,
			    struct net_info_keeper *net_info_keeper,
			    struct timespec *time_received,
			    struct timespec *time_sent);

extern struct timing_algo tcp_scalable;

#endif

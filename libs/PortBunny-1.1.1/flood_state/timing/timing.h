#ifndef _PBUNNY_TIMING_H_
#define _PBUNNY_TIMING_H_

#include "../state.h"

/**
  A timing-algorithm must provide an event-handler called on
  packet-reciept and one to be called on packet-drops.
  
  The timing-algorithm's job is to update:

  - cwnd/ccthresh
  - timeout-value

  which it can access via the flood_state_context passed each
  of the two event-handlers.

  The timing-algorithm may save its per-scan-job state within
  the scan-job's context.
  
  
*/



typedef void (*on_rcv_func_t)(struct scan_job_t *scan_job,
			      void *timing_algo_state,
			      struct flood_state_timing_context *tcontext,
			      struct packet_batch *batch);

typedef void (*on_update_timeout_func_t)(struct scan_job_t *scan_job,
					 void *timing_algo_state,
					 struct flood_state_timing_context *tcontext,
					 struct net_info_keeper *net_info_keeper,
					 struct timespec *time_received,
					 struct timespec *time_sent);


typedef void (*on_drop_func_t)(struct scan_job_t *scan_job,
			       void *timing_algo_state,
			       struct flood_state_timing_context *tcontext,
			       struct net_info_keeper *keeper,
			       struct sniffed_packet_descr_t *pdescr);

typedef void (*on_late_response_func_t)(struct scan_job_t *scan_job,
					void *timing_algo_state,
					struct flood_state_timing_context *tcontext);

typedef void *(*constructor_t) (struct scan_job_t *scan_job,
				struct flood_state_timing_context *tcontext);

typedef void (*destructor_t) (struct scan_job_t *scan_job,
			      void *timing_algo_state,
			      struct flood_state_timing_context *tcontext);


struct timing_algo{
	
	
	on_rcv_func_t       on_rcv;
	on_drop_func_t      on_drop;
	on_update_timeout_func_t on_update_timeout;
	on_late_response_func_t on_late_response;

	constructor_t       constructor;
	destructor_t        destructor;

	
};

#define TIMING_ALGO_TCP_RENO           0 
#define	TIMING_ALGO_TCP_SCALABLE       1
#define TIMING_ALGO_TCP_VEGAS          2
//#define TIMING_ALGO_TCP_BIC            3
#define N_TIMING_ALGOS                 3



/**
   Array of available timing-algorithms.   
*/

extern struct timing_algo *timing_algorithms[];

#endif

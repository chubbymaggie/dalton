#ifndef _FLOOD_STATE_H_
#define _FLOOD_STATE_H_

#include "packet_batch.h"
#include "port_result.h"
#include "../trigger_state/trigger_finding_methods.h"
#include "../scanner_module.h"
#include "../queue.h"


#define ADD_TRIGGERS_AT_RUNTIME 1

/**
   TODO: This isn't too nice: We should define a number
   of bits to shift instead of a number to multiply
   with.
*/

#define CWND_BLOWUP_FACTOR               10000


/** \addtogroup FloodStateScanJobManager
    
    Flood-state logic - I suggest to start off by reading the
    ScanJobManagerFunction \ref flood_state_scan_job_manager
    and the \ref flood_state_context to get a general overview.
    
@{ 
*/


#define NRESCANS_OF_FILTERED_PORTS           2

#define NDEFAULT_PORTS_TO_SCAN            1024
#define NUM_OLD_BATCHES_TO_STORE           100
#define SRC_PORT                         61373

struct flood_state_timing_context{
	
	/** number of probes in a single batch
	 * not counting the trigger
	 */
	
	u8 cur_batch_size;
	
	s64 cur_timeout;
	/** congestion window */   
	s64 cur_cwnd;            
	
	/** copies of cwnd and ccthresh
	 *  before the last drop are kept
	 * to restore them if late
	 * responses are encountered. 
	 */
	
	s64 cwnd_before_drop;
	s64 ccthresh_before_drop;

	/** cong. control threshold */	
	s64 cur_ccthresh;
  
	boolean no_responses_since_drop;
		
};


/**
        flood_state_context-structure
		
	Holds the context of
	a flood-state-scan-job.
	This includes the configuration
	of the scan-job such as the
	ports to scan as well as state-descriptive
	values such as the trigger which
	was used for the last packet-batch sent
	by this scan-job.
	
*/


struct flood_state_context{
	
        /******************************************
	 *        Configuration                   *
	 * (not changed once the job is executed) *
	 ******************************************/
		
	u32 port_array_size;
	        

	/** array big enough so that ports_to_scan[BIGGEST_PORT]
	 * is part of the array. While this may mean, that there
	 * are some unused fields in the array, it allows us
	 * O(1) on lookups which has proven to be quite important.
	 */
	
	struct port_result **ports_to_scan;
	

	/* variables used to keep track of 
	 * scanning progress */
  

	/** note that nports_to_scan may be smaller
	 * than the port_array_size.
	 */
	u32 nports_to_scan;
	
	/** number of ports we have already scanned. */
	
	u32 nports_scanned;
	
	struct flood_state_timing_context timing_context;		
		
	/* Lists used for batch-management */
  
	struct queue_t *active_batches;
	struct queue_t *recent_batches;
	

	struct batch_creator *creator;
	
	boolean started;
	
	/** Number of rescan-rounds of filtered ports which have been performed */
	u8 nrescanned_filtered;
	
	/** whether to report events or not */
	boolean report_events;
	
	/* last sequence-number acked. */

	u32 max_batch_seq_received;		
	/* contains the last sequence-number sent */	
	u32 batch_seq_num;

	

	void *timing_algo_state;
	struct timing_algo *timing_alg;

	struct net_info_keeper *net_info_keeper;
	
	struct trigger_manager_t *trig_man;
	
	
};

/*
  Export the state.
*/

extern struct scan_job_state_t flood_state;

/** @} */


#endif

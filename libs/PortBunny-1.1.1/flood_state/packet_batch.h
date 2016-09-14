#ifndef _PACKET_BATCH_LIST_H
#define _PACKET_BATCH_LIST_H

#include "../scan_jobs.h"
#include "../trigger_state/trigger_finding_methods.h"

#include "port_result.h"
#include "state.h"

#include <linux/time.h>
#include <linux/list.h>

/**
    \addtogroup PacketBatch            
    
    A PacketBatch consists of
    a number of probes and a trigger.
    
    Probes are grouped in PacketBatches
    to associate them with a trigger.
    
    @{ 
    
*/

/**
  The \ref FloodStateScanJobManagerFunction
  sends packets in PacketBatches.
  A batch consists of a subset of
  packets of the ports_to_scan-array.
  
*/

struct packet_batch{
	
	/** TODO: rename this to "ports" */
	__u16 *port_indices;
	
	unsigned int size_of_batch; /** number of probes (without the trigger )*/
			
	/**
	   Reference to the scan-job's
	   ports_to_scan-array.
	*/

	struct port_result **ports_to_scan;
		
	/** the trigger which was used */
	struct trigger_instance *trigger;
	
	/* results */
	
	struct timespec time_sent;
        struct timespec timeout_time;
	struct timespec *trigger_rcv_time;		

	u64 seq_num;	

	boolean inactive;
	
};

struct flood_state_packet_descr_t;
struct flood_state_context;


/** @name Functions which operate on batch-lists:
    @{
*/


boolean batch_handles_port(struct packet_batch *this, int port_index);

struct packet_batch *get_active_batch_by_port_index(struct flood_state_context *context,
						   int port);


/** @} */

/** @name Functions which operate on a single batch
 @{
*/

struct packet_batch *create_packet_batch(__u16 *ports,
					 unsigned int nports,
					 struct trigger_instance *trigger);

void delete_packet_batch(struct packet_batch *this);

void send_packet_batch(struct packet_batch *this,
		       struct scan_job_t *job);

void batch_output_filtered_ports(struct packet_batch *this,
				 struct scan_job_t *job);

void batch_mark_unknown_as_filtered(struct packet_batch *this,
				    struct scan_job_t *job);


boolean batch_timed_out(struct packet_batch *this,			
			struct flood_state_context *context,
			struct timespec *cur_time);


int compare_batches(void *a, void *b);


/** @} */
/** @} */

#endif


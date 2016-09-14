#ifndef _BATCH_CREATOR_H
#define _BATCH_CREATOR_H

#include "packet_batch.h"
#include "port_result.h"
#include "trigger_manager.h"
#include "../queue.h"
#include "../trigger_state/trigger_finding_methods.h"

/** \addtogroup BatchCreator

    A BatchCreator is used by the FloodStateScanJobManager-
    Function to create \ref PacketBatch es.

    A BatchCreator is initialized with a port_result-array
    which contains all ports which are to be scanned. It
    then keeps these ports in a queue to know which ports
    still need to be scanned.  

@{
*/

struct batch_creator{
	
	/** queue holding all ports which still need 
	 * to be scanned.*/
	struct queue_t *port_results;	
	
	/** pointer to ports_to_scan-array of scan-job */
	struct port_result **ports_to_scan;
	
	/** number of probes in batch (not counting the trigger) */
	
	u32 cur_batch_size;	
		
	struct trigger_manager_t *trig_man;

	/* contains the last sequence-number sent */
	
	u32 *batch_seq_num;

};


/**
   create_batch_creator
   
   Creates a batch-creator from a port-array
*/

struct batch_creator *create_batch_creator(struct port_result **port_result,
					   unsigned int port_array_size,
					   struct trigger_manager_t *trig_man,
					   u32 *batch_seq_num);


/**
   create a new batch
   
   Returns NULL if no more batches can be created.
   
*/

struct packet_batch *batch_creator_create_batch(struct batch_creator *this);


/**
   Sets the number of probes in a batch (not counting the trigger).
*/

void batch_creator_set_cur_batch_size(struct batch_creator *this,
				      u32 size);

/**
   Reinserts all ports of the batch which do NOT have a
   registered port_result into the queue of ports which
   still need scanning.
*/

void batch_creator_reinsert_ports_of_batch(struct batch_creator *this,
					   struct packet_batch *batch);


void batch_creator_add_port(struct batch_creator *this, struct port_result *presult);


/* Destructor */

void delete_batch_creator(struct batch_creator *this);

/** @} */



#endif

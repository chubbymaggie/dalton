#include "state.h"
#include "packet_batch.h"

#include "../scanner_ui/scanner_output_queue.h"
#include "../packet_submitter.h"
#include "../scan_jobs.h"
#include "../scanner_module.h"
#include "../timespec_utils.h"

#include "../trigger_state/tcp_syn_method.h"

#include <linux/module.h>
#include <asm/div64.h>

/**
    \addtogroup PacketBatch
    @{
*/



/**
  Constructor
    
*/

struct packet_batch *create_packet_batch(__be16 *ports,
					 unsigned int nports,
					 struct trigger_instance *ntrigger)
{	
	struct packet_batch *new_batch;

	/* Do not allow the creation of a null-batch */
	
	if(nports == 0 || !ports)
		return NULL;

	/* allocate and initialize batch */

	new_batch = kmalloc(sizeof(struct packet_batch), GFP_KERNEL);	
	if(!new_batch)
		return NULL;	
	
	memset(new_batch, 0, sizeof(struct packet_batch));
	
		
	new_batch->port_indices = kmalloc(sizeof(__u16) * nports, GFP_KERNEL);
		

	if(!new_batch->port_indices){
		kfree(new_batch);
		return NULL;
	}
	
	memcpy(new_batch->port_indices, ports, sizeof(__u16) * nports);
			
	new_batch->size_of_batch = nports;		
	new_batch->trigger = ntrigger;       		
	
	return new_batch;

}


/**
   Destructor
   
*/

void delete_packet_batch(struct packet_batch *this)
{
	
	if(!this)
		return;
	

	if(this->port_indices){
		
		/* make sure to deregister all pointers
		 * from port_results to this batch */
		
		int t;
		for(t = 0; t < this->size_of_batch; t++){
			struct port_result *presult = 
				this->ports_to_scan[this->port_indices[t]];
		
			if(presult->port_is_in_batch == this)
				presult->port_is_in_batch = NULL;
		
		}									
		
		kfree(this->port_indices);
	
	}
	
	

	if(this->trigger_rcv_time)
		kfree(this->trigger_rcv_time);
	
	del_trigger_instance(this->trigger);
	kfree(this);
}

/**
  Returns true if scanning 'port' was
  part of this packet-batch.

  Else, returns false

*/

boolean batch_handles_port(struct packet_batch *this, int port_index)
{
	int t;
	for(t = 0; t < this->size_of_batch; t++)
		if(this->port_indices[t] == port_index)
			return TRUE;
       

	return FALSE;
}


/**
  Returns a pointer to the active batch which
  handles a given port or NULL if no such batch
  exists.
*/

struct packet_batch *get_active_batch_by_port_index(struct flood_state_context *context,
						    int port_index)
{		
	if(context->ports_to_scan[port_index])
		return context->ports_to_scan[port_index]->port_is_in_batch;
 
	return NULL;
 
}


/*
  Send the packet-batch AND set timeout-time.
*/

void send_packet_batch(struct packet_batch *this,
		       struct scan_job_t *job)
{	
		
	struct trigger_finding_method *trig_method;	
        struct flood_state_context *context = job->state_context;
	int t;
		
	/* Iterate through all ports of this batch and
	 * send packets */
	
	
	for(t = 0; t < this->size_of_batch; t++)	  				
		send_tcp_syn_packet(job->addr, this->port_indices[t],
				    SRC_PORT, 0xffffffff);				
			
	trig_method = trigger_finding_methods[this->trigger->method_id];
	/* register batch_id with trigger */

	if(trig_method->register_batch_id)
		trig_method->register_batch_id(this->trigger, this->port_indices[0]);
	
	/* now append the trigger */
	
	getnstimeofday(&this->time_sent);	
	trig_method->sender_func(job, this->trigger);		
	
	/* set timeout-time */

	this->timeout_time = this->time_sent;	
	timespec_add_ns(&this->timeout_time,
			context->timing_context.cur_timeout);		
}


/**
   Output results of packet-batch in the form specified
   in the architecture-paper.
*/

void batch_output_filtered_ports(struct packet_batch *batch,
				 struct scan_job_t *job)
{
	struct flood_state_context *context = job->state_context;	
	int t;
	
				
	for(t = 0; t < batch->size_of_batch; t++){
						
		if(!context->ports_to_scan[batch->port_indices[t]]->exists)
			continue;
				
		if((context->ports_to_scan[batch->port_indices[t]]->state == FILTERED))
			/* Output filtered port */			
			output_port_result(context->ports_to_scan[batch->port_indices[t]],
					   job->addr_str);	
	}
		
}


void batch_mark_unknown_as_filtered(struct packet_batch *this,
				    struct scan_job_t *job)
{
	struct flood_state_context *context =
		job->state_context;
	
	int t;

	for( t = 0; t < this->size_of_batch; t++){
		
		/* absurdity check */
		
		if(! context->ports_to_scan[ this->port_indices[t] ] ){
			scanner_output_queue_add("ERROR -1 Almost dereferenced a NULL-ptr");
			scanner_output_queue_add("in batch_mark_unkown_as_filtered\n");
			scanner_output_queue_flush();
			return;
		}

		if(! (context->ports_to_scan[this->port_indices[t]]->exists )){
			context->nports_scanned++;
			context->ports_to_scan[this->port_indices[t]]->exists = 1;
			context->ports_to_scan[this->port_indices[t]]->state = FILTERED;
			
			
		}
	}
}


/**

   Return TRUE if the batch has timed-out,
   FALSE otherwise.
   
*/

boolean batch_timed_out(struct packet_batch *this,			
			struct flood_state_context *context,
			struct timespec *cur_time)
{	
	boolean timed_out = FALSE;	
			
	timed_out = (timespec_compare(&this->timeout_time, cur_time) <= 0);
	
	
	if(timed_out){
		/* Hit Clock */
		//printk("Hit clock\n");
		return TRUE;
	}
	
	
	/* check if any batch has not received its trigger-response
	   and has a sequence-number smaller than 
	   the biggest sequence_number received
	 */

	
	if ((!this->trigger_rcv_time) &&
	    ( this->seq_num + 3 < context->max_batch_seq_received)){
		printk("fast-retransmit\n");
		return TRUE;
	}
	
	return FALSE;
	
}

/**
  
   Comparision-function used by queue_add_ordered
   to allow ordered insertion into the
   active_batches list. Batches are sorted by
   timeout-time.
   
*/

int compare_batches(void *a, void *b)
{
	return timespec_compare( &(((struct packet_batch *)a)->timeout_time),
				 &(((struct packet_batch *)b)->timeout_time)
		);		      
}



/** @} */

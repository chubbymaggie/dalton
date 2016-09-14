#include "batch_creator.h"
#include "trigger_manager.h"
#include "../trigger_state/trigger_finding_methods.h"
#include "../queue.h"
#include "../timespec_utils.h"
#include "../scanner_ui/scanner_output_queue.h"

#include <linux/kernel.h>
#include <linux/module.h>

/* create a batch-creator from a port-array */

struct batch_creator *create_batch_creator(struct port_result **port_result,
					   unsigned int port_array_size,
					   struct trigger_manager_t *trig_man,
					   u32 *bseq_num)
{	
	int t;
	struct batch_creator *this = 
		kmalloc(sizeof(struct batch_creator), GFP_KERNEL);

	if(!this)
		return NULL;

	memset(this, 0, sizeof(struct batch_creator));
		
	this->port_results = create_queue(NULL, GFP_KERNEL, FALSE);	
	this->ports_to_scan = port_result;
	this->batch_seq_num = bseq_num;
	this->trig_man = trig_man;


	if(!this->port_results){
		kfree(this);
		return NULL;
	}
	
	
	/* create the internal ports_results queue from 
	 * the given port-array */

	for(t = 0; t < port_array_size; t++){
		
		if(port_result[t] && !(port_result[t]->exists) ){			
			queue_add(this->port_results, port_result[t]);	
		}

	}

	this->cur_batch_size = 1;
	
	
	return this;
	
}


/**
   Create a new PacketBatch.
   
   A batch must contain at least 1 probe
   and 1 trigger.
*/

struct packet_batch *batch_creator_create_batch(struct batch_creator *this)
{
	struct packet_batch *new_batch;
	struct trigger_instance *new_instance;	

	u16 *port_array = NULL;
	struct port_result **presult_array = NULL;
			
	unsigned int actual_size = 0;
	struct port_result *presult;
	unsigned int t;	
	
	
	new_instance = trig_man_get_fresh_trigger_instance(this->trig_man);

	
	if(!new_instance){
		printk("Error: no trigger available\n");
		return NULL;
	}
	

	port_array = kmalloc(sizeof(u16) * this->cur_batch_size, GFP_KERNEL);	
	
	if(!port_array){
		del_trigger_instance(new_instance);
		return NULL;
	}
	
	presult_array = kmalloc(sizeof(struct port_result *) * this->cur_batch_size, GFP_KERNEL);
	
	if(!presult_array){
		del_trigger_instance(new_instance);
		kfree(port_array);
		return NULL;
	}
	
	
	/* determine ports to use */
	
	for(t = 0; t < this->cur_batch_size; t++){
		
		presult = queue_head(this->port_results, FALSE);
		
		if(!presult){
			break;			
		}
		
		if(presult->exists){
			
			/* The result has been registered after the
			 * batch-timeout. Great, then we don't have
			 * to send another request.
			 */			
			
			t--;
			continue;
		}
		
		port_array[t] = presult->port;
		presult_array[t] = presult;
		actual_size++;		
		
	}
	
	/* Batch creation impossible because no ports
	 * are left to scan.
	 */
	
	if(actual_size == 0){		
		del_trigger_instance(new_instance);
		kfree(presult_array);
		kfree(port_array);
		return NULL;
	}		
	
	new_batch = create_packet_batch(port_array, actual_size, new_instance);	
	
	
	if(!new_batch){		
		del_trigger_instance(new_instance);
		kfree(presult_array);		
		kfree(port_array);
		return NULL;
	}
	
	/* Register pointer from port to batch */
	
	for(t = 0; t < new_batch->size_of_batch; t++){
		presult_array[t]->port_is_in_batch = new_batch;		
	}
	
	new_batch->ports_to_scan = this->ports_to_scan;
	
	/* give next sequence number to this batch */
	
	new_batch->seq_num = ++(*this->batch_seq_num);
	
	kfree(presult_array);
	kfree(port_array);		
	
	return new_batch;

}


void batch_creator_set_cur_batch_size(struct batch_creator *this,
				      u32  size)
{	
	if(size == 0)
		return;
	
	this->cur_batch_size = size;	
}


void batch_creator_add_port(struct batch_creator *this,
			    struct port_result *presult)
{	
	if(presult->exists){
		
		printk("BUG: Attempt to add port to the packet-creator");
		printk("eventhough a result exists already!\n");
		
		return;
	}

	queue_add(this->port_results, presult);	
}

/*
  Reinserts all ports with unkown
  port-state into the batch-creator.
  
*/


void batch_creator_reinsert_ports_of_batch(struct batch_creator *this,
					   struct packet_batch *batch)
{
	
	int t;	
	for(t = 0; t < batch->size_of_batch; t++){
		int port = batch->port_indices[t];
		struct port_result *presult = batch->ports_to_scan[port];
		
		
		if(presult->exists)
			continue;
		
		//presult->port_is_in_batch = NULL;		
		batch_creator_add_port(this, presult);				

	}
	
}


/* Destructor */

void delete_batch_creator(struct batch_creator *this)
{	
	/* Don't free the port_results. They're not yours.
	 * Only forget about them.
	 */

	if(this->port_results)
		queue_clear(this->port_results, NULL);
	
	kfree(this);
}


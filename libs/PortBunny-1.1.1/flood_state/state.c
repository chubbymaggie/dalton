
#include "cmd_handlers.h"
#include "../scanner_module.h"
#include "../scan_jobs.h"
#include "../scan_job_states.h"
#include "../scanner_ui/cmd_handlers.h"
#include "../scanner_ui/scanner_output_queue.h"

#include "../scanner_module.h"
#include "../packet_submitter.h"


#include "../trigger_state/trigger_finding_methods.h"
#include "../trigger_state/tcp_syn_method.h"
#include "../trigger_state/trigger_instance.h"

#include "state.h"
#include "packet_batch.h"
#include "batch_creator.h"
#include "event_reporters.h"
#include "net_info_keeper.h"

#include "timing/tcp_reno.h"
#include "timing/tcp_vegas.h"
#include "timing/tcp_scalable.h"

#include "../sniffer/sniffed_packet.h"
#include <asm/div64.h>
#include <linux/vmalloc.h>

#include "../timespec_utils.h"

/** \addtogroup FloodStateScanJobManager
@{
*/

static struct cmd_handlers_hash_bucket cmd_handlers_hash[CMD_HASH_SIZE];

/**************************************************
   Sending new packets:
****************************************************/


/* Calculate number of packets to send:
 * current_window - nactive_packets
 * 
 * This isn't pleasant to look at because
 * we're using s64 and unsigned int +
 * a blowup-factor since floating-point-
 * arithmetic in the kernel isn't possible.
 */

static u32 get_nnew_packets_allowed(struct flood_state_context *context)
{
	s64 nnew_packets;
	s64 nactive_packets = context->net_info_keeper->nactive_packets;
	nactive_packets *= CWND_BLOWUP_FACTOR;
	
	
	/* If there are currently more active packets than allowed,
	   do not send new ones.*/
	
	if(context->timing_context.cur_cwnd < nactive_packets)
		return 0;

	nnew_packets = 
		context->timing_context.cur_cwnd - nactive_packets;	
	
	do_div(nnew_packets, CWND_BLOWUP_FACTOR);
		
	/* One may never send a single probe
	 * without a trigger. So 2 packets is
	 * the absolute minimum that needs to
	 * be sent at once.
	 */
		
	if(nnew_packets < 2) return 0;

	return (u32) nnew_packets;
}


/*
  Given a number of packets, which it may inject into
  the network, this function creates batches, sends them
  and adds them to the list of active-batches.
  
*/

/* Warning: We're currently not taking into account
 * that as we have fewer ports available to scan, we might
 * be thinking that we have actually sent more than we did.
 * This is of course not good for cwnd-calculation.
 */


static void send_new_packet_batches(struct scan_job_t *this)
{
	struct flood_state_context *context
		= this->state_context;

	struct batch_creator *creator
		= context->creator;

	unsigned int ncomplete_batches;
	u32 nextra_probes;
	struct packet_batch **new_batches;
	unsigned int t;
	unsigned int nbatches = 0;
	
	/* Calculate number new packets allowed */

	u32 nnew_packets = get_nnew_packets_allowed(context);
	if(!nnew_packets) return;	

	/* create new batches: */
	
	ncomplete_batches = 
		(nnew_packets) / (creator->cur_batch_size + 1);
	nextra_probes = nnew_packets - 
		ncomplete_batches * (creator->cur_batch_size + 1);
			

	new_batches =  kmalloc(sizeof(struct packet_batch *) * (ncomplete_batches + 1),
			       GFP_KERNEL);

	if(!new_batches) return;
	
	memset(new_batches, 0, sizeof(struct packet_batch *) * (ncomplete_batches + 1) );
	
	/* (1) create complete batches */
	
	for(t = 0; t < ncomplete_batches; t++){
		
		new_batches[t] =
			batch_creator_create_batch(creator);
		
		if(!new_batches[t]){
			
			/* no further batch could be created.
			 * We're probably out of ports to scan
			 */
			
			break;
		}
								
		nbatches++;			

	}			
	
	if( (nbatches == 0) && (ncomplete_batches > 0) ){
		/* Not a single batch could be created... */				
		kfree(new_batches);		
		return;
	}
	

	/* If there are extra probes or there is only one batch
	   to be created, create last or one and only batch */
	
	if( ! ((nbatches != ncomplete_batches) || (nextra_probes <= 1) )){
		
		
		
		/* create last batch or, if npackets_requested < cur_batch_size + 1,
		 * create the one and only batch.
		 */
		
		unsigned int old_batch_size = creator->cur_batch_size;				
		
		
		batch_creator_set_cur_batch_size(creator, nextra_probes - 1);				
		new_batches[ncomplete_batches] = batch_creator_create_batch(creator);
		batch_creator_set_cur_batch_size(creator, old_batch_size);


		if(!new_batches[ncomplete_batches] && (ncomplete_batches == 0)){
			
			/* One and only batch could not be created. */

			kfree(new_batches);			
			return;
			
		}
		
	}
	
	/* now add all batches created */
	
	for(t = 0; t < (ncomplete_batches + 1); t++){
		if(new_batches[t]){
						
			send_packet_batch(new_batches[t], this);
			queue_ordered_add(context->active_batches, new_batches[t],
					  &compare_batches);			
			
			
			net_info_keeper_on_sent(context->net_info_keeper, new_batches[t]);																	
		}
	}


	kfree(new_batches);
}


/**
   FloodStateScanJob-Constructor
   
   TODO: trigger-list does not make use of the generic
   queue-class yet and is not freed in the scan-job-destructor

*/


static int scan_job_init(struct scan_job_t *this)
{
	struct flood_state_context *context;
	unsigned int t = 0;

	
	/* Allocate memory for state-context and initialize it to 0. */

	context = this->state_context
		= kmalloc(sizeof(struct flood_state_context), GFP_KERNEL);

	if(!this->state_context){
		this->state_context = NULL;
		return FAILURE;
	}

	memset(this->state_context, 0, sizeof(struct flood_state_context));
	
	/* initialize net_info_keeper */
	context->net_info_keeper = create_net_info_keeper();
	if(!context->net_info_keeper)
		return FAILURE;
	
	
	/* Initialize timing */
	
	context->timing_alg = &tcp_scalable;
	context->timing_algo_state =
		context->timing_alg->constructor(this, &context->timing_context);


	/* Initialize trigger-manager */

	context->trig_man = new_trigger_manager();
	
	/* Initialize lists used for batch-management */	
	context->active_batches = create_queue(NULL, GFP_KERNEL, FALSE);
	context->recent_batches = create_queue(NULL, GFP_KERNEL, FALSE);
	
	
	if(!context->active_batches || !context->recent_batches || !context->trig_man){
		kfree(this->state_context);
		this->state_context = NULL;
		return FAILURE;
	}
		
	/* initialize the packet-queue used for incoming packets. */			
	
	this->packets = create_queue(NULL, GFP_KERNEL, FALSE);
	
	if(!this->packets){
		delete_queue(context->active_batches, NULL);
		delete_queue(context->recent_batches, NULL);
		kfree(this->state_context);
		this->state_context = NULL;
		return FAILURE;
	}

	/* initialize ports to scan to a valid value
	 * just to make sure people don't crash their kernel
	 * simply because they forgot to use set_ports_to_scan
	 */
	
	context->nports_to_scan = NDEFAULT_PORTS_TO_SCAN;
	context->port_array_size = NDEFAULT_PORTS_TO_SCAN + 1;
	context->ports_to_scan = vmalloc(sizeof(struct port_result *) * context->port_array_size);
	
	if(!context->ports_to_scan){		
		delete_queue(context->active_batches, NULL);
		delete_queue(context->recent_batches, NULL);
		kfree(this->state_context);
		this->state_context = NULL;
		return FAILURE;
	}

	memset(context->ports_to_scan, 0, sizeof(struct port_result *) * context->port_array_size);	
	
	for(t = 1; t <= NDEFAULT_PORTS_TO_SCAN; t++){
		context->ports_to_scan[t] = create_port_result(t);
	}

	
	return SUCCESS;

}


/**
        Flood-state-scan-job Destructor
*/

static void scan_job_fini(struct scan_job_t *this)
{
	
	struct flood_state_context *context
		= this->state_context;
		
	if(context->net_info_keeper)
		delete_net_info_keeper(context->net_info_keeper);
	

	/* delete queues holding batches */
	
	delete_queue(context->active_batches, (delete_data_func) delete_packet_batch);
	delete_queue(context->recent_batches, (delete_data_func) delete_packet_batch);
	
	/* destruct trigger-manager*/
	if(context->trig_man)
		del_trigger_manager(context->trig_man);
	

	if(context->creator)
		delete_batch_creator(context->creator);
		
	
	/* free old ports_to_scan array if any. */

	if(context->ports_to_scan){
		
		int t;
		for(t = 0; t < context->port_array_size; t++)
			if(context->ports_to_scan[t])
				delete_port_result(context->ports_to_scan[t]);
				
		vfree(context->ports_to_scan);		
	}
		
	
	delete_queue(this->packets, (delete_data_func) del_sniffed_packet_descr);
	
	if(this->addr_str)
		kfree(this->addr_str);
	
	context->timing_alg->destructor(this, context->timing_algo_state,
					&context->timing_context);
	
	kfree(this->state_context);
	kfree(this);
}

/**************************************************
  Processing of incoming packets in flood-state
***************************************************/

/**
  
   Returns one of the three port-states OPEN, CLOSED or FILTERED
   indicated by the incoming packet 'descr'.

*/

static port_state_t get_port_state_by_packet
(struct sniffed_packet_descr_t *descr)
	
{
	if(descr->protocol == IPPROTO_TCP){	
		
		if( descr->tcp.syn && descr->tcp.ack ) return OPEN;
		if( descr->tcp.rst && descr->tcp.ack ) return CLOSED;
		
		
	}else if(descr->protocol == IPPROTO_ICMP){
		if(descr->icmp.type == ICMP_DEST_UNREACH &&
		   (descr->icmp.code == ICMP_PKT_FILTERED ||
		    descr->icmp.code == ICMP_PORT_UNREACH)) return FILTERED;		
	}
	
	return ERROR;
}



u16 get_port_by_probe_response(struct sniffed_packet_descr_t *descr)
{
	if(descr->protocol == IPPROTO_TCP) return descr->tcp.port;
	
	if(descr->protocol == IPPROTO_ICMP &&
	   descr->icmp.type == ICMP_DEST_UNREACH &&
	   (descr->icmp.code == ICMP_PKT_FILTERED || 
	    descr->icmp.code == ICMP_PORT_UNREACH))
		return descr->icmp.unreach_port;
	
	return 0;
}

/**
  
   Returns the port-result-entry associated with the given
   port or NULL if the port is not valid or the port-result
   is already know.
   
 */

static struct port_result *get_port_result_by_port(__u16 port,
						   struct flood_state_context *context)
{
	struct port_result *retval;	

	/* 1. Is the port being scanned at all? */
	
	/* check if port is between 0 and biggest port-number scanned */

	if(!((port > 0) && (port < context->port_array_size))){
		printk("port-number %d out of range\n", port);
		return NULL;
	}

	retval = context->ports_to_scan[port];
	
	if(!retval){
		printk("port-number %d not being scanned\n", port);
		return NULL;
	}
	
	
	/* Check if there is already a result registered for
	 * this port which was created using an
	 * earlier response.
	 */
	
	if( (retval->exists) && (retval->state != FILTERED) ){		
		printk("port-result %d already known\n", port);						
		return NULL;
	}
	
	return retval;
}


/**
   Adds 'descr' as a trigger.
*/

static void add_trigger(struct sniffed_packet_descr_t *descr,
			struct scan_job_t *this,
			__u16 port)
{
	struct flood_state_context *context = this->state_context;	
	u8 quality = TCP_SYN_NEG_QUALITY;
	

	if(!ADD_TRIGGERS_AT_RUNTIME) return;
	
	/* We only want to do this for TCP-responses
	 * (TCP_SYN_ACK/TCP_ACK_RST) for now.
	 */	
	if(descr->protocol != IPPROTO_TCP) return;
	
	if(get_port_state_by_packet(descr) == OPEN)
		quality = TCP_SYN_POS_QUALITY;
		
		
	if(trig_man_add_trigger(context->trig_man, TCP_SYN_FINDING_METHOD, port, quality))
			output_trigger_added_event(this, port);	
	
}

/**

   Handles all incoming probe-responses after they have been
   classified as such by process_pending_packets.
      
   Registers the port_result indicated by the port-response.

*/

static void process_probe_response(struct scan_job_t *this,
				   struct sniffed_packet_descr_t *descr)
{
	struct flood_state_context *context = this->state_context;	
	struct port_result *result;	
	struct packet_batch *batch;	

	/* 1. Extract port-number from packet and validate it. */

	u16 port = get_port_by_probe_response(descr);		
	if(!(result = get_port_result_by_port(port, context)))
		return;
	
	
	/* 2. Is this probe currently in an active batch
	 * or in the list of recent batches?
	 */
	
	batch = result->port_is_in_batch;
	
	if(!batch){
		printk("probe-response has valid form but probe can't be found");
		printk("in active or recent batches\n");			
		return;	
	}
	
		
	/* register result */
	
	/* given that result does not yet exist,
	 * increase nports_scanned. If this port
	 * is currently in a batch
	 */

	if(!result->exists){
		context->nports_scanned++;		
	
		if(!batch->inactive){
			
			/*
			  If this is a non-duplicate probe-response for an
			  active batch, inform the net-info-keeper.
			 */
			
			net_info_keeper_on_probe_rcv(context->net_info_keeper,
						     batch, descr);		
		
		}

	}

	set_port_result(result, get_port_state_by_packet(descr));			
	output_port_result(result, this->addr_str);		
	
	/* use this port as a new trigger */	
	add_trigger(descr, this, port);
			
}




/**
   Determine the trigger-type (trigger-method) of
   the trigger described by descr and the batch
   this trigger belongs to.
   
   Register the trigger-response.  
   
   Note: This new implementation expects that all
   trigger-methods can determine without question
   if a trigger-response does or does not belong
   to its triggering-method.
   

*/

static void process_trigger_response(struct scan_job_t *this,
				     struct sniffed_packet_descr_t *descr)
{
	struct flood_state_context *context = this->state_context;	
	struct packet_batch *batch = NULL;
	struct port_result *result;
		
	u8 method_id = trig_man_get_method_id(context->trig_man, descr);	
	u32 batch_id;
	s32 round;

	struct timespec new_rtt = { .tv_sec = 0, .tv_nsec = 0,};
	
	if(method_id == NO_FINDING_METHOD) return;
	
	batch_id = trig_man_get_batch_id(context->trig_man, descr, method_id);	
	
	if(! ((batch_id > 0 ) && (batch_id < context->port_array_size))){
		printk("batch_id: %d out of range\n", batch_id);
		return;
	}		
	
	result = context->ports_to_scan[batch_id];		
		
	if(!result){
		
		/* This can't be a response to our trigger because
		 * a trigger with this seq-num will never and has
		 * never been sent.*/
		
		printk("invalid trigger-sequence-number\n");
		return;
	}
	
	batch = result->port_is_in_batch;
	
	if(!batch){
		printk("packet has correct trigger-response-form but");
		printk(" cannot be found in active or recent batches\n");
		return;
	}
	
	
	if(batch->trigger_rcv_time){
			printk("Trigger %d already has a response\n", batch->port_indices[0]);
			return;
	}
	
	
	/* Handle late trigger-responses */
	
	if(batch->inactive){
		
		printk("late-trigger response received\n");		
		
		/* rewind cwnd */
		
		
		
		context->timing_alg->on_late_response(this,
						      context->timing_algo_state,
						      &context->timing_context
			);				
		
		
		/* and act as if the batch completed normally. */
		
		batch_mark_unknown_as_filtered(batch, this);
		batch_output_filtered_ports(batch, this);
		
	}
	
	
	/* write down the trigger-receive time */
	batch->trigger_rcv_time = kmalloc(sizeof(struct timespec), GFP_KERNEL);
	if(!batch->trigger_rcv_time)
		return;
	
	/* trigger response received */				
	
	memcpy(batch->trigger_rcv_time, &descr->time_received, sizeof(struct timespec));				
	
	/* update the last-sequence-number-received counter 'max_batch_seq_received'. */
	
	if(context->max_batch_seq_received < batch->seq_num)
		context->max_batch_seq_received = batch->seq_num;
			
	/* if this trigger triggered a tcp_syn_ack, write this
	 * down! This may result in ports being reported OPEN
	 * twice but at least we wont miss the port.
	 */
	
	if(get_port_state_by_packet(descr) == OPEN){
		struct port_result *result;
		struct method_id_and_round m_id_and_round = {
			.method_id = method_id,
			.round = trigger_finding_methods[method_id]->get_round_by_descr(descr),
		};		
		
		
		if(descr->tcp.port < context->port_array_size){
			
			result = context->ports_to_scan[descr->tcp.port];						
			
			if(!result) return;
			
			if(result->state != OPEN){										
				result->state = OPEN;	
				
				/* output OPEN ports. */
				
				output_port_result(result, this->addr_str);				
			}	
			
		}
		
		/* Mark the trigger's quality to make sure it can be
		   discarded if better triggers are found
		*/
		
		trig_man_set_quality_of_instance(context->trig_man, &m_id_and_round,
						 TCP_SYN_POS_QUALITY);		
	}
	
	
	/* and update the rtt */		
	if(timespec_compare(batch->trigger_rcv_time, &batch->time_sent) >= 0){
		
		new_rtt = timespec_sub(*(batch->trigger_rcv_time),
				       batch->time_sent);		
	}
	
	
	net_info_keeper_update_rtt(context->net_info_keeper,
				   &new_rtt);
	
	context->timing_alg->on_update_timeout(this, context->timing_algo_state,
					       &context->timing_context,
					       context->net_info_keeper,
					       batch->trigger_rcv_time,
					       &batch->time_sent
		);				
	
	
	//output_timeout_info(this);
	
	/* report trigger-event */
		
	round =
		trigger_finding_methods[method_id]->get_round_by_descr(descr);
	
	
	output_trigger_received_event(this, method_id, round, &new_rtt);			
	
			
}



/**
   Polls the sniffed_packet_queue of this ScanJob which
   contains all newly arrived packets.

   For each newly arrived packet, it checks whether this
   is a trigger-response or a probe-response. In the
   case of a probe-response, \ref process_probe_response is called.
   Else, \ref process_trigger_response is called.
   
*/


static void process_pending_packets(struct scan_job_t *this)
{
	struct sniffed_packet_descr_t *p_descr;
	struct flood_state_context *context = this->state_context;

	while((p_descr = queue_head(this->packets, FALSE))){
		
		struct sniffed_packet_descr_t *descr =
			(struct sniffed_packet_descr_t *) p_descr;				
		
		/* Discard arp-frames for now */
		
		if(descr->is_arp){
			kfree(descr);
			continue;
		}
		
		
		/* If this is a tcp-syn-ack with an ack_seq of 0,
		   this is a probe-response.
		*/		
				
		if( (descr->protocol == IPPROTO_TCP) &&
		    (descr->src == this->addr)       &&	    
		    descr->tcp.ack && ( ( descr->tcp.syn || descr->tcp.rst ) &&
					(descr->tcp.ack_seq == 0)))					
			
			process_probe_response(this, descr);
		
		/*
		  If this is an icmp-destination-unreachable with
		  a code ICMP_PKT_FILTERED or ICMP_PORT_UNREACH,
		  this is a probe-response. This is however, only
		  the case if the unreachable was actually generated
		  by a TCP-packet.
		 */
		
		else if (descr->protocol == IPPROTO_ICMP &&
			 descr->src == this->addr &&
			 descr->icmp.type == ICMP_DEST_UNREACH &&
			 descr->icmp.unreach_protocol == IPPROTO_TCP &&
			 (descr->icmp.code == ICMP_PKT_FILTERED ||
			  descr->icmp.code == ICMP_PORT_UNREACH)){												
			
			process_probe_response(this, descr);
		}		

		/*
		  For all other packets, check if it is
		  a trigger-response.
		*/
		
		else		  						
			process_trigger_response(this, descr);
		
				
		
		if(context->timing_context.no_responses_since_drop)
			context->timing_context.no_responses_since_drop = FALSE;
				
		kfree(descr);
	}
	
}

static boolean all_port_states_known(struct scan_job_t *this)
{
	struct flood_state_context *context
		= this->state_context;
	
	return (context->nports_scanned == context->nports_to_scan);

}



/**
   Check the list of active batches
   for finished and timed-out batches and
   react accordingly.
         
   Returns the next timeout-time or 0 if no batches exist.
   
*/


static s64 manage_batches(struct scan_job_t *this)
{
	struct flood_state_context *context = 
		this->state_context;
	
	/* for each active batch, check if it has finished
	 * or timed out.*/
	struct list_head *p, *n;
	struct queue_node_t *root = get_root(context->active_batches);
	boolean last_batch_alive = FALSE;
	struct packet_batch *head;
	
	/* current time is needed to check for timed-out batches */
	struct timespec cur_time;
	getnstimeofday(&cur_time);
	
	/* for each active batch */
	
	list_for_each_safe(p, n, &root->list){
		struct queue_node_t *entry = 
			list_entry(p, struct queue_node_t, list);
		struct packet_batch *batch = entry->data;
		
			
		/* handle finished batches */
		if(batch->trigger_rcv_time){		
			unsigned int t;
			
			
			/* trigger has been received - batch is finished. */
	
			context->timing_alg->on_rcv(this, context->timing_algo_state,
						    &context->timing_context,
						    batch);
	
			net_info_keeper_on_trigger_rcv(context->net_info_keeper, batch);
			
			
			/* port-states which are still unknown can now
			 * be marked as filtered.
			 */
			
			batch_mark_unknown_as_filtered(batch, this);
			
			/* all probes of this batch are now not active anymore:
			 * increase cwnd accordingly.			 
			 * This isn't optimal: We're increasing the cwnd by
			 * multiples of the batch size.
			 * This results in rather bursty data.
			 */
			
			for(t = 0; t < batch->size_of_batch; t++){										
				
				/* increase cwnd for each probe in the batch */
				
				context->timing_alg->on_rcv(this, context->timing_algo_state,
							    &context->timing_context, batch);																								
			}			
			
																		
			/* remove batch from list of active batches */
			
			list_del(&entry->list);                 
                        kfree(entry);
                        
			batch_output_filtered_ports(batch, this);		
			
			
			/* save batch in recent-batches */
			
			batch->inactive = TRUE;
			queue_add_limited(context->recent_batches, batch,
					  (delete_data_func) delete_packet_batch,
					  NUM_OLD_BATCHES_TO_STORE);
			
					  

			//output_cwnd_updated_event(this);			
			
			/* the window has changed, try sending new batches. */
			send_new_packet_batches(this);						
						
			/* process next batch */
			continue;
			
		}
		
		/* No answer for this batch. Check if it has timed out. */
		
		else if(last_batch_alive){
			
			/* if the last batch we checked has not timed-out,
			 * this one hasn't either since active_batches is
			 * ordered by timeout-time
			 */
			
			/* process next batch */			
			continue;
		}else{
			
			/* last batch has timed out, check if this one has, too.*/
			if(!batch_timed_out(batch, context, &cur_time)){			
				last_batch_alive = TRUE;
				/* process next batch */
				continue;
			}
			
		}
		
		/* batch has timed out. */
		
		
		/* make sure to call drop-function only once for each
		 * burst of drops.
		 */
		
		if(! context->timing_context.no_responses_since_drop){
			context->timing_alg->on_drop(this, context->timing_algo_state,
						     &context->timing_context,
						     context->net_info_keeper,
						     NULL);
						
		}
		
		
		/* notify net-info-keeper and event-reporter about the drop */

		net_info_keeper_on_timeout(context->net_info_keeper, batch);		
		
		if(context->report_events){						
			s32 round = trigger_instance_get_round(batch->trigger);
			output_dropped_trigger_event(this, batch->trigger->method_id, round);
		}			
		
		/* report rate-limiter if it was detected */
		
		//if(context->net_info_keeper->is_rate_limiter)
		//	output_rate_limiter_detected(this);
		

		/* Reinsert any unknown ports
		 * from timed-out batch into
		 * the batch-creator so that they
		 * can be scanned again.
		 */		
		
		batch_creator_reinsert_ports_of_batch(context->creator, batch);			
		context->timing_context.no_responses_since_drop = TRUE;			
		
		/* remove batch from queue of active-batches */
		list_del(&entry->list);			
		kfree(entry);
		
		
		/* save batch in recent_batches */
		
		batch->inactive = TRUE;
		queue_add_limited(context->recent_batches, batch,
				  (delete_data_func) delete_packet_batch,
				  NUM_OLD_BATCHES_TO_STORE);
		
		/* the window has changed, try sending new batches. */
		send_new_packet_batches(this);						
				
	}	

	head = queue_read_head(context->active_batches);
	if(!head){
		return 1;		
	}
	return timespec_to_ns(&head->timeout_time);
		
	
}


static void rescan_filtered(struct scan_job_t *this)
{
	struct flood_state_context *context = this->state_context;
	
	unsigned int nfiltered = 0;
	unsigned int nothers = 0;
	int t;

	/* count number of filtered/not filtered ports */

	for(t = 0; t < context->port_array_size; t++){
		
		if(!context->ports_to_scan[t])
			continue;

		if(context->ports_to_scan[t]->state == FILTERED)
			nfiltered++;
		else
			nothers++;

	}

	/* if the number of filtered ports is bigger than 30%,
	 * don't rescan.
	 */
	
	if ((nfiltered * 100)/(nfiltered + nothers) > 30)
		return;
	
	
	/* rescan */

	for(t = 0; t < context->port_array_size; t++){
		
	
		if(context->ports_to_scan[t] && context->ports_to_scan[t]->state == FILTERED){
			
			/* mark port-states as unknown */
			context->ports_to_scan[t]->exists = FALSE;
			context->ports_to_scan[t]->port_is_in_batch = NULL;
			

			/* add port to batch-creator */
			batch_creator_add_port(context->creator, context->ports_to_scan[t]);		
			context->nports_scanned--;
			
		}

	}

	batch_creator_set_cur_batch_size(context->creator, 9);


}

/**
  Called by the flood-state-scan-job-manager to
  start the scan-job:
  
  - Creates the batch-creator
  - Sends initial packets.

*/


static void start_flood_job(struct scan_job_t *this)
{
	struct flood_state_context *context = this->state_context;
	
	context->creator = create_batch_creator(context->ports_to_scan,
							context->port_array_size,
							context->trig_man,
							&context->batch_seq_num);
		
		batch_creator_set_cur_batch_size(context->creator,
						 context->timing_context.cur_batch_size);
		
		context->started = TRUE;		
		
		send_new_packet_batches(this);
}

/**
   FloodStateScanJobManager-Function.
   
   When initialy called, a \ref BatchCreator
   is created and initialized with the
   ports_to_scan-array. Initial packets are sent.
   
   The ScanJobManagerFunction then does
   the following each round:
        
   (1) it processes any pending packets
   by calling
   \ref FloodStateScanJobManager::process_pending_packets.
   
   (2) It manages active \ref Batches s by
   calling \ref manage_batches.
   
   (3) It checks if all port states are now
   known and we are finished waiting for late
   responses. If so, it returns FINISHED.
   

*/

static s64 flood_state_scan_job_manager(struct scan_job_t *this)
{
	struct flood_state_context *context = this->state_context;		
	s64 next_timeout;
	
	if(!context->started)
		start_flood_job(this);					       	
	

	process_pending_packets(this);				
	next_timeout = manage_batches(this);	
		

	/* We're done once we know all port-states
	 * and we have no more batches waiting for
	 * late packets in the complete_batches-queue.
	 */

	if(all_port_states_known(this)){
		
		/* rescan filtered ports if necessary */
		
		if(context->nrescanned_filtered != NRESCANS_OF_FILTERED_PORTS){
			rescan_filtered(this);
			context->nrescanned_filtered++;
			printk("%d rescans of filtered ports performed.\n", context->nrescanned_filtered);
		}else						
			return FINISHED;			
			
		send_new_packet_batches(this);
		
		/* if there was previously no active batch left,
		   call manage_batches again to get the next-timeout-time
		*/
		if(next_timeout == 1)
			next_timeout = manage_batches(this);
	}
		
	
	return next_timeout;
}


static int flood_state_init(void)
{
		
	cmd_handlers_init(flood_state.cmd_handlers);

	/* now register all cmd-handlers */
	
	cmd_handlers_register(flood_state.cmd_handlers,
			      "set_ports_to_scan",
			      &set_ports_to_scan_handler);

	cmd_handlers_register(flood_state.cmd_handlers,
			      "append_to_trigger_list",
			      &append_to_trigger_list_handler);
	
	
	cmd_handlers_register(flood_state.cmd_handlers,
			      "clear_trigger_list",
			      &clear_trigger_list_handler);

	cmd_handlers_register(flood_state.cmd_handlers,
			      "set_report_events",
			      &set_report_events_handler);
	
	cmd_handlers_register(flood_state.cmd_handlers,
			      "set_timing_algorithm",
			      &set_timing_algorithm_handler);



	return SUCCESS;
}


static void flood_state_fini(void)
{
	cmd_handlers_fini(flood_state.cmd_handlers);
}


/**
   scan_job_state_t-implementation exported
   and saved in \ref scan_job_states so that
   the ScanJobManager can make use of this state.
   
*/

struct scan_job_state_t flood_state = {
		
	.name = "FLOOD",	
	.scan_job_manager = &flood_state_scan_job_manager,
	.scan_job_init = &scan_job_init,
	.scan_job_fini = &scan_job_fini,
	.init = &flood_state_init,
	.fini = &flood_state_fini,
	
	.cmd_handlers = cmd_handlers_hash


};

/** @} */


#include "../scanner_module.h"
#include "../scan_job_states.h"
#include "../scanner_ui/cmd_handlers.h"
#include "../queue.h"
#include "../packet_submitter.h"
#include "../sniffer/sniffed_packet.h"
#include "../timespec_utils.h"
#include "../scanner_ui/scanner_output_queue.h"
#include "state.h"
#include "trigger_finding_methods.h"
#include "cmd_handlers.h"

#include <linux/list.h>


/** \addtogroup TriggerStateScanJobManager
    @{
*/

static int has_timed_out(struct scan_job_t *this);

static struct cmd_handlers_hash_bucket cmd_handlers_hash[CMD_HASH_SIZE];

static int trigger_state_init(void)
{	
	cmd_handlers_init(trigger_state.cmd_handlers);
	
	/* now register all cmd-handlers */
	
	cmd_handlers_register(trigger_state.cmd_handlers,
			      "append_to_methods_list",
			      &append_to_methods_list_handler);
	
	cmd_handlers_register(trigger_state.cmd_handlers,
			      "clear_methods_list",
			      &clear_methods_list_handler);
	
	cmd_handlers_register(trigger_state.cmd_handlers,
			      "number_of_triggers_wanted",
			      &number_of_triggers_wanted_handler);
	
	cmd_handlers_register(trigger_state.cmd_handlers,
			      "set_method_timeout",
			      &set_method_timeout_handler);	
							
	return SUCCESS;
}


static void trigger_state_fini(void)
{
	cmd_handlers_fini(trigger_state.cmd_handlers);
}

/**
   TriggerStateScanJob-Constructor  
   
   Constructs a trigger-state scan-job's context.
   
   Return-value: SUCCESS on success, FAILURE otherwise.
*/

static int scan_job_init(struct scan_job_t *this)
{
	struct trigger_state_context *context;
	
        /* allocate space for context */
	context = this->state_context
		= kmalloc(sizeof(struct trigger_state_context), GFP_KERNEL);
	
	if(!this->state_context){
		this->state_context = NULL;
		return FAILURE;
	}

	/* Initialize context */
	memset(this->state_context, 0, sizeof(struct trigger_state_context));	
	
	/* Initialize list of triggers and list of active triggers */

	context->trigger_list = create_queue(NULL, GFP_KERNEL, FALSE);	
	context->active_triggers = create_queue(NULL, GFP_KERNEL, FALSE);

	
	if(!context->trigger_list || !context->active_triggers){
		kfree(this->state_context);
		this->state_context = NULL;
		return FAILURE;
	}

	context->ntriggers_found = 0;
	
	/* To speed up the trigger process, try to get only
	 * 1 trigger by default
	 */
	
	context->ntriggers_to_find = 1;
	context->ntriggers_at_once = DEFAULT_NTRIGGERS_AT_ONCE;
	
	
	/* initialize the packet-queue used for incoming packets */
	/* if the number of state-independent members which need
	   initialization grows, create a generic scan-job-constructor. */
	
	this->packets = create_queue(NULL, GFP_KERNEL, FALSE);
	if(!this->packets){
		kfree(this->state_context);
		this->state_context = NULL;
		return FAILURE;
	}
	

	context->timeout.tv_sec = TRIGGER_DEFAULT_TIMEOUT_S;
	context->timeout.tv_nsec = TRIGGER_DEFAULT_TIMEOUT_NS;	
	

	return SUCCESS;
}

/**
   TriggerStateScanJob-Destructor

   
*/

static void scan_job_fini(struct scan_job_t *this)
{
	struct trigger_state_context *context
		= this->state_context;
		
	delete_queue(context->trigger_list, (delete_data_func) del_trigger_instance);
	delete_queue(context->active_triggers, (delete_data_func) del_trigger_instance);
	
	delete_queue(this->packets, (delete_data_func) del_sniffed_packet_descr);
		
	if(this->addr_str)
		kfree(this->addr_str);
	
	/* free the scan-job */
	kfree(this->state_context);
	kfree(this);
}


/**
   Scan-job-manager-function:
   
   Return-Value: Returns FINISHED if it has finished and CALL_AGAIN if
   it has not.
*/

static s64 trigger_state_scan_job_manager(struct scan_job_t *this)
{
	struct trigger_state_context *context = this->state_context;				

	
	if(is_queue_empty(context->active_triggers)){
		
		/* We're not waiting for any more triggers to complete
		   or haven't sent any.
		   Send as many triggers as we are allowed to send at once.
		*/
		
		unsigned int ntriggers_sent = 0;				
		while(ntriggers_sent < context->ntriggers_at_once){			
			
			/* fetch next trigger-node from the trigger-list */
			struct trigger_instance *cur_trigger_instance = 
				queue_head(context->trigger_list, FALSE);
						
			
			if(cur_trigger_instance == NULL)
				/* no triggers left to send. */
				break;
						
			/* launch this trigger-finding-method's sender-routine. */
			
			trigger_finding_methods[cur_trigger_instance->method_id]->sender_func(this, cur_trigger_instance);
			
			
			/* trigger has been sent, add it to list of
			 * active triggers. */
			queue_add(context->active_triggers, cur_trigger_instance);
			ntriggers_sent++;
		}
		
				
		/* if the list of active triggers is still empty,
		 * no triggers were left to try and we're done.
		 */
		
		if(is_queue_empty(context->active_triggers)){			
			
			if(context->got_arp_reply){				
				
				/* no trigger found but we got an ARP-reply.
				 * report the host as up.
				 */
				
				output_msg_header(this->addr_str, "R", "UP", FALSE);		
				scanner_output_queue_add("\n");
				scanner_output_queue_flush();	

			}
			
			return FINISHED;							
		}
		
		/* set timeout-time to be current-time + timeout-value */
		
		getnstimeofday(&context->timeout_spec);		
		context->timeout_spec.tv_sec += context->timeout.tv_sec;
		timespec_add_ns(&context->timeout_spec, context->timeout.tv_nsec);

	}
	
	
	/* Check for results for all active triggers. */
	
	if(!is_queue_empty(context->active_triggers)){
		
		struct list_head *p, *n;
		struct queue_node_t *root = get_root(context->active_triggers);

		
		/* fetch next packet from sniffed-packet-queue */

		struct sniffed_packet_descr_t *descr;		
		while((descr = queue_head(this->packets, FALSE))){
						

			if(descr->is_arp){
				
				/* Handle arp-responses for this job. */			
				context->got_arp_reply = TRUE;				
				kfree(descr);
				continue;
			}

			list_for_each_safe(p, n, &root->list){
				
				struct queue_node_t *entry = 
				list_entry(p, struct queue_node_t, list);
				struct trigger_instance *cur_trigger_instance = entry->data;
				int call_again;
				
				
				/* call the trigger-method supplied receiver-function */
				
				call_again = trigger_finding_methods[cur_trigger_instance->method_id]->
					receiver_func(this, cur_trigger_instance, descr);
				
				
				if(call_again) continue;				
				

				/* method has finished, remove it. */
				
				list_del(&entry->list);
				kfree(entry);			
				del_trigger_instance(cur_trigger_instance);
				
				
				if(context->ntriggers_to_find > 0){
					
					/* Return FINISHED if we have found enough triggers */
					
					if(context->ntriggers_found >= context->ntriggers_to_find){
						kfree(descr);			
						printk("Found %d triggers, that's enough :)\n", context->ntriggers_found);
						return FINISHED;
					}								
				}			
			}
			
			
			kfree(descr);			
		}
				
		
		/* if triggers have timed out, clear list of active triggers so
		 * that new triggers will be sent.
		 */
		
		if(has_timed_out(this))			
			queue_clear(context->active_triggers,
				    (delete_data_func) del_trigger_instance);							
	}
		
	return timespec_to_ns(&context->timeout_spec);
	
}


static int has_timed_out(struct scan_job_t *this)
{
	struct trigger_state_context *context = this->state_context;

	/* retrieve current time */
	struct timespec cur_time;
	getnstimeofday(&cur_time);
	
	/* has time-out been reached? */

	return (timespec_compare(&context->timeout_spec, &cur_time) <= 0);	
}

struct scan_job_state_t trigger_state = {
	
	
	.name = "TRIGGER",
	.scan_job_manager = &trigger_state_scan_job_manager,
	.scan_job_init = &scan_job_init,
	.scan_job_fini = &scan_job_fini,
	.init = &trigger_state_init,
	.fini = &trigger_state_fini,

	.cmd_handlers = cmd_handlers_hash,

};

/** @} */

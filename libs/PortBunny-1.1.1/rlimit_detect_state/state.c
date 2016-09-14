
#include "../scanner_module.h"
#include "../scan_job_states.h"
#include "../scanner_ui/cmd_handlers.h"
#include "../queue.h"
#include "../packet_submitter.h"
#include "../sniffer/sniffed_packet.h"
#include "../timespec_utils.h"
#include "state.h"
#include "cmd_handlers.h"

#include <linux/list.h>


static struct cmd_handlers_hash_bucket cmd_handlers_hash[CMD_HASH_SIZE];

static int rlimit_detect_state_init(void)
{	
	cmd_handlers_init(rlimit_detect_state.cmd_handlers);
	
	/* now register all cmd-handlers */

	cmd_handlers_register(rlimit_detect_state.cmd_handlers,
			      "set_trigger",
			      &set_trigger_handler);
	
	/*
	cmd_handlers_register(rlimit_detect_state.cmd_handlers,
			      "set_timeout",
			      &set_timeout_handler);
	*/
	
	cmd_handlers_register(rlimit_detect_state.cmd_handlers,
			      "set_batch_size",
			      &set_batch_size_handler);
									
	return SUCCESS;
}


static void rlimit_detect_state_fini(void)
{
	cmd_handlers_fini(rlimit_detect_state.cmd_handlers);
}



static int scan_job_init(struct scan_job_t *this)
{
	struct rlimit_detect_state_context *context;
	
        /* allocate space for context */
	context = this->state_context
		= kmalloc(sizeof(struct rlimit_detect_state_context), GFP_KERNEL);
	
	if(!this->state_context){
		this->state_context = NULL;
		return FAILURE;
	}
	
	/* Initialize context */
	memset(this->state_context, 0, sizeof(struct rlimit_detect_state_context));	
			
	
	/* initialize the packet-queue used for incoming packets */
	/* if the number of state-independent members which need
	   initialization grows, create a generic scan-job-constructor. */
	
	this->packets = create_queue(NULL, GFP_KERNEL, FALSE);
	if(!this->packets){
		kfree(this->state_context);
		this->state_context = NULL;
		return FAILURE;
	}
	
	/* set default values */

	context->batch_size = RLIMIT_DEFAULT_BATCH_SIZE;
	
	context->trigger_method_id = RLIMIT_DEFAULT_METHOD_ID;
	context->trigger_round = RLIMIT_DEFAULT_ROUND;

	context->timeout.tv_sec = RLIMIT_DEFAULT_TIMEOUT_S;
	context->timeout.tv_nsec = RLIMIT_DEFAULT_TIMEOUT_NS;
	
	
	return SUCCESS;
}

static void scan_job_fini(struct scan_job_t *this)
{
	struct rlimit_detect_state_context *context
		= this->state_context;
	unsigned int t;
		
	if(this->addr_str)
		kfree(this->addr_str);
	
	if(context->triggers_sent){

		for(t = 0; t < context->batch_size; t++){
			if(context->triggers_sent[t])
				kfree(context->triggers_sent[t]);
		}
	
		kfree(context->triggers_sent);
	}

	/* free the scan-job */
	kfree(this->state_context);
	kfree(this);
}


static s64 rlimit_detect_scan_job_manager(struct scan_job_t *this)
{
	struct rlimit_detect_state_context *context = this->state_context;						


	if(context->state == STATE_INIT){
		
		unsigned int t;		

		if(!trigger_finding_methods[context->trigger_method_id]->large_sender_func){
			printk("Can't do firewall-detection: Trigger cannot be enlarged\n");
			return FINISHED;
		}		

		/* create array of trigger-instances */

		context->triggers_sent = kmalloc(sizeof(struct trigger_instance *)
						 * context->batch_size, GFP_KERNEL);
		
		if(!context->triggers_sent){
			printk("ERROR -1 out of memory\n");
			return FINISHED;
		}
		

		/* send initial burst and enter state STATE_FIRST_WAIT */
		
		
		for(t = 0; t < context->batch_size; t++){
			
			if(!t)				
				context->triggers_sent[0] = new_trigger_instance(context->trigger_method_id,
										 context->trigger_round);			
			else
				context->triggers_sent[t] = copy_trigger_instance(context->triggers_sent[0]);
			
			if(!context->triggers_sent[t]){
				printk("ERROR -1 Can't create trigger\n");
				return FINISHED;
			}

			/* register batch-id and send */
			
			trigger_finding_methods[context->trigger_method_id]->
				register_batch_id(context->triggers_sent[t], t + 1);
			
			trigger_finding_methods[context->trigger_method_id]->
				sender_func(this, context->triggers_sent[t]);
			printk("sent little batch\n");

		}
		
		/* set timeout-clock. */
		
		getnstimeofday(&context->timeout_time);
		context->timeout_time.tv_sec += context->timeout.tv_sec;
		timespec_add_ns(&context->timeout_time, context->timeout.tv_nsec);		
		

		context->state = STATE_FIRST_WAIT;		
		return 10000;
		
	}else if(context->state == STATE_FIRST_WAIT){
		
		struct timespec cur_time;
		unsigned int t;

		/* collect results until first timeout is reached. */
		
		struct sniffed_packet_descr_t *descr;
		while((descr = queue_head(this->packets, FALSE))){
			
			
			
			u32 batch_id = trigger_finding_methods[context->trigger_method_id]->
				extract_batch_id(descr);			
			
			if(!batch_id){
				kfree(descr);
				continue;
			}
			
			if(batch_id > context->batch_size ){
				printk("id out of range\n");
				kfree(descr);
				continue;
			}
			
			batch_id -= 1;
			if(batch_id > batch_id + 1){
				printk("detected integer overflow\n");
				kfree(descr);
				continue;
			}
			
			/* for now, we don't really need to know which triggers
			 * actually returned. We're only interested in the number.
			 */

			context->nresponses_first_round++;			
			
		}
				
		getnstimeofday(&cur_time);

		/* return if timeout has not been reached */
		
		if (timespec_compare(&context->timeout_time, &cur_time) > 0)
			return 1000;
		
		/* timeout has been reached */
						
		/* when timeout is reached, send large-packet-burst
		   and enter state STATE_SECOND_WAIT. */
		
		
		for(t = 0; t < context->batch_size; t++){
			trigger_finding_methods[context->trigger_method_id]->
				large_sender_func(this, context->triggers_sent[t]);
		}
		
		printk("sent large batch\n");
		
		
		getnstimeofday(&context->timeout_time);
		context->timeout_time.tv_sec += context->timeout.tv_sec;
		timespec_add_ns(&context->timeout_time, context->timeout.tv_nsec);		
		
		context->state = STATE_SECOND_WAIT;		
		return 1000;
		
		

	}else{
		/* SECOND WAIT */
		struct timespec cur_time;
		
		struct sniffed_packet_descr_t *descr;
		while((descr = queue_head(this->packets, FALSE))){
			
			
			
			u32 batch_id = trigger_finding_methods[context->trigger_method_id]->
				extract_batch_id(descr);			
			
			if(!batch_id){
				kfree(descr);
				continue;
			}
			
			if(batch_id > context->batch_size ){
				printk("id out of range\n");
				kfree(descr);
				continue;
			}
			
			batch_id -= 1;
			if(batch_id > batch_id + 1){
				printk("detected integer overflow\n");
				kfree(descr);
				continue;
			}
			
			/* for now, we don't really need to know which triggers
			 * actually returned. We're only interested in the number.
			 */

			context->nresponses_second_round++;			
			
		}
	
		getnstimeofday(&cur_time);

		/* return if timeout has not been reached */
		
		if (timespec_compare(&context->timeout_time, &cur_time) > 0)
			return 1000;
		

		/* When timeout is reached, analyze all data
		 * collected and output result. */
		
		printk("nresponses_first_round: %d\n", context->nresponses_first_round);
		printk("nresponses_second_round: %d\n", context->nresponses_second_round);
		

		return FINISHED;		
	}

	return FINISHED;
}


struct scan_job_state_t rlimit_detect_state = {
	
	
	.name = "RLIMIT_DETECT",
	.scan_job_manager = &rlimit_detect_scan_job_manager,
	.scan_job_init = &scan_job_init,
	.scan_job_fini = &scan_job_fini,
	.init = &rlimit_detect_state_init,
	.fini = &rlimit_detect_state_fini,
	
	.cmd_handlers = cmd_handlers_hash,

};

/** @} */

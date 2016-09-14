
#include "cmd_handlers.h"
#include "state.h"

#include "../scanner_ui/cmd_handlers.h"
#include "../scanner_ui/scanner_output_queue.h"

#include "../trigger_state/trigger_finding_methods.h"
#include "../trigger_state/trigger_instance.h"

#include "../queue.h"

#include <linux/list.h>
#include <linux/module.h>


/**
   Command: "set_trigger $TARGET_IP $METHOD_NAME"

   On success: None
   On error: ERROR -1 $ERROR_MSG.

   Sets the trigger to be used for the trigger-burst.

*/

void set_trigger_handler(struct command_t *cmd, struct scan_job_t *scan_job)
{
	struct rlimit_detect_state_context *context = 
		(struct rlimit_detect_state_context *) scan_job->state_context;	

	u8 method_id;
	int round;
	
	char **endp = NULL;	

	enum{
		TARGET_IP = 0,
		TRIGGER_METHOD_ID,
		TRIGGER_ROUND,
		NARGS,
	};	

	printk("set_trigger called\n");

	
	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Wrong number of parameters\n");
		scanner_output_queue_flush();
		return;
	}	
	
	method_id = method_id_by_method_name(cmd->argv[TRIGGER_METHOD_ID]);
	round = simple_strtoul(cmd->argv[TRIGGER_ROUND], endp, 10);	

	if(method_id == NO_FINDING_METHOD){
		scanner_output_queue_add("ERROR -1 trigger-type unknown\n");
		scanner_output_queue_flush();
		return;
	}
	
	context->trigger_method_id = method_id;
	context->trigger_round = round;
}


/**
   Not implemented.
*/

void set_timeout_handler(struct command_t *cmd, struct scan_job_t *scan_job)
{	

	enum{
		TARGET_IP = 0,
		TIMEOUT_NS,
		NARGS,
	};
	
	printk("set_timeout called\n");

	
	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Wrong number of parameters\n");
		scanner_output_queue_flush();
		return;
	}	
}

/**
   Command "set_batch_size $TARGET_IP $BATCH_SIZE"
   
   On success: None
   On error: "ERROR -1 $ERROR_MSG"

   Sets the size of the batch, which will be sent to test
   the connection.
   
*/


void set_batch_size_handler(struct command_t *cmd, struct scan_job_t *scan_job)
{
	struct rlimit_detect_state_context *context = 
		(struct rlimit_detect_state_context *) scan_job->state_context;

	char **endp = NULL;

	enum{
		TARGET_IP = 0,
		BATCH_SIZE,
		NARGS,
	};
	
	printk("set_batch_size called\n");

	
	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Wrong number of parameters\n");
		scanner_output_queue_flush();
		return;
	}	
	
	context->batch_size = simple_strtoul(cmd->argv[BATCH_SIZE], endp, 10);
	
}


#include "cmd_handlers.h"
#include "trigger_finding_methods.h"
#include "state.h"

#include "../scanner_ui/cmd_handlers.h"
#include "../scanner_ui/scanner_output_queue.h"

#include "../queue.h"

#include <linux/list.h>
#include <linux/module.h>

#include "icmp_er_method.h"
#include "tcp_syn_method.h"
#include "tcp_ack_method.h"
#include "udp_method.h"


/**
   Command: "append_to_methods_list $TARGET_IP $METHOD_NAME $ROUND"
   
   On success: $TARGET_IP R APPENDED_METHOD $METHOD_NAME $ROUND
   
   On error: ERROR -1 $ERROR_MSG
   
   Adds the trigger-instance uniquely identified by
   (method_name, round) to the list of triggers to try.
   
*/

void append_to_methods_list_handler(struct command_t *cmd,
				    struct scan_job_t *scan_job)
{
	struct trigger_state_context *context =
		(struct trigger_state_context *) scan_job->state_context;
        u8 method_id; 
	int round;

	struct trigger_instance *new_instance;
	char **endp = NULL;
	

	enum {
		TARGET_IP = 0,		
		METHOD_NAME,
		ROUND,
		NARGS
	};

	if(scan_job->active) return;
	
	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Wrong number of parameters\n");
		scanner_output_queue_flush();
		return;
	}
	
		
	method_id = method_id_by_method_name(cmd->argv[METHOD_NAME]);
	round = simple_strtoul(cmd->argv[ROUND], endp, 10);

	if(method_id == NO_FINDING_METHOD)
		return;
	
	new_instance = new_trigger_instance(method_id, round);

	if(!new_instance){
		scanner_output_queue_add("ERROR -1 No memory left\n");
		scanner_output_queue_flush();
		return;
	}	
	
	queue_add(context->trigger_list, new_instance);
	
	
	output_msg_header(cmd->argv[TARGET_IP], "R", "APPENDED_METHOD", FALSE);
	scanner_output_queue_add(" ");
	scanner_output_queue_add(cmd->argv[METHOD_NAME]);
	scanner_output_queue_add(" ");
	scanner_output_queue_add(cmd->argv[ROUND]);
	scanner_output_queue_add("\n");
	scanner_output_queue_flush();
	
}

/**
   Command: "clear_methods_list $TARGET_IP"
   
   On success: $TARGET_IP R CLEARED_METHOD_LIST
   
   On error: ERROR -1 $ERROR_MSG

   clears the list of triggers used.
   
*/


void clear_methods_list_handler(struct command_t *cmd, struct scan_job_t *scan_job)
{
	struct trigger_state_context *context =
		(struct trigger_state_context *) scan_job->state_context;
	
	enum {
		TARGET_IP = 0,		
	};
	
	
	if(scan_job->active){
		scanner_output_queue_add("ERROR -1 Can't clear methods-list. Job is active\n");
		scanner_output_queue_flush();
		return;
	}
	
	queue_clear(context->trigger_list, (delete_data_func) del_trigger_instance);

	output_msg_header(cmd->argv[TARGET_IP], "R", "CLEARED_METHOD_LIST", FALSE);	
	scanner_output_queue_add("\n");
	scanner_output_queue_flush();

}

/**
   Command: "number_of_triggers_wanted $TARGET_IP $NTRIGGERS_WANTED"
   
   On success: $TARGET_IP R NUMBER_OF_TRIGGERS_WANTED
   
   On error: ERROR -1 $ERROR_MSG

   Sets the number of triggers wanted. Once this number of triggers has been
   identified, the trigger-state-scanjob will be finished.
   
*/

void number_of_triggers_wanted_handler(struct command_t *cmd, struct scan_job_t *scan_job)
{
	struct trigger_state_context *context =
		(struct trigger_state_context *) scan_job->state_context;
	char **endp = NULL;

	enum {
		TARGET_IP = 0,		
		NTRIGGERS_WANTED,
		NARGS
	};

	if(scan_job->active) return;

	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Wrong number of parameters\n");
		scanner_output_queue_flush();
		return;
	}
	
	context->ntriggers_to_find = simple_strtoul(cmd->argv[NTRIGGERS_WANTED], endp, 10);

	output_msg_header(cmd->argv[TARGET_IP], "R", "NUMBER_OF_TRIGGERS_WANTED", FALSE);	
	scanner_output_queue_add("\n");
	scanner_output_queue_flush();

}

/**
   Command: "set_method_timeout $TARGET_IP $SECONDS $NSECONDS"
   
   on success: $TARGET_IP R SET_METHOD_TIMEOUT
   On error: ERROR -1 $ERROR_MSG

   Sets the timeout to $SECONDS seconds + $NSECONDS nano-seconds.
   
*/

void set_method_timeout_handler(struct command_t *cmd, struct scan_job_t *scan_job)
{
	struct trigger_state_context *context =
		(struct trigger_state_context *) scan_job->state_context;
	char **endp = NULL;

	enum {
		TARGET_IP = 0,
		SECONDS,
		NSECONDS,
		NARGS
	};

	if(scan_job->active) return;
		
	
	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Wrong number of parameters\n");
		scanner_output_queue_flush();
		return;
	}
	
	
	context->timeout.tv_sec = simple_strtoul(cmd->argv[SECONDS], endp, 10);
	context->timeout.tv_nsec = simple_strtoul(cmd->argv[NSECONDS], endp, 10);
	
	output_msg_header(cmd->argv[TARGET_IP], "R", "SET_METHOD_TIMEOUT", FALSE);	
	scanner_output_queue_add("\n");	
	scanner_output_queue_flush();


}

boolean match_method_id(void *item, void *aux)
{
	struct trigger_instance *item_instance = item;
	u8 *aux_method_id = aux;
	
	return (item_instance->method_id == *aux_method_id);
}


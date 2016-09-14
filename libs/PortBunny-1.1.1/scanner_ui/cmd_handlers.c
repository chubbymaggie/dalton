/* 
        Recurity Labs Port-Scanner kernel-module.
		
	Authors:        Fabian Yamaguchi <fabs@recurity-labs.com>
	
	Descripion:     State-independant command-handlers. This code is part
	                of the scan-job-manager.
		
*/

#include "../scanner_module.h"
#include "../scan_jobs.h"
#include "../scan_job_states.h"
#include "../packet_submitter.h"
#include "../flood_state/state.h"

#include "cmd_handlers.h"
#include "scanner_output_queue.h"

#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/inet.h>

/** retrieve a command-handler by its name */
static struct cmd_handlers_hash_chain_item *
cmd_handlers_hash_get(struct cmd_handlers_hash_bucket *this,
		      const char *key);

/* 
   converts string-state-representations such
   as "TRIGGER" into their numerical ids which are used
   internally.
*/

static int state_str_to_int(const char *state);

/********************** Handlers **********************************/

/**
   
   Command: "create_scanjob $TARGET_IP $STATE"
   
   on success: "$TARGET_IP R SCAN_JOB_CREATED $STATE"
   
   on error:   "ERROR $ERROR_CODE $ERROR_MSG"
   
   
   If the scan-job already exists, nothing is done.
   If it does not, the scan-job is created and added to the
   scan-job-hash.
   
   TODO:
   
   Currently the ip-address passed to this handler
   is not validated. So if somebody enters something other
   than an ip-address, we're fucked. This should definately
   be fixed but this has been delayed.
   
	
*/

void handle_create_scanjob(struct command_t *cmd, struct scan_job_t *unused)
{
	char *target_ip, *state;
	int state_int = -1;
	__be32 target_ip_int;
	
	struct scan_job_t *cur_scan_job;
	char *ip_str;
	
	enum {
		TARGET_IP = 0,
		STATE,
		NARGS
	};
	
	/* process arguments */

	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Not enough parameters\n");
		scanner_output_queue_flush();
		return;
	}
	
	target_ip = cmd->argv[TARGET_IP];
	state     = cmd->argv[STATE];
	
	
	ip_str = kmalloc(sizeof(char) * strlen(target_ip) + 1, GFP_KERNEL);
	if(!ip_str) return;


	state_int = state_str_to_int(state);
	if(state_int == -1){
		kfree(ip_str);
		return;
	}
	
	target_ip_int = in_aton(target_ip);
	strcpy(ip_str, target_ip);
		
	/* arguments are now in target_ip_int and state_int */
			
	/* try adding a scan-job with the desired key to the scan-jobs-hash */
	if((scan_jobs_hash_add(target_ip_int, state_int)) == FAILURE){		
		kfree(ip_str);
		scanner_output_queue_add("ERROR -1 Error creating scanjob\n");
		scanner_output_queue_flush();
		return;
	}
	
	/* retrieve newly created scan-job */
	cur_scan_job = scan_jobs_hash_get(target_ip_int);
	
	if(!cur_scan_job){		
		kfree(ip_str);
		scanner_output_queue_add("ERROR -1 Error creating scanjob\n");
		scanner_output_queue_flush();
		return;
	}
	
	/* Call the state-dependent scan-job-constructor */

	if(scan_job_states[cur_scan_job->state]->scan_job_init(cur_scan_job)
	   == FAILURE){
		/* constructor failed, remove scan-job */
		
		scan_jobs_hash_remove(target_ip_int);
		scanner_output_queue_add("ERROR -1 Error creating scanjob\n");
		scanner_output_queue_flush();
		return;
	}
		
	
	cur_scan_job->addr_str = ip_str;		
	
	output_msg_header(ip_str, "R", "SCAN_JOB_CREATED", FALSE);	
	scanner_output_queue_add(" ");
	scanner_output_queue_add(state);
	scanner_output_queue_add("\n");
	scanner_output_queue_flush();

}

/**
   Command: "execute_scanjob $TARGET_IP"
   
   on success: "$TARGET_IP R SCAN_JOB_EXECUTED"

   on error  : "ERROR $ERROR_CODE $ERROR_MSG"

   
   If the scan-job does not exist, do nothing.
   If it does, add it to the active_scan_jobs_list.
   
   Register scan-job with the packet-submitter.
   
   TODO:
   
   Currently the ip-address passed to this handler
   is not validated. So if somebody enters something other
   than an ip-address, we're fucked. This should definately
   be fixed but this has been delayed.

*/

void handle_execute_scanjob(struct command_t *cmd, struct scan_job_t *unused)
{
	
	char *target_ip;
	struct scan_job_t *scan_job;	

	enum {
		TARGET_IP = 0,
		NARGS
	};

	/* process arguments */

	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Wrong number of parameters\n");
		scanner_output_queue_flush();
		return;
	}

	target_ip = cmd->argv[TARGET_IP];	
	
	/* retrieve the scan-job the user wants to start */
			
	scan_job = scan_jobs_hash_get(in_aton(target_ip));
	
	if(!scan_job){
		scanner_output_queue_add("ERROR -1 execute failed: scan-job does not exist\n");
		scanner_output_queue_flush();
		return;
	}

	
	/* add it to the active_scan_jobs_list
	   if it is not already active.
	   
	   Also, tell the packet-submitter that this scan-job
	   now exists.
	   
	*/
	
	if(scan_job->active != 1)	  
		active_scan_jobs_list_add(scan_job);
	
	
	output_msg_header(target_ip, "R", "SCAN_JOB_EXECUTED", FALSE);
	scanner_output_queue_add("\n");
	scanner_output_queue_flush();
	
}

/**
   
	Command: "pause_scanjob $TARGET_IP
	
	on success: "$TARGET_IP R SCAN_JOB_PAUSED"
	
	on error: "ERROR $ERROR_CODE $ERROR_MSG"
	
	Effect:
	
	If scan-job is not currently active, do nothing.
	If it is, remove it from the active-scan-jobs-queue.

	TODO:
	
	Currently the ip-address passed to this handler
	is not validated. So if somebody enters something other
	than an ip-address, we're fucked. This should definately
	be fixed but this has been delayed.
	
*/

void handle_pause_scanjob(struct command_t *cmd, struct scan_job_t *unused)
{
	char *target_ip;	
	__be32 target_ip_int;
	
	enum {
		TARGET_IP = 0,
		NARGS
	};

	/* process arguments */
	
	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Not enough parameters\n");
		scanner_output_queue_flush();
		return;
	}
	
	target_ip = cmd->argv[TARGET_IP];			
	target_ip_int = in_aton(target_ip);

	/* remove scan-job from active-scan-jobs-list. */

	if( (active_scan_jobs_list_remove(target_ip_int)
	     == SUCCESS )){
		
		
		output_msg_header(target_ip, "R", "SCAN_JOB_PAUSED", FALSE);
		scanner_output_queue_add("\n");
		scanner_output_queue_flush();
	}
	
}


/**
   
   Command : "remove_scanjob $TARGET_IP"
   
   on success: $TARGET_IP R SCAN_JOB_REMOVED

   on error: ERROR -1 $ERROR_MSG

   Effect:
   If scan-job does not exist, does nothing.
   If it does, the scan-job is removed from the
   scan-jobs-hash and the scan-job is deleted.
	
   Also, the packet-submitter is informed about
   the removed scan-job.
   
   TODO:
   
   Currently the ip-address passed to this handler
   is not validated. So if somebody enters something other
   than an ip-address, we're fucked. This should definately
   be fixed but this has been delayed.
   

*/

void handle_remove_scanjob(struct command_t *cmd, struct scan_job_t *unused)
{
	char *target_ip;	
	__be32 target_ip_int;
	boolean removed_scanjob;

	enum {
		TARGET_IP = 0,		
		NARGS
	};

	/* process arguments */
	
	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 not enough parameters\n");
		scanner_output_queue_flush();
		return;
	}
	
	target_ip = cmd->argv[TARGET_IP];			
	target_ip_int = in_aton(target_ip);
		
	removed_scanjob = scan_jobs_hash_remove(target_ip_int);
	
	
	if(!removed_scanjob){
		scanner_output_queue_add("ERROR -1 scanjob not removed because it's either active or non-existant.");
		scanner_output_queue_flush();
	}else{
	
		output_msg_header(target_ip, "R", "SCAN_JOB_REMOVED", FALSE);		
		scanner_output_queue_add("\n");
		scanner_output_queue_flush();
	}
	
}

static int state_str_to_int(const char *state)
{
	if(strcmp(state, "TRIGGER") == 0)
		return SCAN_JOB_STATE_TRIGGER_STATE;
	
	if(strcmp(state, "FLOOD") == 0)
		return SCAN_JOB_STATE_FLOOD_STATE;

	if(strcmp(state, "RLIMIT_DETECT") == 0)
		return SCAN_JOB_STATE_RLIMIT_STATE;
	
	return -1;
}

/******************************************************/

void cmd_handlers_init(struct cmd_handlers_hash_bucket *this)
{
	
	/* Initialize cmd_handlers_hash */
	int t;
	for(t = 0; t < CMD_HASH_SIZE; t++)
		INIT_LIST_HEAD(&this[t].root.list);

}


static u32 cmd_handlers_hash_func(const char *str)
{
	u32 val;
	val = jhash(str, strlen(str), 0);
	val &= (CMD_HASH_SIZE - 1);

	return val;

}


static struct cmd_handlers_hash_chain_item *
cmd_handlers_hash_get(struct cmd_handlers_hash_bucket *this, const char *key)
{
	struct list_head *p;
	struct cmd_handlers_hash_chain_item *item;

	
	u32 hash_val = cmd_handlers_hash_func(key);
	struct cmd_handlers_hash_bucket *bucket = 
		&this[hash_val];
	
	if(list_empty(&bucket->root.list))
		return NULL;

	list_for_each(p, &bucket->root.list){
		item = list_entry(p, struct cmd_handlers_hash_chain_item, list);
		if(strcmp(item->cmd_str, key) == 0){
			/* Handler found. return it. */
			return item;
			
		}

	}

	
	return NULL;
}

static void clear_hash_chain(struct cmd_handlers_hash_chain_item *root)
{
	struct list_head *p, *n;
	
	list_for_each_safe(p, n, &root->list){
		struct cmd_handlers_hash_chain_item *item
			= list_entry(p, struct cmd_handlers_hash_chain_item, list);
		list_del(p);
		kfree(item);
	}
	
}


void cmd_handlers_fini(struct cmd_handlers_hash_bucket *this)
{
	/* Free memory used by cmd-handlers. */
	int t;
	for(t = 0; t < CMD_HASH_SIZE; t++)
		clear_hash_chain(&this[t].root);
}


void cmd_handlers_register(struct cmd_handlers_hash_bucket *this,
			   const char *cmd_name, cmd_handler_func func)
{
	
	/* create a new hash-chain-item */
	struct cmd_handlers_hash_chain_item *new_item =
		kmalloc(sizeof(struct cmd_handlers_hash_chain_item), GFP_KERNEL);

	if(!new_item) return;	
	
	new_item->cmd_str = kmalloc(strlen(cmd_name) + 1, GFP_KERNEL);
	if(!new_item){
		kfree(new_item);
		return;
	}

	strcpy(new_item->cmd_str, cmd_name);
	new_item->func = func;


	/* Add the newly created hash-chain-item to cmd_handlers_hash */
	INIT_LIST_HEAD(&new_item->list);
	list_add_tail(&new_item->list,
		      &this[cmd_handlers_hash_func(cmd_name)].root.list);
	
}

/*********************************************************************/



int cmd_handlers_execute(struct cmd_handlers_hash_bucket *this, struct command_t *cmd)
{
	struct cmd_handlers_hash_chain_item *item =  cmd_handlers_hash_get(this, cmd->name);
	struct scan_job_t *scan_job = NULL;

	if(!item){
		
		/* no state-independent handler found.
		 * There may still be a state-dependent one
		 */

		char *target_ip;		
		
		/* process arguments */
		
		if(cmd->argc < 1) return FAILURE;

		target_ip = cmd->argv[0];		
			
		scan_job = scan_jobs_hash_get(in_aton(target_ip));
		
		/* if scan-job does not exist, return FAILURE*/
		if(!scan_job){
			scanner_output_queue_add("ERROR -1 scan-job does not exist or command unknown\n");
			scanner_output_queue_flush();
			return FAILURE;
		}
		
		/* check if this state provides the desired cmd-handler */
		item = cmd_handlers_hash_get( scan_job_states[scan_job->state]->cmd_handlers,
					      cmd->name);
		
		if(!item){
			scanner_output_queue_add("ERROR -1 command unknown\n");
			scanner_output_queue_flush();
			return FAILURE;
		}

	}
	
	/* execute the command-handler */

	item->func(cmd, scan_job);

	return SUCCESS;

}

void handle_flush_device_file(struct command_t *cmd, struct scan_job_t *unused)
{
	scanner_output_queue_clear();
}

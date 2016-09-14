#ifndef _CMD_HANDLERS_H
#define _CMD_HANDLERS_H

#include "pending_commands_queue.h"
#include "../scan_jobs.h"

/**
   \addtogroup CommandHandlers

   \see FloodStateCommandHandlers, TriggerStateCommandHandlers

   CommandHandlers - This module contains all functions used
   to handle commands of type \ref command_t as well as all
   command-handlers for commands understood by the scan-job-manager
   regardless of the state a given scan-job is in.
   
   For a list of all extra commands supported by flood-state-scanjobs/
   trigger-state-scanjobs

   checkout \ref FloodStateCommandHandlers or
   
   \ref TriggerStateCommandHandlers respectively.
   

   To process commands the scan-job-manager
   polls the \ref PendingCommandsQueue. For each \ref command_t
   structure extracted from the queue, it will call
   \ref cmd_handlers_execute which will lookup the command-handler
   in charge and execute it.
   
@{
*/

#define CMD_HASH_SIZE        256

typedef void (*cmd_handler_func)(struct command_t *cmd, struct scan_job_t *scan_job);

struct cmd_handlers_hash_chain_item{
	struct list_head list;
	char *cmd_str;
	cmd_handler_func func;
};

struct cmd_handlers_hash_bucket{
	struct cmd_handlers_hash_chain_item root;
};


/**
   cmd_handlers_execute:
   
   Effect: Given the provided command 'cmd', execute the handler
   which is in charge of handling the command.
   Return SUCCESS if such a handler exists or FAILURE if it does not.
      
*/


int cmd_handlers_execute(struct cmd_handlers_hash_bucket *this, struct command_t *cmd);


/**
   cmd_handlers_register:
   
   Effect: Register a command-handler.
   
   Arguments: cmd_str: The command's name.
   func:    The handler-function.
   
*/


void cmd_handlers_register(struct cmd_handlers_hash_bucket *this,
			   const char *cmd_name, cmd_handler_func func);

/* initialize command-handling interface */
void cmd_handlers_init(struct cmd_handlers_hash_bucket *this);
/* deinitialize command-handling interface*/
void cmd_handlers_fini(struct cmd_handlers_hash_bucket *this);


/**
   @name CommandHandlers for all ScanJobs (regardless of state)
   @{
*/

void handle_create_scanjob(struct command_t *cmd, struct scan_job_t *unused);
void handle_execute_scanjob(struct command_t *cmd, struct scan_job_t *unused);
void handle_pause_scanjob(struct command_t *cmd, struct scan_job_t *unused);
void handle_remove_scanjob(struct command_t *cmd, struct scan_job_t *unused);

void handle_flush_device_file(struct command_t *cmd, struct scan_job_t *unused);


/** @}  */
/** @}  */

#endif

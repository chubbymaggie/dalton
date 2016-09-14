#ifndef _TRIGGER_STATE_CMD_HANDLERS_H
#define _TRIGGER_STATE_CMD_HANDLERS_H

#include "../scanner_ui/pending_commands_queue.h"
#include "../scan_jobs.h"

/**
   \addtogroup TriggerStateCommandHandlers
   
   @{
*/

void append_to_methods_list_handler(struct command_t *cmd, struct scan_job_t *scan_job);
void clear_methods_list_handler(struct command_t *cmd, struct scan_job_t *scan_job);
void number_of_triggers_wanted_handler(struct command_t *cmd, struct scan_job_t *scan_job);
void set_method_timeout_handler(struct command_t *cmd, struct scan_job_t *scan_job);

/** @} */

#endif

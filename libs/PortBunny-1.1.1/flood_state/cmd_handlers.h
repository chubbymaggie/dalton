#ifndef _FLOOD_STATE_CMD_HANDLERS_H
#define _FLOOD_STATE_CMD_HANDLERS_H

#include "../scanner_ui/pending_commands_queue.h"
#include "../scan_jobs.h"

/**
   \addtogroup FloodStateCommandHandlers
   
   CommandHandlers for commands understood by
   flood-state-scanjobs.
   
   @{
*/

/**
   @name Command Handlers

   @{
*/

void set_ports_to_scan_handler(struct command_t *cmd, struct scan_job_t *scan_job);
void append_to_trigger_list_handler(struct command_t *cmd, struct scan_job_t *scan_job);
void clear_trigger_list_handler(struct command_t *cmd, struct scan_job_t *scan_job);
void set_report_events_handler(struct command_t *cmd, struct scan_job_t *scan_job);
void set_timing_algorithm_handler(struct command_t *cmd, struct scan_job_t *scan_job);


/** @}  */
/** @}  */

#endif

#ifndef _RLIMIT_DETECT_STATE_CMD_HANDLERS_H
#define _RLIMIT_DETECT_STATE_CMD_HANDLERS_H

#include "../scanner_ui/pending_commands_queue.h"
#include "../scan_jobs.h"

void set_trigger_handler(struct command_t *cmd, struct scan_job_t *scan_job);
void set_timeout_handler(struct command_t *cmd, struct scan_job_t *scan_job);
void set_batch_size_handler(struct command_t *cmd, struct scan_job_t *scan_job);

#endif

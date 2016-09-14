#ifndef _TRIGGER_STATE_H
#define _TRIGGER_STATE_H

#include "trigger_finding_methods.h"

#define TRIGGER_DEFAULT_TIMEOUT_S 0
#define TRIGGER_DEFAULT_TIMEOUT_NS 500000000

#define DEFAULT_NTRIGGERS_AT_ONCE 3

/** \addtogroup TriggerStateScanJobManager
    Trigger-state logic - I suggest to start off by reading the
    ScanJobManagerFunction \ref trigger_state_scan_job_manager
    and the \ref trigger_state_context to get a general overview.    

@{
*/

struct trigger_state_context{
	
	/** list of all triggers used by this scan-job */
	struct queue_t *trigger_list;        		
	struct queue_t *active_triggers;	
	
	
	struct timespec timeout_spec;
	struct timespec timeout;	

	unsigned int ntriggers_found;
	
	/** if ntriggers_to_find == 0,
	   find as many as possible. */
	
	unsigned int ntriggers_to_find; 	
	unsigned int ntriggers_at_once;

	boolean got_arp_reply;
	

};

/*
  Export the state-pointer.
*/

extern struct scan_job_state_t trigger_state;

/** @} */

#endif

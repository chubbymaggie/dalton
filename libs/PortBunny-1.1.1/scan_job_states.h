#ifndef _SCAN_JOB_STATE_H
#define _SCAN_JOB_STATE_H

#include <linux/spinlock.h>
#include <linux/list.h>

#include "scan_jobs.h"
#include "sniffer/parse_tree.h"


/**
   \addtogroup ScanJobStates

   When scanning a target, two completely
   different scan-"jobs" (tasks, so to say) have
   to be performed.

   (1) Triggers for the target have to be found.
   
   (2) The target must be port-scanned by making
   use of the triggers found in stage (1).
   
   A scan-job is said to be either in "trigger-state"
   or in "flood-state".

   Both flood-state and trigger-state come into
   existance by "implementing the interface"
   \ref scan_job_state_t.
   
   @{

*/

#define SCAN_JOB_STATE_TRIGGER_STATE         0
#define SCAN_JOB_STATE_FLOOD_STATE           1
#define SCAN_JOB_STATE_RLIMIT_STATE          2
#define N_SCAN_JOB_STATES                    3

/**
   Holds pointers to all currently implemented states.
*/

extern struct scan_job_state_t *scan_job_states[];

struct host_node{
	struct list_head list;
	__be32           host;
};

/**
   Each scan-job-state "implements this interface".   
*/

struct scan_job_state_t
{
	
	/** Name of the state */
	const char *name;

	/** Initialization-function of the state */
	int (*init)(void);
	/** Deinitialization-function of the state */
	void (*fini)(void);
	
	/** Constructor used to construct a scan-job which will
	    run in this state.
	 */
	
	int (*scan_job_init) (struct scan_job_t *this);
	
	/** Destructor for scan-jobs running in this state */

	void (*scan_job_fini) (struct scan_job_t *this);
	
	
	/**
	   
	   the scan-job-manager-function of this state
	   Think of it as the main-function used when
	    running a scan-job in this state.
	    
	    Returns the time in nanoseconds until the
	    scan-job-manager should call the job again.
	    
	*/
	s64 (*scan_job_manager)(struct scan_job_t *this);

	/**
	   A hash-table of commands handled for scan-jobs
	   of the state.
	*/

	struct cmd_handlers_hash_bucket *cmd_handlers;
	
};


int scan_job_states_init(void);
void scan_job_states_fini(void);


/** @} */

#endif

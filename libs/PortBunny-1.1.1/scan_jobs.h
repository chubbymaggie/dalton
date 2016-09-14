#ifndef _SCAN_JOBS_H
#define _SCAN_JOBS_H

#include <linux/spinlock.h>
#include <linux/list.h>

#include "scanner_module.h"
#include "queue.h"

#define SCAN_JOBS_HASH_SHIFT       5
#define SCAN_JOBS_HASH_SIZE        (1 << SCAN_JOBS_HASH_SHIFT)


/** \addtogroup ScanJob
    
    ScanJobs are managed by the ScanJobManager
    and are saved in the ScanJobsHash. Active
    scan-jobs are moved to the active_scanjobs_list
    on execution.

    The behaviour of a scan-job is dependent on its
    state. See \ref ScanJobStates for more information
    on states.
    
@{ 
*/

/**   
      ScanJob-structure held in memory for
      each scan-job, independent of state.
      
*/

struct scan_job_t{
	__be32 addr;
	char *addr_str; 	/** string-representation of addr
				    saved for convinience */
	unsigned int state;
	boolean active;
  
	/* TODO:	   
	   'packets' should use the queue-interface provided
	   in queue.h and it should be cleared when deinitializing
	   the scan-job.
	 
	*/

	/** queue for incoming packets */	
	struct queue_t *packets;		

	/** This pointer may be used by states
	 * to save the context of this scan-job.
	 * Since the type of this context is
	 * state-dependent, we can only use a
	 * void-ptr here :/
	 */
	
	void *state_context; 
};


/**
   Wrapped around a scan-job to allow
   management in kernel-linked-lists.
*/

struct scan_jobs_node{
	struct list_head list;
	struct scan_job_t *scan_job;

};


struct scan_jobs_hash_bucket{
	struct scan_jobs_node root;
};


/**
   @name Interface to ScanJobsHash
   @{
*/

void scan_jobs_hash_init(void);
void scan_jobs_hash_fini(void);
int scan_jobs_hash_add(__be32 addr, unsigned int state);
struct scan_job_t *scan_jobs_hash_get(__be32 addr);
boolean scan_jobs_hash_remove(__be32 addr);

/** @} */

/**
   @name Interface to ActiveScanJobsList
   @{
*/

extern struct scan_jobs_node active_scan_jobs_list;

void active_scan_jobs_list_add(struct scan_job_t *new_node);
struct scan_job_t *active_scan_jobs_list_head(void);
void active_scan_jobs_list_fini(void);
int active_scan_jobs_list_remove(__be32 addr);

/** @} */
/** @} */

#endif

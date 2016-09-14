#ifndef _PBUNNY_SCAN_JOB_MANAGER_H
#define _PBUNNY_SCAN_JOB_MANAGER_H

#include <linux/wait.h>
#include <asm/semaphore.h>

/**
   \addtogroup ScanJobManager

   ScanJobManager

   The ScanJobManager is the central component
   of the system. It processes user-input, newly
   arrived packets and submitter-reports and
   forwards them to the scan-job in question if
   necessary. See the kernel thread's main function
   \ref scan_job_manager for details.

   @{

*/

/**
   @name Public functions
   @{

*/

/**
   Initializes the scan-job-manager.
   
   (1) Initializes all scan-job-states.   
   (2) Initializes command-handlers  
   (3) Initializes scan_jobs_hash   
   (4) Starts the scan-job-manager kernel-thread.
   
*/

int scan_job_manager_init(void);

/**
   deinitializes everything which was initialized
   In scan_job_manager_init
*/

void scan_job_manager_fini(void);



void scan_job_manager_wait_for_termination(void);

/** @}*/


/**
   A pointer to the scan-job-manager's
   task-structure is exported so that
   interrupt-handlers can wake up
   the scan-job-manager-thread by
   using kill_proc.   
*/

extern struct task_struct *scan_job_man_thread;

/**
   @}

*/

extern spinlock_t scan_job_man_thread_lock;


#endif

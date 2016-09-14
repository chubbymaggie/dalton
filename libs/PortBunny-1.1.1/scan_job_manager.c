
#include "scan_job_manager.h"
#include "scan_job_states.h"
#include "scanner_module.h"

#include "scanner_ui/pending_commands_queue.h"
#include "scanner_ui/cmd_handlers.h"
#include "scanner_ui/scanner_output_queue.h"
#include "scanner_ui/scanner_ui.h"

#include "packet_submitter.h"
#include "scan_jobs.h"
#include "queue.h"

#include "sniffer/packet_receiver.h"
#include "sniffer/sniffed_packet.h"

#include "timespec_utils.h"

#include <linux/kthread.h>
#include <linux/delay.h>


struct task_struct *scan_job_man_thread;

/* we actually want to initialize this as locked ... */
spinlock_t scan_job_man_thread_lock = SPIN_LOCK_UNLOCKED;

/* mutex used to make sure the module doesn't
 * unload itsself before the kernel-thread has
 * been deinitialized and has finished.
 */

static __DECLARE_SEMAPHORE_GENERIC(fini_mutex, 0);


/** \addtogroup ScanJobManager
    @{ 
*/

/** hash-table which maps command-names to handler-functions */
struct cmd_handlers_hash_bucket cmd_handlers_hash[CMD_HASH_SIZE];

/** @name Private functions
    @{    
*/

/**   
   Polls the sniffed-packet-queue and forwards packets to
   scan-jobs which may have an interest in the packet.

   This function is part of the scan-job-manager and
   thus runs in user- (as opposed to interrupt-)
   context.
   
   Note that we're using write_lock_bh and
   write_unlock_bh which not only makes use
   of a spinlock to protect the packet-queue
   but also disables interrupts on the processor
   we are running on so that interrupt-handlers
   cannot interrupt us.


*/


static void process_pending_packets(void)
{
	
	/* poll the global 'sniffed-packet-queue' provided by the
	   packet-receiver
	*/
		
	struct queue_t *packet_queue =
		packet_receiver.sniffed_packet_queue;
       	
	struct sniffed_packet_descr_t *packet_descr;
	
	
	/* for each element in packet-queue: */
	write_lock_bh(&packet_queue_lock);
	while((packet_descr = queue_head(packet_queue, FALSE))){
		/* determine sender and forward the packet
		   to the scan-job which handles this host. */
		struct scan_job_t *sj;				

		write_unlock_bh(&packet_queue_lock);		
								
		sj = scan_jobs_hash_get(packet_descr->subject);				
						
		if(!sj){									
			kfree(packet_descr);
			write_lock_bh(&packet_queue_lock);
			continue;
		}				
				
		/* Insert packet into the queue of the scan-job */
		queue_add(sj->packets, packet_descr);		
		
		write_lock_bh(&packet_queue_lock);
	}
		
	write_unlock_bh(&packet_queue_lock);
	
}

/**
   
   For each scan-job in the active_scan_jobs_list,
   execute its scan_job_manager-function.
   
   The scan_job_manager-function's return value will
   indicate whether the scan-job has finished or needs
   to be called again. If it has finished, this function
   removes the scan_job from the scan_jobs_hash and it
   will not be reinserted into the list of
   active scan-jobs.
     
   Return the next time scan-jobs must be processed due
   to timeouts.

*/

static s64 process_active_scan_jobs(void)
{	
	s64 timeout_time;
	s64 smallest_timeout_time = 0;	
	
	struct list_head *p, *n;
	list_for_each_safe(p, n, &active_scan_jobs_list.list){
		struct scan_jobs_node *entry
			= list_entry(p, struct scan_jobs_node, list);
		
		struct scan_job_t *cur_scan_job = 
			entry->scan_job;
				

		/* execute scan-job-manager for the current state */
		
		timeout_time = scan_job_states[cur_scan_job->state]->scan_job_manager(cur_scan_job);
		
		if(timeout_time != FINISHED){
			if(smallest_timeout_time == 0 || timeout_time < smallest_timeout_time)
				smallest_timeout_time = timeout_time;		
			continue;
		}
				

		/* remove scan-job from active-scan-jobs-list */
		entry->scan_job->active = FALSE;
		list_del(&entry->list);
		kfree(entry);
	
		output_msg_header(cur_scan_job->addr_str, "R", "SCAN_JOB_REMOVED", FALSE);				
		/* remove from hash as well. */
		
		scan_jobs_hash_remove(cur_scan_job->addr);		
		scanner_output_queue_add("\n");
		scanner_output_queue_flush();
		
	}			

	return smallest_timeout_time;
	
}

/**
   Handle pending commands

   Polls the pending_commands_queue for commands which were
   received by the scanner-userland-interface and executes
   the associated command-handler-function.  

   Returns TRUE if the scanner should shutdown,
   FALSE otherwise

*/

static boolean process_pending_commands(void)
{
	struct command_t *cmd;	
	
	/* if there are no active scan-jobs, it's allowed
	 * to sleep in the pending_commands_queue_head-call.
	 */
	boolean may_sleep = list_empty(&active_scan_jobs_list.list);

	while((cmd = pending_commands_queue_head(may_sleep))){
		
		
		if(cmd->name && (strcmp(cmd->name, "exit") == 0)){
			delete_command(cmd);
			return TRUE;
		}
		
		printk("cmd->name: %s\n", cmd->name);						
		
		cmd_handlers_execute(cmd_handlers_hash, cmd);
		
		delete_command(cmd);
	
		may_sleep = list_empty(&active_scan_jobs_list.list);
			
	}

	return FALSE;
}


/**
  
  \brief  kernel-thread's main function.
  
  Main-function of the scan-job-manager
  kernel-thread.
  
*/

static int scan_job_manager(void *unused)
{		

	/* After calling daemonize, all signals
	 * will be ignored. */

	daemonize("scan-job-manager");
	
	/* enabled SIGINT so that the scan-job-manager
	 * can be woken up if there are new packets
	 * or user-input.
	 */

	allow_signal(SIGINT);	
	printk("Scan-Job-Manager started\n");
	
	while(!kthread_should_stop()){
		boolean stop;
		s64 next_timeout;		
		
		process_pending_packets();
		next_timeout = process_active_scan_jobs();		
		stop = process_pending_commands();		
		
		if(stop) break;
				
										
		// sleep but allow interruption.
		msleep_interruptible(1);				
		//msleep(1);
	}

		
	scan_job_manager_fini();
	
	spin_lock(&scan_job_man_thread_lock);
	scan_job_man_thread = NULL;
	spin_unlock(&scan_job_man_thread_lock);
	
	printk("Shutting down scan-job-manager\n");
	
	up(&fini_mutex);
	return 0;
}

/** @} */

int scan_job_manager_init(void)
{	

	int ret = scan_job_states_init();
	if(ret != SUCCESS)
		return ret;
	
	cmd_handlers_init(cmd_handlers_hash);
	
	/* now register all cmd-handlers */

	cmd_handlers_register(cmd_handlers_hash, "create_scanjob", &handle_create_scanjob );
	cmd_handlers_register(cmd_handlers_hash, "execute_scanjob", &handle_execute_scanjob );
	cmd_handlers_register(cmd_handlers_hash, "pause_scanjob", &handle_pause_scanjob) ;
	cmd_handlers_register(cmd_handlers_hash, "remove_scanjob", &handle_remove_scanjob);	
	cmd_handlers_register(cmd_handlers_hash, "flush_device_file", &handle_flush_device_file);
	
	scan_jobs_hash_init();

	scan_job_man_thread = kthread_run(&scan_job_manager, NULL, "scan-job-manager");
	
	if(scan_job_man_thread == ERR_PTR(-ENOMEM))
		return FAILURE;
	
	
	spin_unlock(&scan_job_man_thread_lock);
	

	return SUCCESS;
}


void scan_job_manager_fini(void)
{
  	
	/* first make sure no new
	 * commands or packets reach
	 * the scan-job-manager
	 */
	scanner_ui_fini();	
  
	packet_receiver_fini();	
	
	/* Now it's safe to deinit
	   the scan-job-manager
	*/	
		
	active_scan_jobs_list_fini();
	scan_jobs_hash_fini();
	cmd_handlers_fini(cmd_handlers_hash);
	scan_job_states_fini();	

}


void scan_job_manager_wait_for_termination(void)
{
	down(&fini_mutex);
}

/** @} */  /* End ScanJobManager-Group */


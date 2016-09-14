/* 
        Recurity Labs PortBunny kernel-module.
		
	Authors:        Fabian Yamaguchi <fabs@recurity-labs.com>

	Changes:        fabs        :       Initial Revision     28.03.07 
	
	Descripion:     scan_job_hash and active_scan_jobs_list which
	                are the two data-structures used to deal with scan-jobs.
	
	
*/

#include "scan_jobs.h"
#include "scan_job_states.h"
#include "scanner_module.h"
#include "packet_submitter.h"

#include "scanner_ui/scanner_output_queue.h"

#include <linux/hash.h>
#include <linux/module.h>

/* this hash maps (TARGET_IP, STATE)-tuples to scan-jobs. */

static struct scan_jobs_hash_bucket scan_jobs_hash[SCAN_JOBS_HASH_SIZE];

struct scan_jobs_node active_scan_jobs_list = {
	.list = LIST_HEAD_INIT(active_scan_jobs_list.list),
	.scan_job = NULL,
};


void scan_jobs_hash_init()
{
	int t;
	for(t = 0; t < SCAN_JOBS_HASH_SIZE; t++)
		INIT_LIST_HEAD(&scan_jobs_hash[t].root.list);
}

static u32 scan_jobs_hash_func(__be32 addr)
{
	u32 val;
	val = hash_long(addr, SCAN_JOBS_HASH_SHIFT);
	val &= (SCAN_JOBS_HASH_SIZE - 1);

	return val;
}


/*
        clear_list:

         Delete each item of the given list.
         This does not free the associated scan-jobs.
*/

static void clear_list(struct scan_jobs_node *root)
{
	struct list_head *p, *n;
	
	list_for_each_safe(p, n, &root->list){
		struct scan_jobs_node *item
			= list_entry(p, struct scan_jobs_node, list);
		list_del(p);
		kfree(item);
	}

}


void scan_jobs_hash_fini(void)
{
	
	int t;
	struct list_head *p;
	struct scan_jobs_node *item;

	/* Free memory used by scan-jobs */
	for(t = 0; t < SCAN_JOBS_HASH_SIZE; t++){

		
		list_for_each(p, &scan_jobs_hash[t].root.list){
			item = list_entry(p, struct scan_jobs_node, list);
			
			/* call state-dependent destructor on scan-job */
			scan_job_states[item->scan_job->state]->scan_job_fini(item->scan_job);
			
		}
		
		clear_list(&scan_jobs_hash[t].root);
	}
	
}


/*
        scan_jobs_hash_add:
        Adds a new scan-job to the scan_jobs-hash.
	Return SUCCESS/FAILURE.
	
	This function may only be used by the scan-job-manager.
	
*/

int scan_jobs_hash_add(__be32 addr, unsigned int state)
{
	struct scan_job_t *sj;
	struct scan_jobs_node *new_item;

		
	/* Check if this scan-job already exists. */
	
	if( (sj = scan_jobs_hash_get(addr)) != NULL )	
		return FAILURE;
	

	/* Allocate space for new scan-job-item */
	new_item = kmalloc(sizeof(struct scan_jobs_node), GFP_KERNEL);
	if(!new_item)	
		return FAILURE;
	

	
	new_item->scan_job = kmalloc(sizeof(struct scan_job_t), GFP_KERNEL);
	
	if(!(new_item->scan_job)){
		kfree(new_item);
		return FAILURE;
	}
	
	/* initialize new item */

	new_item->scan_job->addr = addr;
	new_item->scan_job->state = state;
	new_item->scan_job->active = 0;

	
	INIT_LIST_HEAD(&new_item->list);
	list_add_tail(&new_item->list,
		      &scan_jobs_hash[scan_jobs_hash_func(addr)].root.list);

	return SUCCESS;
}


/* scan_jobs_hash_get and scan_jobs_hash_remove are very similar and may
 * be merged in the future. */

struct scan_job_t *scan_jobs_hash_get(__be32 addr)
{
	struct list_head *p;
	struct scan_jobs_node *item;

	/* Retrieve correct hash-bucket */
	u32 hash_val = scan_jobs_hash_func(addr);
	struct scan_jobs_hash_bucket *bucket = 
		&scan_jobs_hash[hash_val];

	/* Search hash-bucket */
	if(list_empty(&bucket->root.list))
		return NULL;

	list_for_each(p, &bucket->root.list){
		item = list_entry(p, struct scan_jobs_node, list);
		if( (item->scan_job->addr == addr) )
			return item->scan_job;
	}

	return NULL;
}

/**
   returns TRUE if the scan_job was removed, false
   otherwise.
*/

boolean scan_jobs_hash_remove(__be32 addr)
{
	
	struct list_head *p, *n;
	struct scan_jobs_node *item;	
	
	/* Retrieve correct hash-bucket */
	u32 hash_val = scan_jobs_hash_func(addr);
	struct scan_jobs_hash_bucket *bucket = 
		&scan_jobs_hash[hash_val];
			

	/* Search hash-bucket */
	
	if(list_empty(&bucket->root.list)){
		scanner_output_queue_add("ERROR -1 scan-job does not exist.\n");
		scanner_output_queue_flush();
		return FALSE;
	}

	list_for_each_safe(p, n, &bucket->root.list){
		item = list_entry(p, struct scan_jobs_node, list);
		if (item->scan_job->addr == addr) {
			
			/* Item has been found.*/
			
			/* scanjob is active, don't remove it.*/
			
			if(item->scan_job->active == 1)				
				return FALSE;
						
			
                        /* call state-dependent destructor on scan-job */
			if(item->scan_job->state_context)
				scan_job_states[item->scan_job->state]->scan_job_fini(item->scan_job);
			/* delete item */
			list_del(p);
			kfree(item);	

			return TRUE;
		}
		
	}
	
	return FALSE;
}


/********************************************************************/

/*
  active_scan_jobs_list_add:
  
  Requirements: scan_job is registered in the
                scan_jobs_hash.
		
  Description: add the given scan-job to the active-scan-jobs-list and
               set it's active-attribute to 1.
*/


void active_scan_jobs_list_add(struct scan_job_t *scan_job)
{
	struct scan_jobs_node *new_node =
		kmalloc(sizeof(struct scan_jobs_node), GFP_KERNEL);

	if(!new_node) return;

	new_node->scan_job = scan_job;
	INIT_LIST_HEAD(&new_node->list);
	
	scan_job->active = 1;
	list_add_tail(&new_node->list, &active_scan_jobs_list.list);
}



struct scan_job_t *active_scan_jobs_list_head(void)
{
	struct scan_jobs_node *entry;
	struct scan_job_t *retval;
	
	if(list_empty(&active_scan_jobs_list.list))
		return NULL;

	entry = list_entry( active_scan_jobs_list.list.next,
			    struct scan_jobs_node, list);

	retval = entry->scan_job;

	list_del(&entry->list);
	kfree(entry);

	return retval;

}

/*
  Removing an item from the active-scan-jobs-list
  does not remove the scan-job.
*/

int active_scan_jobs_list_remove(__be32 addr)
{
	struct list_head *p, *n;

	list_for_each_safe(p, n, &active_scan_jobs_list.list){
		struct scan_jobs_node *entry
			= list_entry(p, struct scan_jobs_node, list);
		
		if(entry->scan_job->addr == addr){
		
			/* entry found. kill it. */
			entry->scan_job->active = FALSE;
			list_del(&entry->list);
			kfree(entry);
			return SUCCESS;
		}
		
	}
	return FAILURE;
}


void active_scan_jobs_list_fini(void)
{

	if(list_empty(&active_scan_jobs_list.list))
		return;

	clear_list(&active_scan_jobs_list);
	
}


#include "scanner_output_queue.h"
#include "scanner_ui.h"
#include "../scanner_module.h"
#include "../timespec_utils.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/sched.h>

static DECLARE_RWSEM(queue_lock);

static struct scanner_output_queue_node scanner_output_queue = {
	.lock = &queue_lock,
	.list = LIST_HEAD_INIT(scanner_output_queue.list),
	.str  = NULL,
};


/*
  Stores a copy of str in the queue.
*/

void scanner_output_queue_add(const char *str)
{
	size_t length = strlen(str);

	/* Allocate memory for the new node. */

	struct scanner_output_queue_node *new_node =
		kmalloc(sizeof(struct scanner_output_queue_node), GFP_KERNEL);

	char *kbuf =
		kmalloc(sizeof(char) * (length + 1), GFP_KERNEL);
	
	if( (!new_node) || (!kbuf) )
		return;

	/* Fill node with information. */

	strcpy(kbuf, str);
	INIT_LIST_HEAD(&new_node->list);
	new_node->str = kbuf;
	
	/* add the newly created node to the queue. */

	down_write(scanner_output_queue.lock);
	list_add_tail(&new_node->list, &scanner_output_queue.list);
	up_write(scanner_output_queue.lock);
		
}

void scanner_output_queue_flush(void)
{
	wake_up_interruptible(&inq);
}


/*
  Returns a pointer to a newly allocated string
  containing the content of the head of the output_queue.
  Removes the head.

  If the list is empty, return NULL.

  The functions peforms proper locking using semaphores
  so the caller must not peform any locking.

*/

char *scanner_output_queue_head(void)
{
	struct scanner_output_queue_node *entry;
	size_t entry_length;
	char *ret;

	down_write(scanner_output_queue.lock);

	/* Handle empty list: */

	if(list_empty(&scanner_output_queue.list)){
		up_write(scanner_output_queue.lock);
		return NULL;
	}

	/* Retrieve entry */

	entry = list_entry( scanner_output_queue.list.next,
			    struct scanner_output_queue_node, list);
	
	
	/* Allocate memory for the copy of entry which this function
	   will return.
	*/
	
	entry_length = strlen(entry->str);
	ret = kmalloc(sizeof(char) * entry_length + 1, GFP_KERNEL);
	if(!ret)
		return NULL;

	/* Copy it into newly allocated buffer. */

	strcpy(ret, entry->str);

	/* Remove node */
	kfree(entry->str);
	list_del(&entry->list);
	kfree(entry);
	
	up_write(scanner_output_queue.lock);	
	return ret;
	
}

boolean scanner_output_queue_is_empty(void)
{
	boolean retval;
	down_write(scanner_output_queue.lock);
	retval = list_empty(&scanner_output_queue.list); 	
	up_write(scanner_output_queue.lock);	
	
	return retval;	
}


void output_msg_header(const char *addr_str,
		       const char *event_class,
		       const char *type,
		       boolean output_timestamp)
{
	char buf[512];	
	struct timespec cur_time;	
	
	if(output_timestamp){
		getnstimeofday(&cur_time);
		
		snprintf(buf, sizeof(buf), "%s %s %s %lld", addr_str,
			 event_class, type, timespec_to_ns(&cur_time));
	
	}else{
		snprintf(buf, sizeof(buf), "%s %s %s", addr_str,
			 event_class, type);
	}
	
	buf[sizeof(buf) - 1 ] = '\0';
	scanner_output_queue_add(buf);
	
}


void scanner_output_queue_clear(void)
{

	struct scanner_output_queue_node *entry;

	down_write(scanner_output_queue.lock);
	while (!list_empty(&scanner_output_queue.list)) {
		
		entry = list_entry(scanner_output_queue.list.next,
				   struct scanner_output_queue_node, list);
		
		if(entry->str)
			kfree(entry->str);
		
		list_del(&entry->list);
		kfree(entry);		
	}
	
	up_write(scanner_output_queue.lock);
}

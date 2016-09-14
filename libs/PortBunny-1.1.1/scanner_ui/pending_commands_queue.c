#include "pending_commands_queue.h"
#include "../scan_job_manager.h"

#include <asm/semaphore.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/sched.h>


static DECLARE_RWSEM(queue_lock);
static __DECLARE_SEMAPHORE_GENERIC(queue_empty_lock, 0);

static struct pending_commands_queue_node pending_commands_queue = {
	.lock = &queue_lock,
	.queue_empty = &queue_empty_lock,
	.list = LIST_HEAD_INIT(pending_commands_queue.list),
	.command = NULL,
};


#define DELIMITER ' '

/*
  Maps a command in form of a string to a command_t-structure
  and adds it to the pending-commands-queue.
*/
void pending_commands_queue_add(const char *cmd_str)
{
	struct pending_commands_queue_node *new_node;
	char *cmd_name, **cmd_argv;
	unsigned int cmd_argc;
	size_t cmd_str_length;
	
	char *cmd_str_cp;
	char *arguments_str;

	if(cmd_str == NULL) return;

	cmd_str_length = strlen(cmd_str);
	
        /* Command must at least contain '\n'*/
	if(cmd_str_length < 1) return;

	if(cmd_str[cmd_str_length - 1] != '\n'){
		printk("Warning: command %s rejected because of missing '\\n'\n", cmd_str);
		return;
	}

	/* Since we will now be modifying cmd_str, make a copy to work on.
	  This copy shall not contain the trailing '\n' so the buffer holding it
	  may be one byte shorter.
	*/

	cmd_str_cp = kmalloc(sizeof(char) * (cmd_str_length), GFP_KERNEL);
	if(!cmd_str_cp) return;

	memcpy(cmd_str_cp, cmd_str, cmd_str_length -1);
	cmd_str_cp[cmd_str_length -1 ] = '\0';

	
	/* Create the new pending-commands-queue-node */
	
	new_node = kmalloc(sizeof(struct pending_commands_queue_node), GFP_KERNEL);
	if(!new_node){
		kfree(cmd_str_cp);
		return;
	}

	new_node->command = kmalloc(sizeof(struct command_t), GFP_KERNEL);
	if(!new_node){
		kfree(cmd_str_cp);
		kfree(new_node);
		return;
	}
		

	cmd_argc = 0;
	cmd_argv = NULL;

	arguments_str = strchr(cmd_str_cp, DELIMITER);
	
	if(!arguments_str){
		/* If no arguments were given: */
	  
		cmd_name = cmd_str_cp;
		
	
	}else{
		/* If arguments were given: */
		
		char *tmp;
		int t;
		
		*arguments_str = '\0';
		cmd_name = cmd_str_cp;
		arguments_str++;
		
		tmp = arguments_str;
		
		/* Replace all delimiters with '\0'
		 and count how often this is done. */
		cmd_argc = 1;
		while((tmp = strchr(tmp, DELIMITER))){
			
			
			/* Don't allow two delimiters after another. */
			if(*(tmp - 1) == '\0'){
				
				kfree(cmd_str_cp);
				kfree(new_node);
				return;
			}
			
			cmd_argc++;
			*tmp = '\0';
			tmp++;
		}
		
		/* Create argv-array */
		new_node->command->argv = kmalloc(sizeof(char *) * cmd_argc, GFP_KERNEL);
		if(!(new_node->command->argv)){
			
			kfree(cmd_str_cp);
			kfree(new_node);
			return;
		}

		for(t = 0; t < cmd_argc; t++){
			size_t arg_size = strlen(arguments_str) + 1;
			
			
			new_node->command->argv[t] = kmalloc(sizeof(char) * arg_size, GFP_KERNEL);
			
			/* If there's no memory left: */
			if(!(new_node->command->argv[t])){
				int i;
				for(i = 0; i < t; i++)
					kfree(new_node->command->argv[i]);

				kfree(cmd_str_cp);
				kfree(new_node);
				return;
			}

			memcpy(new_node->command->argv[t], arguments_str, arg_size);
			arguments_str+= arg_size;
			
		}
		
		
	}
	
	/* cmd-str has now been parsed. Now insert the new node into the pending-commands-queue. */

	new_node->command->name = kmalloc(sizeof(char) * (strlen(cmd_name) + 1) , GFP_KERNEL);
	
	if(!(new_node->command->name)){
		int k;
		for(k = 0; k < cmd_argc; k++)
			kfree(new_node->command->argv[k]);
		
		kfree(cmd_str_cp);
		kfree(new_node);
		return;
	}
	
	memcpy(new_node->command->name, cmd_name, strlen(cmd_name) + 1);
	new_node->command->argc = cmd_argc;
	INIT_LIST_HEAD(&new_node->list);
	
	down_write(pending_commands_queue.lock);	
	list_add_tail(&new_node->list, &pending_commands_queue.list);
	up_write(pending_commands_queue.lock);

	up(pending_commands_queue.queue_empty);
	/* wake up scan-job-manager */
	kill_proc(scan_job_man_thread->pid, SIGINT, 1);

}


/*
  Return a pointer to the command contained in the head
  of the queue and remove the head of the queue.
*/

struct command_t *pending_commands_queue_head(boolean may_sleep)
{
	struct pending_commands_queue_node *entry;
	struct command_t *retval;
	boolean was_empty = FALSE;

	down_write(pending_commands_queue.lock);
	
	if(list_empty(&pending_commands_queue.list)){
	  up_write(pending_commands_queue.lock);
		
		if(!may_sleep)
			return NULL;
		
		was_empty = TRUE;
	}
	
	/* sleep until there's a command available */
	
	down(pending_commands_queue.queue_empty);
	
	if(was_empty)
		down_write(pending_commands_queue.lock);

	entry = list_entry( pending_commands_queue.list.next,
			    struct pending_commands_queue_node, list);


	retval = entry->command;
	
	/* remove entry but do not free entry->command */
	list_del(&entry->list);
	kfree(entry);
	
	up_write(pending_commands_queue.lock);
	return retval;

}

void pending_commands_queue_clear(void)
{
	down_write(pending_commands_queue.lock);

	while(!list_empty(&pending_commands_queue.list)){
		struct command_t *cmd = 
			pending_commands_queue_head(FALSE);
		
		if(!cmd)
			break;
		
		delete_command(cmd);				
	}
	
	up_write(pending_commands_queue.lock);
}

void delete_command(struct command_t *this)
{
	int t;
	if(!this)
		return;

	kfree(this->name);
	for(t = 0; t < this->argc; t++)
		kfree(this->argv[t]);

	kfree(this);

}

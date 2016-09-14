#include "trigger_instance.h"
#include "trigger_finding_methods.h"

#include "../scanner_ui/scanner_output_queue.h"

#include <linux/kernel.h>
#include <linux/module.h>

/*
        new_trigger_instance

	Description:
	
	Create a trigger_instance from
	a method_id and an optional round.
	All triggers are uniquely identified by
	a method_id and a round.
	

*/


struct trigger_instance *
new_trigger_instance(u8 method_id, s32 round)
{
	struct trigger_instance *retval;

	/* Create a new node */

	retval = kmalloc(sizeof(struct trigger_instance), GFP_KERNEL);

	if(!retval)
		return retval;

	/* Initialize */

	retval->method_id = method_id;
	retval->round = round;
	
	
	/* Call the context-constructor if it exists. */
	if(trigger_finding_methods[method_id]->context_init)
		trigger_finding_methods[method_id]->context_init(retval, round);
	
	
	
	return retval;

}


/* Destructor */

void del_trigger_instance(struct trigger_instance *this)
{
	/* Call the context-destructor if it exists. */
	if(trigger_finding_methods[this->method_id]->context_fini)
		trigger_finding_methods[this->method_id]->context_fini(this);

	/* free the node */
	kfree(this);
	
}

/**
   Copy-constructor
*/


struct trigger_instance *
copy_trigger_instance(struct trigger_instance *this)
{
  	struct trigger_instance *new_node = 
		kmalloc(sizeof(struct trigger_instance), GFP_KERNEL);

	
	if(!new_node)
		return NULL;

	memcpy(new_node, this, sizeof(struct trigger_instance));

	/* now copy the context */

	if(trigger_finding_methods[this->method_id]->context_copy)
		new_node->context = 
			trigger_finding_methods[this->method_id]->context_copy(this);
	
	return new_node;
	
}

s32 trigger_instance_get_round(struct trigger_instance *this)
{
	return trigger_finding_methods[this->method_id]->get_round(this->context);
}


/**
   trigger_instance_match is used as a
   comparision-function for queue_get_item
   to allow us to retrieve a trigger by
   method_id/round-combination. See
   \rmethod_id_and_round.
*/

boolean trigger_instance_match(void *item, void *a)
{
	struct trigger_instance *item_instance = item;
	struct method_id_and_round *aux = a;
	
	return ( (item_instance->method_id == aux->method_id) &&
		 (item_instance->round == aux->round));
}


/*
  Output a trigger-finding-method-node
  in its textual representation.
*/

void trigger_instance_out(struct trigger_instance *this,
				     struct scan_job_t *job,
				     s32 round)
{
	
	char buf[128];
	
	snprintf(buf, sizeof(buf), "%s R TRIGGER %s %d\n", job->addr_str,
		 trigger_finding_methods[this->method_id]->name,
		 round
		);
	
	scanner_output_queue_add(buf);
	scanner_output_queue_flush();
	
}

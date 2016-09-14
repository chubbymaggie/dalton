#include "trigger_manager.h"

#include "../scanner_ui/scanner_output_queue.h"
#include "../trigger_state/trigger_finding_methods.h"

/**
   Constructor
*/


struct trigger_manager_t *new_trigger_manager(void)
{
	struct trigger_manager_t *this =
		kmalloc(sizeof(struct trigger_manager_t), GFP_KERNEL);

	if(!this) return NULL;
	
	memset(this, 0, sizeof(struct trigger_manager_t));
	
	/* create trigger-list */

	this->trigger_list = create_queue(NULL, GFP_KERNEL, FALSE);
	this->cur_trigger_quality = 0xff;
	
	if(!this->trigger_list){
		kfree(this);
		return NULL;
	}		
	
	return this;

}

/**
   Destructor

*/

void del_trigger_manager(struct trigger_manager_t *this)
{
	
	if(!this) return;

	/* delete list of triggers */	
	delete_queue(this->trigger_list, (delete_data_func) del_trigger_instance);

	kfree(this);
	
}

/**
  Adds a newly allocated trigger-instance of the trigger
  identified by 'method_id' and 'round' to the trigger-list
  given that it meets quality standards the the maximum
  number of triggers has not been reached.

  Note that we do not remove triggers with lower quality as
  we may still be awaiting responses for instances of these
  triggers. Triggers of lower quality will simply be skipped
  in the creation of new trigger-instances (see
  trig_man_get_fresh_trigger_instance).

  Pass in 0xff as quality if you want the function to
  use the default-quality of the trigger.
  
  Returns TRUE if the trigger was added, FALSE otherwise.
  
*/


boolean trig_man_add_trigger(struct trigger_manager_t *this,
			  u8 method_id, int round, u8 quality)
{
	u8 trigger_quality;
	struct trigger_instance *new_instance;
	

	/* check if maximum number of triggers has been reached */
	
	if( ++ this->ntriggers > MAX_TRIGGERS){
		this->ntriggers--;
		return FALSE;
	}
	
	
	/* create new instance */
	
	new_instance = new_trigger_instance(method_id, round);	
	if(!new_instance)		
		return FALSE;
	
	
	/* add trigger only if it meets quality standards
	   and assure that trigger-quality is updated accordingly
	*/
	
	/* if user has specified quality, use it.*/

	if(quality == 0xff)
		trigger_quality = trigger_finding_methods[method_id]->get_default_quality();
	else
		trigger_quality = quality;

	if( trigger_quality <= this->cur_trigger_quality){	
		this->cur_trigger_quality = trigger_quality;		
		queue_add(this->trigger_list, new_instance);
	}else
		del_trigger_instance(new_instance);
	
	
	return TRUE;
}

/**
   
   Returns a newly allocated copy of the first trigger in the
   trigger-list, which meets quality standards. The original
   is then added to the back of the trigger-list so that this
   function will return another trigger when executed next time.
   

*/

struct trigger_instance *
trig_man_get_fresh_trigger_instance(struct trigger_manager_t *this)
{
	unsigned int p = 0;
	unsigned int q_length = queue_length(this->trigger_list);

	struct trigger_instance *new_instance;
	struct trigger_instance *instance_to_copy;

	while(p++ <= q_length){
		
		instance_to_copy = queue_head(this->trigger_list, FALSE);

		if(!instance_to_copy){
			scanner_output_queue_add("ERROR -1 No trigger available to create batch\n");
			return NULL;
		}
		
		
		/* only use trigger if it meets quality standards. */
		if(instance_to_copy->quality <= this->cur_trigger_quality)
			break;
		
		queue_add(this->trigger_list, instance_to_copy);
		instance_to_copy = NULL;
	}
	
	if(!instance_to_copy){
		scanner_output_queue_add("ERROR -1 No trigger fullfills quality standards\n");
		return NULL;
	}

	/* copy trigger-instance */
	
	new_instance = copy_trigger_instance(instance_to_copy);	
	
	/* add initial trigger-instance to the back of the queue. */
	queue_add(this->trigger_list, instance_to_copy);
	
	return new_instance;

	
}

/**
  Iterate the list of triggers and call each
  triggers extract_batch_id-method on the packet
  until one of them returns a non-zero batch-id.

  If no trigger-method matches, NO_FINDING_METHOD
  is returned.
  
*/


u8 trig_man_get_method_id(struct trigger_manager_t *this,
			  struct sniffed_packet_descr_t *descr)
{
	struct queue_node_t *root = get_root(this->trigger_list);
	struct list_head *p;
	
	/* iterate all triggers in use to see if one matches:
	 * This loop is another reason to limit the maximum
	 * number of extra triggers to use.
	 */
	

	list_for_each(p, &root->list){
		struct queue_node_t *entry = 
			list_entry(p, struct queue_node_t, list);
		struct trigger_instance *trigger = entry->data;
		u8 method_id = trigger->method_id;
		
		u32 batch_id = 
			trig_man_get_batch_id(this, descr, method_id);
		
		if(batch_id)
			return method_id;		
	}
	
	return NO_FINDING_METHOD;
	
}

u32 trig_man_get_batch_id(struct trigger_manager_t *this,
			  struct sniffed_packet_descr_t *descr,
			  u8 method_id)
{
	return trigger_finding_methods[method_id]->extract_batch_id(descr);
}

/**
  Sets the quality-parameter of the trigger-instance, which first matches
  method-id-and-round to 'quality'.
  
*/


void trig_man_set_quality_of_instance(struct trigger_manager_t *this,
				      struct method_id_and_round *m_and_r,
				      u8 quality)
{
	struct trigger_instance *instance = 
		queue_get_item(this->trigger_list, trigger_instance_match,
			       m_and_r);
	
	if(!instance) return;
	instance->quality = quality;	
}


void trig_man_clear_trigger_list(struct trigger_manager_t *this)
{
	queue_clear(this->trigger_list, (delete_data_func) del_trigger_instance);
	this->cur_trigger_quality = 0xff;
	this->ntriggers = 0;

}

#ifndef _TRIGGER_FINDING_METHOD_NODE
#define _TRIGGER_FINDING_METHOD_NODE

#include <linux/list.h>
#include <linux/time.h>

#include "../scan_jobs.h"

/**
        trigger_instance
                
	A trigger_instance is an
	instance of a trigger_finding_method.

*/

struct trigger_instance{
		
	u8 method_id;			
	s32 round;

	u8 quality;
	void *context;

};

/**
   To be able to extract the trigger with
   a specified method_id and round using
   queue_get_item, we supply the below
   structure which is used in conjunction
   with match_method_id_and_round.
  
*/


struct method_id_and_round{
	u8 method_id;
	s32 round;
};

/* Constructor */
struct trigger_instance *
new_trigger_instance(u8 method_id, s32 round);

/* Output-operator */
void trigger_instance_out(struct trigger_instance *this,
				     struct scan_job_t *job,
				     s32 round);

s32 trigger_instance_get_round(struct trigger_instance *this);

/* Copy-constructor */

struct trigger_instance *
copy_trigger_instance(struct trigger_instance *this);


/* Comparision-function */
boolean trigger_instance_match(void *item, void *a);


/* Destructor */
void del_trigger_instance(struct trigger_instance *this);

#endif

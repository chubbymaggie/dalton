#ifndef _TRIGGER_MANAGER_HPP
#define _TRIGGER_MANAGER_HPP

#include "../queue.h"

#include "../sniffer/sniffed_packet.h"
#include "../trigger_state/trigger_instance.h"

#define MAX_TRIGGERS          40

/*
  Maintains the list of triggers in
  use and gives out new trigger-instances
  on demand. This could have also been called
  the 'trigger-instance-factory' but that
  would have been even longer.
*/


struct trigger_manager_t{
	
	u8 cur_trigger_quality;
	u32 ntriggers;
	struct queue_t *trigger_list;
	
};


struct trigger_manager_t *new_trigger_manager(void);
void del_trigger_manager(struct trigger_manager_t *this);

boolean trig_man_add_trigger(struct trigger_manager_t *this,
			     u8 method_id, int round, u8 quality);

struct trigger_instance *
trig_man_get_fresh_trigger_instance(struct trigger_manager_t *this);

u8 trig_man_get_method_id(struct trigger_manager_t *this,
			  struct sniffed_packet_descr_t *descr);

u32 trig_man_get_batch_id(struct trigger_manager_t *this,
			  struct sniffed_packet_descr_t *descr,
			  u8 method_id);

void trig_man_set_quality_of_instance(struct trigger_manager_t *this,
				      struct method_id_and_round *m_and_r,
				      u8 quality);

void trig_man_clear_trigger_list(struct trigger_manager_t *this);


#endif

#include "sniffed_packet.h"

#include <linux/module.h>

/**
   Constructor
   
*/

struct sniffed_packet_descr_t *new_sniffed_packet_descr(void)
{

	struct sniffed_packet_descr_t *descr;
	
	descr = kmalloc(sizeof(struct sniffed_packet_descr_t), GFP_ATOMIC);
	if(!descr)
		return NULL;
	
	memset(descr, 0, sizeof(struct sniffed_packet_descr_t));
	
	return descr;

	
}

void del_sniffed_packet_descr(struct sniffed_packet_descr_t *this)
{
	if(!this) return;
	kfree(this);
}

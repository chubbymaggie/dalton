#include "state.h"
#include "trigger_finding_methods.h"

#include "../scanner_module.h"
#include "../packet_submitter.h"
#include "../queue.h"


#include <linux/module.h>
#include <linux/list.h>

#include "tcp_syn_method.h"
#include "tcp_ack_method.h"
#include "icmp_er_method.h"
#include "icmp_ts_method.h"
#include "icmp_addr_mask_method.h"
#include "udp_method.h"
#include "ip_prot_method.h"


/**
   
   Lookup method-id by method-name.
   The method-id is the index of the
   trigger_finding_methods-array used to
   reference the trigger-finding-method.

*/ 

int method_id_by_method_name(const char *name)
{
	int t;
	for(t = 0; t < N_FINDING_METHODS; t++)
		if(strcmp(trigger_finding_methods[t]->name, name) == 0)
			return t;

	return NO_FINDING_METHOD;
}


/*
	This array maps triggger-finding-method-ids to
	trigger-finding-method-structures.
*/

struct trigger_finding_method *trigger_finding_methods[] = {
	
	&icmp_er_method,
	&icmp_ts_method,
	&icmp_addr_mask_method,
	&udp_method,
	&tcp_syn_method,
	&tcp_ack_method,
	&ip_prot_method,
	
};

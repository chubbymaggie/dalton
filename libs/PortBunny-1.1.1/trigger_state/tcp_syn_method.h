#ifndef _TCP_SYN_FINDING_METHOD_H
#define _TCP_SYN_FINDING_METHOD_H

#include "trigger_finding_methods.h"

#define TCP_SYN_NEG_QUALITY  0  /* quality of a negative tcp-syn trigger*/
#define TCP_SYN_POS_QUALITY  1  /* quality of a positive tcp-syn-trigger*/

struct tcp_syn_context{
		
	u16 port;	
	u32 batch_id;
	u16 src_port;
	

};

extern struct trigger_finding_method tcp_syn_method;

#endif

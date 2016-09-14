#ifndef _TCP_ACK_FINDING_METHOD_H
#define _TCP_ACK_FINDING_METHOD_H

#include "trigger_finding_methods.h"

#define TCP_ACK_QUALITY 0 

struct tcp_ack_context{
		
	u16 port;
	
	u32 batch_id;
	u16 src_port;
		
};

extern struct trigger_finding_method tcp_ack_method;

#endif

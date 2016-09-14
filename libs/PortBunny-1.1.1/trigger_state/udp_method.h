#ifndef _UDP_FINDING_METHOD_H
#define _UDP_FINDING_METHOD_H

#include "trigger_finding_methods.h"

#define UDP_QUALITY 3

struct udp_context{
		
	u16 port;	
	u32 data;
	
};

extern struct trigger_finding_method udp_method;

#endif

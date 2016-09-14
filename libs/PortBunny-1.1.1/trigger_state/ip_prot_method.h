#ifndef _IP_PROT_FINDING_METHOD_H
#define _IP_PROT_FINDING_METHOD_H

#include "trigger_finding_methods.h"

#define IP_PROT_QUALITY 3

struct ip_prot_context{
	
	u8 protocol;
	u32 data;		
	
};

extern struct trigger_finding_method ip_prot_method;

#endif

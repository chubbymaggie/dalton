#ifndef _ICMP_ADDR_MASK_FINDING_METHOD_H
#define _ICMP_ADDR_MASK_FINDING_METHOD_H

#include "trigger_finding_methods.h"

#define ICMP_ADDR_MASK_QUALITY 2

struct icmp_addr_mask_context{
	u32 batch_id;	
};

extern struct trigger_finding_method icmp_addr_mask_method;

#endif

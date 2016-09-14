#ifndef _ICMP_TS_FINDING_METHOD_H
#define _ICMP_TS_FINDING_METHOD_H

#include "trigger_finding_methods.h"

#define ICMP_TS_QUALITY 2

struct icmp_ts_context{
	u32 batch_id;
};

extern struct trigger_finding_method icmp_ts_method;

#endif

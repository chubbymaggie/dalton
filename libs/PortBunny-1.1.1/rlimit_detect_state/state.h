#ifndef _RLIMIT_DETECT_STATE_H
#define _RLIMIT_DETECT_STATE_H

#include "../trigger_state/trigger_finding_methods.h"

#define RLIMIT_DEFAULT_TIMEOUT_S 2
#define RLIMIT_DEFAULT_TIMEOUT_NS 0
#define RLIMIT_DEFAULT_BATCH_SIZE 50

//#define RLIMIT_DEFAULT_METHOD_ID  ICMP_ER_FINDING_METHOD
//#define RLIMIT_DEFAULT_ROUND      0

#define RLIMIT_DEFAULT_METHOD_ID  TCP_SYN_FINDING_METHOD
#define RLIMIT_DEFAULT_ROUND      81

#define STATE_INIT           0
#define STATE_FIRST_WAIT     1
#define STATE_SECOND_WAIT    2


struct rlimit_detect_state_context{
	
	unsigned int batch_size;
	
	u8 trigger_method_id;
	int trigger_round;
	
	struct timespec timeout;
	
	
	unsigned int state;		
	struct trigger_instance **triggers_sent;	
	unsigned int nresponses_first_round;
	unsigned int nresponses_second_round;
	
	struct timespec timeout_time;

};

/*
  Export the state-pointer.
*/

extern struct scan_job_state_t rlimit_detect_state;

/** @} */

#endif

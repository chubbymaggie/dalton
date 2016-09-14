
#ifndef _PBUNNY_TCP_BIC_H
#define _PBUNNY_TCP_BIC_H

#include "timing.h"

#define BIC_LOW_WINDOW       (12 * CWND_BLOWUP_FACTOR)
#define BIC_SMAX             (32 * CWND_BLOWUP_FACTOR)
#define BIC_DEFAULT_MAX_WIN  (9000 * CWND_BLOWUP_FACTOR)

struct tcp_bic_state
{	
	s64 last_max_cwnd;		
	s64 max_cwnd;
	s64 min_cwnd;
	s64 target_cwnd;	
	
	s64 ss_cwnd;
	s64 ss_target;
	
	boolean bic_slow_start;
	
};

#define BIC_INITIAL_CWND                        (2 * CWND_BLOWUP_FACTOR)
#define BIC_INITIAL_CCTHRESH                    (20 * CWND_BLOWUP_FACTOR)

#define BIC_DEFAULT_BATCH_TIMEOUT_NS 1000000000 /* 1s */
#define BIC_DEFAULT_BATCH_SIZE       9

extern struct timing_algo tcp_bic;

#endif

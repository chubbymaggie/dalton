#ifndef _PBUNNY_TCP_VEGAS_H
#define _PBUNNY_TCP_VEGAS_H

#include "timing.h"


struct tcp_vegas_state
{	
	s64 ack_counter_at_start;
	s64 cwnd_at_start; /* [packets] * CWND_BLOWUP_FACTOR */
	
	u8 doing_vegas_now;	
	
	u16 cntRTT; /* number of rtt-samples collected since last reset */
	s64 minRTT; /* minimum rtt during the last rtt.
		     * This decides how we adjust cwnd.
		     */
	
	s64 baseRTT; /* propagation-delay */
};

#define VEGAS_INITIAL_CWND                        (2 * CWND_BLOWUP_FACTOR)
#define VEGAS_INITIAL_CCTHRESH                    (20 * CWND_BLOWUP_FACTOR)

#define VEGAS_DEFAULT_BATCH_TIMEOUT_NS 1000000000 /* 1s */
#define VEGAS_DEFAULT_BATCH_SIZE       9

extern struct timing_algo tcp_vegas;

#endif

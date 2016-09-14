#include "timing.h"

#include "tcp_reno.h"
#include "tcp_scalable.h"
#include "tcp_vegas.h"
#include "tcp_bic.h"

/**
   Array of available timing-algorithms.
*/



struct timing_algo *timing_algorithms[] = 
{
	&tcp_reno,
	&tcp_scalable,
	&tcp_vegas,
//	&tcp_bic,
};


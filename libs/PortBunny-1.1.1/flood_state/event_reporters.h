#ifndef _EVENT_REPORTERS_H
#define _EVENT_REPORTERS_H

#include "../scan_jobs.h"
#include "../trigger_state/trigger_finding_methods.h"

/**
   @name FloodStateEvents
   @{
   
   The scanner-front-end may
   request to be informed of
   any of the events listed below
   so that it can expose this
   information to the user.  
*/

/** @} */

void output_trigger_added_event(struct scan_job_t *this,
				int port);


void output_timeout_info(struct scan_job_t *this);

void output_cwnd_updated_event(struct scan_job_t *this);

void output_trigger_received_event(struct scan_job_t *this, int method_id, int round,
				   struct timespec *rtt);

void output_dropped_trigger_event(struct scan_job_t *this, int method_id, int round);

void output_rate_limiter_detected(struct scan_job_t *this);

#endif

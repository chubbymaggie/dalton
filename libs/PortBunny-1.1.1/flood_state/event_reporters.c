
#include "event_reporters.h"
#include "state.h"
#include "net_info_keeper.h"
#include "../scanner_ui/scanner_output_queue.h"

#include "../timespec_utils.h"

/**
   @name Output-functions for events
   @{
*/

/**
   

*/

/*
  Outputs the following information about the scanner's state:
  
  CWND CCTHRESH TIMEOUT RTT_AVERAGE RTT_DEVIATION LATEST_RTT_SAMPLE
 */

static void output_scanner_state(struct scan_job_t *this)
{
	char num_buf[128];
	struct flood_state_context *context = 
		this->state_context;		
	
	s64 deviation = context->net_info_keeper->rtt_deviation;	
	s64 average = context->net_info_keeper->rtt_average;			
	s64 latest_rtt = context->net_info_keeper->latest_rtt_sample;
	
	sprintf(num_buf, " %lld", context->timing_context.cur_cwnd);
	scanner_output_queue_add(num_buf);	
	
	sprintf(num_buf, " %lld", context->timing_context.cur_ccthresh);
	scanner_output_queue_add(num_buf);	
	
	sprintf(num_buf, " %lld", context->timing_context.cur_timeout);
	scanner_output_queue_add(num_buf);	
	
	sprintf(num_buf, " %lld", average);
	scanner_output_queue_add(num_buf);

	sprintf(num_buf, " %lld", deviation);
	scanner_output_queue_add(num_buf);	

	sprintf(num_buf, " %lld", latest_rtt);
	scanner_output_queue_add(num_buf);		
	
}

void output_trigger_added_event(struct scan_job_t *this,
				int port)
{
	struct flood_state_context *context = 
		this->state_context;		
	
	char num_buf[128];
	
	if(!(context->report_events))
		return;
	
	output_msg_header(this->addr_str, "I", "TRIGGER_ADDED", TRUE);	
	
	output_scanner_state(this);
	
	scanner_output_queue_add(" TCP_SYN");
	sprintf(num_buf, " %d ", port);
	scanner_output_queue_add(num_buf);		
	scanner_output_queue_add("\n");
	scanner_output_queue_flush();

}


void output_trigger_received_event(struct scan_job_t *this, int method_id, int round,
				   struct timespec *rtt)
{
	
	char num_buf[128];			
	
	struct flood_state_context *context = 
		this->state_context;		
	
	if(!(context->report_events))
		return;
	
		
	output_msg_header(this->addr_str, "I", "TRIGGER_RECEIVED", TRUE);
	
	output_scanner_state(this);
	
	scanner_output_queue_add(" ");
	scanner_output_queue_add(trigger_finding_methods[method_id]->name);
	sprintf(num_buf, " %d", round);
	scanner_output_queue_add(num_buf);
	scanner_output_queue_add("\n");
	scanner_output_queue_flush();
	
}

void output_dropped_trigger_event(struct scan_job_t *this, int method_id, int round)
{
	
	char num_buf[128];
	
	output_msg_header(this->addr_str, "I", "TRIGGER_DROPPED", TRUE);
	
	output_scanner_state(this);	
	scanner_output_queue_add(" ");
	scanner_output_queue_add(trigger_finding_methods[method_id]->name);
	sprintf(num_buf, " %d", round);
	scanner_output_queue_add(num_buf);		
	scanner_output_queue_add("\n");
	scanner_output_queue_flush();
}

void output_rate_limiter_detected(struct scan_job_t *this)
{	
	output_msg_header(this->addr_str, "I", "RATE_LIMITER", FALSE);	
	output_scanner_state(this);
	scanner_output_queue_add("\n");
	scanner_output_queue_flush();
}

/** @} */

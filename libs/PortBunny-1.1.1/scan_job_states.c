/* 
        Recurity Labs Port-Scanner - States
			
	Authors:        Fabian Yamaguchi <fabs@recurity-labs.com>

	Changes:        fabs        :       Initial Revision     28.03.07 
	
	
*/


#include "scan_job_states.h"
#include "scanner_module.h"
#include "trigger_state/state.h"
#include "flood_state/state.h"
#include "rlimit_detect_state/state.h"

#include <linux/spinlock.h>


struct scan_job_state_t *scan_job_states[] = {
	&trigger_state,
	&flood_state,
	&rlimit_detect_state,	
};


/** 
    Calls the state-provided initialization-routines.    
*/

int scan_job_states_init(void)
{
	
	int t, ret;
	for(t = 0; t < N_SCAN_JOB_STATES; t++)
		if((ret = scan_job_states[t]->init()) != SUCCESS)
			return ret;
	return SUCCESS;
}


/**
   Calls the state-provided deinitialization-routines.
*/

void scan_job_states_fini(void)
{
	int t;
	for(t = 0; t < N_SCAN_JOB_STATES; t++)
		scan_job_states[t]->fini();
}


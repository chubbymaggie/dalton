
#include "cmd_handlers.h"
#include "state.h"
#include "batch_creator.h"
#include "timing/timing.h"
#include "../scanner_module.h"
#include "../scanner_ui/cmd_handlers.h"
#include "../scanner_ui/scanner_output_queue.h"
#include <linux/list.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

/**
   \addtogroup FloodStateCommandHandlers
   
   @{
*/

/*
  
  All of the handlers below shall only be called
  to configure a not yet active scan-job.
  Don't run this on an active scan-job!
   

*/


struct port_range_t {
	unsigned int start_port;
	unsigned int  end_port;
};


/**
   Command: "set_ports_to_scan $TARGET_IP $PORT_EXPR1 ... $PORT_EXPRn"
   e
   on success: no response
   on error: "ERROR $ERROR_CODE $ERROR_MSG"
   
   Port-Expressions :
   
   A port-expression may either be a port number or
   a port range. Valid port-expressions are:
   
   "80" or "21-25".
   
   Effect:  
   
   A port-result-structure will be allocated
   and initialized for each port
   and it will be registered with the given scan-job.	
   
*/

void set_ports_to_scan_handler(struct command_t *cmd, struct scan_job_t *scan_job)
{
	
	
	struct flood_state_context *context =
		(struct flood_state_context *) scan_job->state_context;
	

	int new_nports;
	u16 *new_ports;	
	unsigned int biggest_port_num = 0;		
	int t, i;	
	
	
	struct port_range_t **port_ranges;
	char **endp = NULL;

	int nport_expressions = cmd->argc - 1;
	
	/* nothing to be done if no ports were specified. */
	if(nport_expressions < 1) return;

	
	/* initialize port_ranges-array */

	port_ranges = vmalloc(sizeof(struct port_range_t *) * nport_expressions);
	
	if(!port_ranges){
		scanner_output_queue_add("ERROR -1 Out of memory\n");
		scanner_output_queue_flush();
		return;
	}
	
	memset(port_ranges, 0, sizeof(struct port_range_t *) *nport_expressions );
		

	/*
	  
	  Iterate through all port-expressions and save the number
	  of ports we must scan in new_nports and each port-range in
	  port_ranges[t].
	
	*/
	

	new_nports = 0;

	for(t = 0; t < nport_expressions; t++){
		
		char *arg = cmd->argv[t + 1];
		char *hyphen_pos;
		struct port_range_t *cur_port_range;

		
		/* if there's no hyphen, this is
		 * not a range of ports. So just increase 
		 * new_nports by one and go on to handle the
		 * next port-expression. */
		
		if(! (hyphen_pos = strchr(arg, '-'))){
			/* Single port found */
			new_nports++;
			continue;
		}		

		/* a hyphen has been found. create a new port-range-
		 * structure: */
		
		cur_port_range = kmalloc(sizeof(struct port_range_t), GFP_KERNEL);
		
		if(!cur_port_range){
			scanner_output_queue_add("ERROR -1 Out of memory\n");
			scanner_output_queue_flush();
			vfree(port_ranges);
			return;
		}
		

		

		/* create port-range-structure from port-expression */
		*hyphen_pos = '\0'; hyphen_pos++;
		cur_port_range->end_port = simple_strtoul(hyphen_pos, endp, 10);
		cur_port_range->start_port = simple_strtoul(arg, endp, 10);		
		port_ranges[t] = cur_port_range;				
		
		/* and restore argument */
		hyphen_pos--;
		*hyphen_pos = '-';
		
		/* Don't allow start-port to be bigger than end-port */

		if(cur_port_range->start_port > cur_port_range->end_port){
			
			port_ranges[t] = NULL;
			kfree(cur_port_range);
			continue;
		}
		
		/* increase new_nports by the number of ports in the port-range */
		
		new_nports +=
			cur_port_range->end_port - cur_port_range->start_port + 1;
				
	}
		

	/* Now that we know the number of ports we will scan, allocate memory
	 * for each port. */
	
	printk("new_nports: %d\n", new_nports);

	new_ports = vmalloc(sizeof(u16) * new_nports);
	
	if( !new_ports ){
		scanner_output_queue_add("ERROR -1 Out of memory\n");
		scanner_output_queue_flush();
		return;
	}
	
		
	/* Copy ports into newly allocated array */
	
	//printk("reached copy-loop\n");
	
	i = 0;
	for(t = 0; t < new_nports; t++){		
		
		/* Just a single port. */
		if(!port_ranges[i])			
			new_ports[t] = simple_strtoul(cmd->argv[i+1], endp, 10);
		else{
			/* A port-range.*/
			
			unsigned int port;		
			for(port = port_ranges[i]->start_port;
			    port <= port_ranges[i]->end_port; port++)
				new_ports[t++] = port;			
		
			t--;
		}				
		
		i++;
	}
	
	
	/* Calculate the biggest port */
	for(t = 0; t < new_nports; t++){
		
		/* Detect request to scan port 0 */
		if(new_ports[t] == 0){
			scanner_output_queue_add("ERROR -1 Request to scan port 0\n");
			scanner_output_queue_flush();
			vfree(new_ports);
			return;
		}
		
		if(biggest_port_num < new_ports[t])
			biggest_port_num = new_ports[t];
	}
	
	/* make sure we're not accepting ports above the highest
	 * port-number.
	 */
	
	if(biggest_port_num > 65535){
		scanner_output_queue_add("ERROR -1 Requested to scan a port above 65535\n");
		scanner_output_queue_flush();
		
		/* now free port_ranges */
		for(t = 0; t < nport_expressions; t++)
			if(port_ranges[t])
				kfree(port_ranges[t]);
		
		vfree(port_ranges);
		vfree(new_ports);	
		
		return;
	}


	/* free old ports_to_scan array if any. */

	if(context->ports_to_scan){
		
		for(t = 0; t < context->port_array_size; t++)
			if(context->ports_to_scan[t])
				delete_port_result(context->ports_to_scan[t]);
		
		
		vfree(context->ports_to_scan);
	
	}
	
	/* create new ports_to_scan-array */

	context->nports_to_scan = new_nports;
	context->ports_to_scan = vmalloc(sizeof(struct port_result *) * (biggest_port_num + 1));
	
	if(!context->ports_to_scan)
		return;

	memset(context->ports_to_scan, 0, sizeof(struct port_result *) * (biggest_port_num + 1));	

	/* Create port-result-structures for each port which is to
	 * be scanned.
	 */
	
	context->port_array_size = biggest_port_num + 1;

	for(t = 0; t < new_nports; t++){
		
		if(!context->ports_to_scan[new_ports[t]])
			context->ports_to_scan[new_ports[t]] = create_port_result(new_ports[t]);
		
		if(!context->ports_to_scan[new_ports[t]])
			return;

	}
	
	
	/* now free port_ranges */
	for(t = 0; t < nport_expressions; t++)
		if(port_ranges[t])
			kfree(port_ranges[t]);
	
	vfree(port_ranges);
	vfree(new_ports);	

}

/**   
   Command: "append_to_trigger_list $TARGET_IP $TRIGGER_METHOD $TRIGGER_ROUND"
   
   on success: no response
   on error  : "ERROR $ERROR_CODE $ERROR_MSG"
      
   Effect:
	
   Creates a new trigger_instance of the desired
   type and adds it to the list of triggers which will be used
   in the scanning-process.
   
*/

void append_to_trigger_list_handler(struct command_t *cmd, struct scan_job_t *scan_job)
{
	struct flood_state_context *context =
		(struct flood_state_context *) scan_job->state_context;
		
	u8 method_id;
	int round;	
	
	char **endp = NULL;
	

	enum{
		TARGET_IP,
		METHOD_NAME,
		METHOD_ROUND,
		NARGS
	};

	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Wrong number of parameters\n");
		scanner_output_queue_flush();
		return;
	}
	
	/* process parameters */
	method_id = method_id_by_method_name(cmd->argv[METHOD_NAME]);
	round     = simple_strtoul(cmd->argv[METHOD_ROUND], endp, 10);

	if(method_id == NO_FINDING_METHOD)
		return;
	
	trig_man_add_trigger(context->trig_man, method_id, round, 0xff);	
	
}

/**
   Command: "clear_trigger_list $TARGET_IP"
   
   on success: no response
   on error  : no response
   
   Clears the list of triggers used by this scan-job.
   
*/

void clear_trigger_list_handler(struct command_t *cmd, struct scan_job_t *scan_job)
{
	struct flood_state_context *context =
		(struct flood_state_context *) scan_job->state_context;	

	trig_man_clear_trigger_list(context->trig_man);
}


/**
   Command: "set_report_events $TARGET_IP TRUE/FALSE"
   
   Enables/disables event-reporting. 

*/

void set_report_events_handler(struct command_t *cmd,
				  struct scan_job_t *scan_job)
{
	
	struct flood_state_context *context =
		(struct flood_state_context *) scan_job->state_context;

	enum {
		TARGET_IP = 0,
		BOOLEAN_VAL,
		NARGS
	};

	unsigned int boolean_val;
	char **endp = NULL;

	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Wrong number of parameters\n");
		scanner_output_queue_flush();
		return;
	}	
	
	boolean_val = simple_strtoul(cmd->argv[BOOLEAN_VAL],endp, 10);	
	
	context->report_events = (boolean_val != 0);
	
}

/**
   Command: "set_timing_algorithm $TARGET_IP $ALGO_ID"
   
   Sets the timing-algorithm to be used.
   
*/


void set_timing_algorithm_handler(struct command_t *cmd,
				  struct scan_job_t *scan_job)
{
	struct flood_state_context *context =
		(struct flood_state_context *) scan_job->state_context;

	enum {
		TARGET_IP = 0,
		ALGO_ID,
		NARGS
	};
	
	unsigned int algo_id;
	char **endp = NULL;

	if(cmd->argc != NARGS){
		scanner_output_queue_add("ERROR -1 Wrong number of parameters\n");
		scanner_output_queue_flush();
		return;
	}	
	
	algo_id = simple_strtoul(cmd->argv[ALGO_ID],endp, 10);	
	
	/* check range */

	if(!(algo_id >= 0 && algo_id < N_TIMING_ALGOS))
		return;
	
	/* deinitialize old timing-algo-context */
	context->timing_alg->destructor(scan_job, context->timing_algo_state,
					&context->timing_context);
	
	context->timing_alg = timing_algorithms[algo_id];
	
	/* initialize the new timing-algo-context */
	context->timing_algo_state = 
		context->timing_alg->constructor(scan_job, &context->timing_context);
	
}


/** @}  */

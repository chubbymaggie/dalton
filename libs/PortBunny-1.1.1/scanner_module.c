/*
        PortBunny kernel-module.
		
	Authors:        Fabian Yamaguchi <fabs@recurity-labs.com>

	Changes:        fabs        :       Initial Revision     28.03.07 
	
	Descripion:     Module initialization/deinitialization.	
*/



/**
   \mainpage PortBunny kernel-module - Documentation
   
   \section intro_sec Introduction

   Welcome to the official documentation of PortBunny - Recurity Labs' kernel-based
   port-scanner! I hope that this document will help you find your way
   around the source-code and most of all, I hope you like the code.
   
   I have put extensive effort into making this code readable, maintainable
   and instructive in the hope that it may motivate people to hack on the code.
   Because let's be honest, to most, hacking in an environment which will make
   your caps-lock-key blink when you do something wrong is not a convincing factor.
   
   Please send comments, suggestions and patches to <fabs@recurity-labs.com>.  
   
   \section overview Overview   
         
   Let's start off by naming the code-entry point: When the module is loaded
   using modprobe or insmod, the function scanner_init is called. This function
   will initialize the 4 components of the system, including the scan-job-manager
   which will spawn a kernel-thread.
   
   The \ref ScanJobManager is the central component of the system which manages all
   \ref ScanJob s. If you want to know more about the port-scanning logic, this is
   the place to look.
   
   The scanning-logic is however, dependent on whether the
   \ref ScanJob is in "trigger-" or "flood-state". In other words,
   are we currently concerned with finding triggers for this
   scan-job or are we in the actual scanning-process already?
   
   You can find the logic of a state in its respective ScanJobManager-function
   which the ScanJobManager executes each round until it this function returns
   \ref FINISHED.
   
   Checkout:
   
   \ref TriggerStateScanJobManager for trigger-state-logic which is used
   to determine triggers.
   
   and
   
   \ref FloodStateScanJobManager for flood-state-logic which is used
   during the actual port-scan.
   
   The other three components are concerned with I/O:
   
   The \ref PacketReceiver is the sniffer PortBunny uses.
   The \ref ScannerUI enables PortBunny to communicate with user-space via
   /dev/portbunny.
   
   Packets are sent out into the world by the \ref PacketSubmitter.  
   

*/


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include "scanner_module.h"
#include "scan_job_manager.h"
#include "sniffer/packet_receiver.h"
#include "packet_submitter.h"

#include "scanner_ui/scanner_ui.h"
#include "scanner_ui/scanner_output_queue.h"
#include "scanner_ui/pending_commands_queue.h"



/** 
        scanner_init:
        Module-entry point.
	Initialize all scanner-components.
*/

static int __init scanner_init(void)
{	
	printk("Loading PortBunny module Rev: ");
	printk(PBUNNY_VERSION);
	printk("\n");
	
	if( packet_receiver_init() != SUCCESS )
		return FAILURE;
	
	if( scanner_ui_init() != SUCCESS )
		return FAILURE;
	
	if( scan_job_manager_init() != SUCCESS)		
		return FAILURE;
		
	
	return SUCCESS;
}

/**
   Called when the module is removed.
*/

static void scanner_fini(void)
{
	/* send an 'exit'-command to the scanner */
	
	pending_commands_queue_add("exit\n");
	
	/* now sleep until the scan-job-manager is done. */	
	
	scan_job_manager_wait_for_termination();
}

MODULE_AUTHOR("Fabian Yamaguchi <fabs@recurity-labs.com>");
MODULE_DESCRIPTION("PortBunny module");
MODULE_ALIAS("portbunny");
MODULE_LICENSE("GPL");

module_init(scanner_init);
module_exit(scanner_fini);

#ifndef _SCANNER_UI_H
#define _SCANNER_UI_H

#include <linux/list.h>
#include <linux/rwsem.h>
#include <linux/wait.h>

/**
   \addtogroup ScannerUI
   
   The ScannerUI is the userland-interface
   to the scanner. It will create \ref command_t structures
   for all commands intercepted and will make these
   available to the scan-job-manager via the
   \ref PendingCommandsQueue.

   Commands have the form
   "command_name arg1 ... argn\n".

   The ScannerUI itsself
   does not validate whether a command is actually
   supported. This is done by the ScanJobManager.
   For a complete list of all available commands,
   checkout the \ref CommandHandlers.
   
   When the device file is read, the ScannerUI
   will poll the ScannerOutputQueue for any
   pending output which it will pass to the
   user.
   
   @{
*/


int scanner_ui_init(void);
void scanner_ui_fini(void);

extern wait_queue_head_t inq;

/**
   @}
*/

#endif

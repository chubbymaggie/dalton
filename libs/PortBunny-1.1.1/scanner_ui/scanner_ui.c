/* 
        PortBunny kernel-module.
		
	Authors:        Fabian Yamaguchi <fabs@recurity-labs.com>

	Changes:        fabs        :       Initial Revision     28.03.07 
	
	Descripion:     Device-File kernel/userland-interface.
	
	
*/

#include "../scanner_module.h"
#include "scanner_ui.h"
#include "scanner_output_queue.h"
#include "pending_commands_queue.h"

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <linux/wait.h>
#include <linux/sched.h>


#define PORTBUNNY_DEV_NAME "portbunny"
#define MAX_CMD_SIZE 32768

static int Major = 0;
DECLARE_WAIT_QUEUE_HEAD(inq);

/*
  The interface for class-device creation
  was modified several times by the kernel-
  authors. To deal with this, we will have
  to introduce some ifdefs.
*/


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#include <linux/devfs_fs_kernel.h>
#else


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)

static struct class *portbunny_class;

#else

static struct class_simple *portbunny_class;

#endif

#endif


/**
   \addtogroup ScannerUI
@{
*/

/**
        scanner_ui_read:
	
	Called by kernel when a user-space-process reads from
	             /dev/portbunny.

	
	@param filp not used.
	@param buffer buffer supplied by the user-space program.
	@param buf_length The user-space buffer's length.
	@param offset not used.  
	

        Effect:  Fills 'buffer' with the next string contained in the
	scanner-output-queue. If buffer is not big enough to hold the
	string, return as much data as possible and save the rest of
	the string so that it can be returned next time a read is issued.


*/


static ssize_t scanner_ui_read(struct file *filp,
			       char *buffer, size_t buf_length,
			       loff_t *offset)
{
	static char *out_buf = NULL;
	int out_buf_length;
	unsigned int nbytes_written = 0;
	unsigned int t;
	char *new_buf;
	char *dest = buffer;
	char *src;
	

	/* only read new data if there's nothing left in out_buf */
	
	if(!out_buf){
		
		if(scanner_output_queue_is_empty())
			wait_event_interruptible(inq, !scanner_output_queue_is_empty());					
		
		out_buf = scanner_output_queue_head();
		
		if(!out_buf){			
			return -ERESTARTSYS;
		}
	}
	
	
	do{
		
		/* out_buf is now initialized. */
		
		src = out_buf;
		out_buf_length = strlen(out_buf);
	
				
		if(out_buf_length <= buf_length){
			/* 
			   user-supplied buffer is large enough for this line.
			   Copy until all data is in user-space.
			*/
			
			for(t = 0; t < out_buf_length; t++)
				put_user(*(src++), dest++);
		
			
			kfree(out_buf);
			out_buf = NULL;
			
			nbytes_written += out_buf_length;
			buf_length -= out_buf_length;
			//return out_buf_length;
			continue;
		}
		
		/* user-supplied-buffer is too small for the complete line,
		   so fill the user-space-buffer and adjust out_buf accordingly
		   for the next read-call. */
		

		for(t = 0; t < buf_length; t++)
			put_user(*(src++), dest++);
		
		/* cut off the copied data */
		new_buf = kmalloc(sizeof(char) * (out_buf_length - buf_length) + 1, GFP_KERNEL);
		if(!new_buf)
			return -ENOMEM;
		
		memcpy(new_buf, out_buf + buf_length*sizeof(char), out_buf_length - buf_length + 1);
		
		kfree(out_buf);
		out_buf = new_buf;
		nbytes_written += buf_length;
		return nbytes_written;
		
	} while((out_buf = scanner_output_queue_head()));
	
	return nbytes_written;

}


/**
        scanner_ui_write:
	Description: Called by kernel when a user-space-process writes to
	/dev/portbunny.
	
	
	@param filp not used.
	@param buffer buffer supplied by the user-space program.
	@param buf_length The user-space buffer's length.
	@param offset not used.  
	

        Copy the contents of 'buffer' into a kernel-space buffer
	and append it to a static kernel-buffer. If the static
	kernel-buffer then contains a full command, add the
	command to the pending-commands-queue and clear the
	buffer.
	
        Notes:   A command is terminated with a newline-character
	and has the form "command_name arg1 ... argn\n"
	

*/

static ssize_t scanner_ui_write(struct file *filp,
				const char __user *buffer, size_t length,
				loff_t *offset)
{	
	static char kcmd_buf[MAX_CMD_SIZE];
	static boolean initialized = FALSE;
		
	/*
	  Allocate length + 1 chars so that we can store
	  and extra terminating \0.
	 */

	char *kbuf = kmalloc(sizeof(char) * (length + 1) , GFP_KERNEL);

	if(!kbuf)
		return -ENOMEM;
	
	kbuf[length] = '\0';

	/* Do not allow empty writes */
	if(length == 0){
		printk("empty write received\n");
		kfree(kbuf);
		return -EFAULT;
	}

	if(!initialized){
		printk("Initializing kcmd_buf\n");
		kcmd_buf[0] = '\0';
		initialized = TRUE;
	}

		
	if (copy_from_user(kbuf, buffer, length) != 0){
		printk("Error copying from user-space\n");
		kfree(kbuf);
		return -EFAULT;
	}
	
	/* The commands are text-based. If there is
	 * a \0 somewhere in the command, we are clearly
	 * being attacked. So just don't bother executing
	 * any more code for this input. */
	
	if(strlen(kbuf) != length){
		printk("Zero-byte poisoning\n");
		kfree(kbuf);
		return -EFAULT;
	}	       	
	
		
	
	/* If the command does not follow the convention 
	   of being no bigger than MAX_CMD_SIZE, discard it.*/
	if(strlen(kcmd_buf) + length + 1 > MAX_CMD_SIZE){
		printk("ERROR: Command too large: discarding.\n");
		kcmd_buf[0] = '\0';
		kfree(kbuf);
		return -EFAULT;
	}
	
	
	/* append newly received data to kcmd_buf */
	strncat(kcmd_buf, kbuf, MAX_CMD_SIZE - strlen(kcmd_buf) - 1);	

	/* if the second-last-char is '\n', we have
	 * received one or more complete commands. */
	
	if(kcmd_buf[strlen(kcmd_buf) - 1] == '\n'){
		char *cmd_start = kcmd_buf;
		char *cmd_end   = NULL;
		
		while((cmd_end = strchr(cmd_start, '\n'))){			
			char *new_cmd;
			
			/* don't accept empty commands */
			if(cmd_end == cmd_start)
				break;
			
			new_cmd = kmalloc(sizeof(char) * (cmd_end - cmd_start + 2), GFP_KERNEL);
			
			if(!new_cmd) return -EFAULT;
			
			memcpy(new_cmd, cmd_start, sizeof(char) * (cmd_end - cmd_start + 1));
			new_cmd[(cmd_end - cmd_start) + 1] = '\0';
		
			/* add the command to the pending-commands-queue */		

			pending_commands_queue_add(new_cmd);
			
			kfree(new_cmd);
			
			cmd_start = cmd_end + 1;
			
		}

		
		kcmd_buf[0] = '\0';
	}
	
	kfree(kbuf);
	return length;
}

static struct file_operations ui_fops = {
	.read  = scanner_ui_read,
	.write =  scanner_ui_write,
	.open  =  NULL,
	.release = NULL,
};


/**
  Registers the char-device and creates the
  device-file "/dev/portbunny".
  
*/

int scanner_ui_init()
{
		
	/* Register device */
	int major = register_chrdev(0, PORTBUNNY_DEV_NAME, &ui_fops);
	
	if (major < 0)
		return major;
	
	
	
	/* create device-file */
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	if (devfs_mk_cdev(MKDEV(major, 0), S_IFCHR | S_IRUGO | S_IWUGO, "portbunny", 0)) {
		printk("Could not create /dev/portbunny\n" );
		return FAILURE;
	}
#else
	

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)

	portbunny_class = class_create(THIS_MODULE, "portbunny");
#else
	portbunny_class = class_simple_create(THIS_MODULE, "portbunny");
#endif

	if (IS_ERR(portbunny_class)) {
		printk("Could not register class 'portbunny' \n");
		return FAILURE;
	} else {
		
		
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
		
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,25)
		device_create_drvdata(portbunny_class, NULL, MKDEV(major, 0), NULL, "portbunny");	
#else
		class_device_create(portbunny_class, NULL, MKDEV(major, 0), NULL, "portbunny");	
#endif		
		
#else
		class_simple_device_add(portbunny_class, MKDEV(major, 0), NULL, "portbunny");
#endif
		

	
	}
#endif
	
	Major = major;
	
	return SUCCESS;
}

/**
  
   Unregisters the device-file and deletes
  "/dev/portbunny".
*/

void scanner_ui_fini()
{
	int result = 0;

	if (!Major) return;
		
	/* Remove the device-file */
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	devfs_remove("portbunny", 0);
#else
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
	class_simple_device_remove(MKDEV(Major, 0));
	class_simple_destroy(portbunny_class);
#else	
	
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,25)
	device_destroy(portbunny_class, MKDEV(Major, 0));	
#else
	class_device_destroy(portbunny_class, MKDEV(Major, 0));	
#endif	
	class_destroy(portbunny_class);

#endif

#endif
	
	/* Unregister the device */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	result = unregister_chrdev(Major, PORTBUNNY_DEV_NAME);
#else
	unregister_chrdev(Major, PORTBUNNY_DEV_NAME);
#endif

	if (result < 0)
		printk("Unregistering the character device failed with %d\n", result);

	Major = 0;
	
}

/** @} */

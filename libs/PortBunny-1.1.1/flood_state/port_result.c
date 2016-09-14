
#include <linux/module.h>
#include <linux/kernel.h>

#include "../scanner_ui/scanner_output_queue.h"


#include "event_reporters.h"
#include "port_result.h"

struct port_result *create_port_result(int port)
{
	struct port_result *this = 
		kmalloc(sizeof(struct port_result), GFP_KERNEL);

	if(!this)
		return NULL;

	memset(this, 0, sizeof(struct port_result));
	
	this->port = port;

	return this;
	
}

void delete_port_result(struct port_result *this)
{				
	kfree(this);
}

void set_port_result(struct port_result *this, __u8 new_state)
{
	this->exists = TRUE;
	this->state = new_state;
}


/* "RESULT PORT_STATE" was abbreviated to "R P"
 * because it is the most frequent string written
 * across /dev/portbunny and the traffic on
 * /dev/portbunny can be a problem when results
 * are pouring in at high rates on slow machines.
 */

void output_port_result(struct port_result *this,
			const char *addr)
{
	char num_buf[128];

	if(!this || !addr) return;
	if(this->state == ERROR) return;
	
	output_msg_header(addr, "R", "P", FALSE);
	
	sprintf(num_buf, " %d ", this->port);
	scanner_output_queue_add(num_buf);
	
	if(this->state == OPEN)
		scanner_output_queue_add("O");
	else if(this->state == CLOSED)
		scanner_output_queue_add("C");
	else
		scanner_output_queue_add("F");
	
	scanner_output_queue_add("\n");	
	scanner_output_queue_flush();
	
}

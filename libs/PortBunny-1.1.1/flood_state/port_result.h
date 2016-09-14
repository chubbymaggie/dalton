#ifndef _PORT_RESULT_H
#define _PORT_RESULT_H

#include "../scanner_module.h"
#include "../queue.h"

#include <linux/list.h>

typedef enum
{
	FILTERED = 0,
	OPEN,
	CLOSED,
	ERROR
} port_state_t;

struct port_result{
	
	__u16 port;
	
	boolean exists;		
	/* state is a port_state_t but we want it to be 8 byte. */
	__u8 state;	
	
	struct packet_batch *port_is_in_batch;
	

	
};

struct port_result *create_port_result(int port);
void delete_port_result(struct port_result *this);
void set_port_result(struct port_result *this, __u8 new_state);
void output_port_result(struct port_result *this, const char *addr);


#endif

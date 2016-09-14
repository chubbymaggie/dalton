#ifndef _PACKET_RECEIVER_H
#define _PACKET_RECEIVER_H

#include <linux/netdevice.h>
#include "../queue.h"

/** \addtogroup PacketReceiver            
    
The packet-receiver sniffs all incoming packets and
passes them through its \ref ParseTree. If the packet
is of interest, a sniffed_packet_descr is saved in
the packet-receiver's sniffed_packet_queue which
other components can then access.

To make use of the packet-receiver, first initialize
it by calling \ref packet_receiver_init, then retrieve
any fetched packets from the global queue
'packet_receiver.sniffed_packet_queue' and
deinitialize the packet-receiver by calling
packet_receiver_fini. It's that simple.

@{
*/

struct packet_receiver_t{		
	struct queue_t *sniffed_packet_queue;	
};


/*
  Lock used to synchronize access to
  global packet-queue shared between
  the scan-job-manager and 
  interrupt-handlers.
  
*/

extern rwlock_t packet_queue_lock;

/**
   Initialize packet-receiver
   
   Initializes the parse-tree and registers a callback
   with the kernel-network stack.
   
*/

int packet_receiver_init(void);


/**
   Deinitialize packet-receiver
   
   Removes callback from kernel-network-stack
   and deinitialize parse-tree.
*/

void packet_receiver_fini(void);

extern struct packet_receiver_t packet_receiver;

/** @} */

#endif

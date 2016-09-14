#include "../scanner_module.h" /* SUCCESS/FAILURE */
#include "../scan_job_manager.h"

#include "packet_receiver.h"
#include "parse_tree.h"
#include "sniffed_packet.h"

static struct packet_type in_ip_pkt;
static struct packet_type in_arp_pkt;
static __be16 eth_ip_type;
static __be16 eth_arp_type;


/*
  Since the interrupt-handler, which accesses
  the packet-queue is registered after the
  queue has already been created, the lock
  may initialy be unlocked.
*/

rwlock_t packet_queue_lock = RW_LOCK_UNLOCKED;

struct packet_receiver_t packet_receiver = {	
	
	/* both of these are initialized by
	 * packet-receiver-init. */
	
	.sniffed_packet_queue = NULL,	
};

/** \addtogroup PacketReceiver
    @{ */

static int packet_receiver_rcv(struct sk_buff *skb, struct net_device *dev,
			       struct packet_type *p, struct net_device *orig_dev);

int packet_receiver_init(void)
{
	
	/* Initialize the scan-job-man-lock to LOCKED */
	spin_lock(&scan_job_man_thread_lock);	


	packet_receiver.sniffed_packet_queue = create_queue(NULL, GFP_ATOMIC, FALSE);
	
	if(!packet_receiver.sniffed_packet_queue)
		return FAILURE;
	
	/* register packet-types with kernel */	
	
	eth_arp_type = htons(ETH_P_ARP);
	in_arp_pkt.type = eth_arp_type;
	in_arp_pkt.dev = NULL;
	in_arp_pkt.func = packet_receiver_rcv;		

	
	eth_ip_type = htons(ETH_P_IP);
	in_ip_pkt.type = eth_ip_type;
	in_ip_pkt.dev = NULL;
	in_ip_pkt.func = packet_receiver_rcv;
	
	
	dev_add_pack(&in_arp_pkt);
	dev_add_pack(&in_ip_pkt);
	

	return SUCCESS;
}


void packet_receiver_fini(void)
{
	/* unregister packet-type. */
	dev_remove_pack(&in_ip_pkt);
	dev_remove_pack(&in_arp_pkt);
	

	write_lock_bh(&packet_queue_lock);

	delete_queue(packet_receiver.sniffed_packet_queue,
		     (delete_data_func) del_sniffed_packet_descr);
	
	packet_receiver.sniffed_packet_queue = NULL;
	write_unlock_bh(&packet_queue_lock);
	
}

/**
   Callback function for Linux-network-stack

   .   
*/

static int packet_receiver_rcv(struct sk_buff *skb, struct net_device *dev,
			struct packet_type *p, struct net_device *orig_dev)
{
	struct sniffed_packet_descr_t *descr = new_sniffed_packet_descr();
	boolean stored;
	
	
	if(!descr){
		dev_kfree_skb(skb);
		return 0;
	}
	
	if(p->type == eth_arp_type)		
		/* Handle ARP-packets */		
		stored = parse_arp_frame(skb, descr);	
	else		
		/* handle others */
		stored = parse_packet(skb, descr);	
	

	/* free the packet-descr. only if it has not been placed
	 * in the packet-queue, in which case it is the
	 * scan-job-manager's responsibility to do so. */

	if(!stored){
		del_sniffed_packet_descr(descr);
	}
	
	/* free the skb in any case. */

	dev_kfree_skb(skb);	
	return 0;
}

/** @} */

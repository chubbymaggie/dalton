#ifndef _SCANNER_PARSE_TREE_
#define _SCANNER_PARSE_TREE_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <linux/time.h>

#include "sniffed_packet.h"

/** \addtogroup ParseTree
 
@{
*/

#define TCP_NOT_HANDLED    0
#define TCP_SYN_ACK_PACK   1
#define TCP_ACK_RST_PACK   2
#define TCP_RST_PACK       3
#define N_TCP_TYPES        4

typedef __u16 (*node_func)   (struct sk_buff *, __u16, void **p_descr);


/**
   All intercepted packets are passed
   through the parse-tree consisting
   of nodes of type parse_tree_node.

   A node has a number of children which
   are pointers to other parse_tree_nodes
   and a decision-function (func) which maps a
   given packet (in the form of a packet_description)
   to one of the children.
   
*/

struct parse_tree_node {
	
	struct parse_tree_node      **children;
	__u16                       max_children;
	
	/** decision-function */
	node_func                   func;
	
};

boolean parse_packet(struct sk_buff *skb, struct sniffed_packet_descr_t *descr);
boolean parse_arp_frame(struct sk_buff *skb, struct sniffed_packet_descr_t *descr);
boolean forward_to_packet_queue(struct sniffed_packet_descr_t *descr);

/** @} */

#endif

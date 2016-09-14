#include <linux/version.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/if_arp.h>

#include "parse_tree.h"
#include "packet_receiver.h"
#include "sniffed_packet.h"

#include "../scan_job_manager.h"

#define ERROR_WHILE_PARSING        1
#define FALLBACK_TREE_INDEX       10
#define ERR_INDEX                 0xffff

/**

   Assumptions:

   * It has been verified that (ihl * 4) <= skb->len.
   
*/


static boolean parse_tcp_packet(struct sk_buff *skb,
			     struct sniffed_packet_descr_t *descr)
{
	struct iphdr *ip_header = (struct iphdr *) skb->data;
	struct tcphdr *tcp_header = NULL;
		
	/* check if packet is long enough to contain tcp-header */
	if(skb->len - (ip_header->ihl * 4) <  sizeof(struct tcphdr))
		return FALSE;
	
	tcp_header = (struct tcphdr *) &(skb->data[ip_header->ihl * 4]);	
		
	descr->protocol = IPPROTO_TCP;
	descr->tcp.port = ntohs(tcp_header->source);	
	descr->tcp.ack_seq = ntohl( tcp_header->ack_seq);
	descr->tcp.seq = ntohl(tcp_header->seq);	
	descr->tcp.syn = tcp_header->syn;
	descr->tcp.ack = tcp_header->ack;
	descr->tcp.rst = tcp_header->rst;	

	/* At this point, the tcp-packet can be forwarded */
	
	return forward_to_packet_queue(descr);	
}


static boolean parse_dest_unreach_tcp(struct sk_buff *skb,
				      struct sniffed_packet_descr_t *descr,	                              
				      struct iphdr *second_ip_header)
{
	struct iphdr *ip_header = (struct iphdr *) skb->data;
	struct tcphdr *tcp = NULL;

	/* check if packet is long enough to contain an
	   extra tcp-header
	*/
	
	if(skb->len - ((ip_header->ihl + second_ip_header->ihl)*4) - sizeof(struct icmphdr)
	   < sizeof(struct tcphdr))
		return FALSE;
	
	tcp = (struct tcphdr *) &(skb->data[ ((ip_header->ihl + second_ip_header->ihl)*4) + sizeof(struct icmphdr)]);
	descr->icmp.unreach_port = ntohs(tcp->dest);	
	

	return forward_to_packet_queue(descr);
}

static boolean parse_dest_unreach_udp(struct sk_buff *skb,
				      struct sniffed_packet_descr_t *descr,				      
				      struct iphdr *second_ip_header)
{
	struct iphdr *ip_header = (struct iphdr *) skb->data;
	struct udphdr *udp = NULL;
	__be16 *payload = NULL;

	/* check if packet is big enough to contain an extra
	 * udp-header + 2 bytes */
	
	if(skb->len - ((ip_header->ihl + second_ip_header->ihl)*4) - sizeof(struct icmphdr)
	   < sizeof(struct udphdr) + 2)
		return FALSE;
	
	udp = (struct udphdr *) &(skb->data[ ((ip_header->ihl + second_ip_header->ihl)*4) + sizeof(struct icmphdr)]);	
	payload = (__be16 *) &(skb->data[ ((ip_header->ihl + second_ip_header->ihl)*4) + sizeof(struct icmphdr) + sizeof(struct udphdr)]);	
	
	descr->icmp.unreach_data = ntohs(*payload);
	descr->icmp.unreach_port = ntohs(udp->dest);
	
	return forward_to_packet_queue(descr);
	
}

static boolean parse_dest_unreach_other(struct sk_buff *skb,
					struct sniffed_packet_descr_t *descr,					
					struct iphdr *second_ip_header)
{
	struct iphdr *ip_header = (struct iphdr *) skb->data;
	__be16 *payload = NULL;
	
	/* for all other protocols, extract the first 2 payload-bytes */
	
	/* check if two more payload-bytes exist */
	
	if(skb->len - ((ip_header->ihl + second_ip_header->ihl)*4) - sizeof(struct icmphdr)
	   < 2)
		return FALSE;
	
	payload = (__be16 *) &(skb->data[ ((ip_header->ihl + second_ip_header->ihl)*4) + sizeof(struct icmphdr) ]);
	descr->icmp.unreach_data = ntohs(*payload);
	
	return forward_to_packet_queue(descr);
	
}


/**
   
   Assumptions:

   * It has been verified that (ihl * 4) + sizeof(struct icmphdr) <= skb->len.
   
   */

static boolean parse_dest_unreachables(struct sk_buff *skb,
				       struct sniffed_packet_descr_t *descr)
{
	struct iphdr *ip_header = (struct iphdr *) skb->data;
	struct iphdr *second_ip_header = NULL;	
	
	/* check if the packet is big enough to contain another
	 * ip-header of minimum size.
	 */
	
	if(skb->len - (ip_header->ihl *4) - sizeof(struct icmphdr) < sizeof(struct iphdr))
		return FALSE;
	
	/* yes, packet is big enough: initialize a pointer to the
	 * beginning of the second header */
	
	second_ip_header = (struct iphdr *) &(skb->data[(ip_header->ihl * 4) + sizeof(struct icmphdr) ]);
	
	descr->icmp.unreach_protocol = second_ip_header->protocol;

	/* verify ihl of second ip-header */

	/*
	  check range of IHL-field
	*/
	
	if(second_ip_header->ihl < 5 || second_ip_header->ihl > 15)
		return FALSE;
	
	/*
	  check ihl against skb-len
	 */

	if(skb->len - (ip_header->ihl * 4) - sizeof(struct icmphdr)  < (second_ip_header->ihl * 4) )
		return FALSE;
	
	/* now check the protocol-field: */
	
	if(second_ip_header->protocol == IPPROTO_TCP)
		return parse_dest_unreach_tcp(skb, descr,
					      second_ip_header);
	else if(second_ip_header->protocol == IPPROTO_UDP)
		return parse_dest_unreach_udp(skb, descr,
					      second_ip_header);
	else
		return parse_dest_unreach_other(skb, descr,
						second_ip_header);
	
	return FALSE;
}

/**

   Assumptions:

   * It has been verified that (ihl * 4) <= skb->len.
   
   */

static boolean parse_icmp_packet(struct sk_buff *skb,
			      struct sniffed_packet_descr_t *descr)
{
	struct iphdr *ip_header = (struct iphdr *) skb->data;
	struct icmphdr *icmp_header = NULL;
	
	/* check if packet is long enough to contain icmp-header */
	
	if(skb->len - (ip_header->ihl *4) < sizeof(struct icmphdr))
		return FALSE;
	
	icmp_header = (struct icmphdr *) &(skb->data[ip_header->ihl *4]);
	
	descr->protocol = IPPROTO_ICMP;
	descr->icmp.seq_num = icmp_header->un.echo.sequence;
	descr->icmp.id = icmp_header->un.echo.id;
	descr->icmp.type = icmp_header->type;
	descr->icmp.code = icmp_header->code;
	
	if(descr->icmp.type != ICMP_DEST_UNREACH)
		return forward_to_packet_queue(descr);
	
	/*
	  handle destination-unreachables.
	*/

	return parse_dest_unreachables(skb, descr);	

}


static boolean parse_udp_packet(struct sk_buff *skb,
				struct sniffed_packet_descr_t *descr)
{
	return FALSE;
}

/**

   skb: The incoming socket-buffer
   descr: The packet-description to fill-out.

   Returns TRUE if the packet has been stored in
   the packet-queue. FALSE, otherwise.
   
   skb->len (unsigned int): packet-length
   skb->data (unsigned char *) : pointer to data

*/

boolean parse_packet(struct sk_buff *skb, struct sniffed_packet_descr_t *descr)
{
	
	struct iphdr *ip_header;
	
	/* we only handle packets, which are big enough
	 * to contain an IP-header.
	 */

	if(skb->len < sizeof(struct iphdr) )
		return FALSE;
	
	ip_header = (struct iphdr *) skb->data;
	
	/*
	  check range of IHL-field
	*/
	
	if(ip_header->ihl < 5 || ip_header->ihl > 15)
		return FALSE;
	
	/*
	  check ihl against skb-len
	 */

	if(skb->len < ip_header->ihl * 4)
		return FALSE;

	/* It has been verified that skb->data[0] to skb->data[ihl*4-1]
	 * is readable. Extract information from ip-header
	 */

	descr->subject = descr->src = ip_header->saddr;	
	
	
	if(ip_header->protocol == IPPROTO_TCP)
		return parse_tcp_packet(skb, descr);
	else if(ip_header->protocol == IPPROTO_ICMP)
		return parse_icmp_packet(skb, descr);
	else if(ip_header->protocol == IPPROTO_UDP)
		return parse_udp_packet(skb, descr);	
	
	
	return FALSE;
}

boolean parse_arp_frame(struct sk_buff *skb, struct sniffed_packet_descr_t *descr)
{
	struct arphdr *arp;
	unsigned char *arp_ptr;
	unsigned char *sha, *tha;
	__be32 sip, tip;
	
	
	if(!skb->dev) return FALSE;

	/* most of this code was taken from arp.c and adapted. */
	
	/* ARP header, plus 2 device addresses, plus 2 IP addresses.  */	

	if (!pskb_may_pull(skb, (sizeof(struct arphdr) +
				 (2 * skb->dev->addr_len) +
				 (2 * sizeof(u32)))))
		return FALSE;		
	
	arp = (struct arphdr *) skb->data;
	
	/* check if device is arp'able */	

	if (arp->ar_hln != skb->dev->addr_len ||
	    skb->dev->flags & IFF_NOARP ||
             skb->pkt_type == PACKET_OTHERHOST ||
             skb->pkt_type == PACKET_LOOPBACK ||
	    arp->ar_pln != 4)
		return FALSE;	
	
	
	if(arp->ar_op != htons(ARPOP_REPLY))
		return FALSE;		
	
	/*
	 *      Extract fields
	 */
	
	arp_ptr= (unsigned char *)(arp+1);
	sha     = arp_ptr;
	arp_ptr += skb->dev->addr_len;
	memcpy(&sip, arp_ptr, 4);
	arp_ptr += 4;
	tha     = arp_ptr;
	arp_ptr += skb->dev->addr_len;
	memcpy(&tip, arp_ptr, 4);
	
	/* Watch out! So far sha and tha are only
	 * pointers into the skb.
	 */
	
	descr->is_arp = TRUE;
	descr->subject = descr->src = sip;			
	
	return forward_to_packet_queue(descr);
	
}


/**
   save the packet-description in
   the sniffed-packet-queue.
*/

boolean forward_to_packet_queue(struct sniffed_packet_descr_t *descr)
{	
	pid_t p;
	
	/* put timestamp on packet */

	getnstimeofday(&descr->time_received);	
			
	write_lock(&packet_queue_lock);
	if(packet_receiver.sniffed_packet_queue)
		queue_add(packet_receiver.sniffed_packet_queue,
			  descr);
	write_unlock(&packet_queue_lock);
	
	/* wake up scan-job-manager */
		
	spin_lock(&scan_job_man_thread_lock);
	if(scan_job_man_thread)
		p = scan_job_man_thread->pid;
	else{
		spin_unlock(&scan_job_man_thread_lock);
		return FALSE;
	}
	spin_unlock(&scan_job_man_thread_lock);
		
	kill_proc(p, SIGINT, 1);				
	return TRUE;	
	
}





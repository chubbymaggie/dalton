#ifndef _SNIFFED_PACKET_H
#define _SNIFFED_PACKET_H

#include "../scanner_module.h" /* boolean */

struct sniffed_tcp_hdr_t{
	__be32            seq;
	__be32            ack_seq;						
	boolean           syn;	
	boolean           ack;
	boolean           rst;
	__be16            port;
};


struct sniffed_icmp_hdr_t{
	__be16            seq_num;
	__be16            id;	
	u8             type;		
	u8               code;	
	
	/* unreach-fields contain information
	 * about packets which generated dest-unreachables
	 */
	
	__be16           unreach_data;		
	__be16           unreach_port; 
	u8               unreach_protocol;
	
	
};

/* describes a sniffed packet */

struct sniffed_packet_descr_t{
	
	/* source and subject may differ 
	 * since a firewall with ip 'source'
	 * may report that a packet sent to 'subject'
	 * was not delivered.
	 */	

	__be32 src;
	__be32 subject;
	u8  protocol;	
	boolean is_arp;

			
	union{
		struct sniffed_tcp_hdr_t tcp;
		struct sniffed_icmp_hdr_t icmp;
	};
	
	struct timespec   time_received;
	
};

struct sniffed_packet_descr_t *new_sniffed_packet_descr(void);
void del_sniffed_packet_descr(struct sniffed_packet_descr_t *this);

#endif

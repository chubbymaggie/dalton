#ifndef _PACKET_SUBMITTER_H
#define _PACKET_SUBMITTER_H

#include <linux/module.h>
#include "scanner_module.h"

/* export nothing but the send-functions */

int send_icmp_packet(u32 destination, u32 icmp_type,
		     u32 icmp_code,
		     unsigned int icmp_data_size,
		     char *data,
		     u32 batch_id);

int send_tcp_syn_packet(u32 destination, u16 port, u16 src_port,
			u32 seq_num);

int send_tcp_ack_packet(u32 destination, u16 port, u16 src_port,
			u32 seq_num);

int send_udp_packet(u32 destination, u16 port, u16 id);			    

int send_ip_prot_packet(u32 destination, u8 prot, u16 id);

#endif

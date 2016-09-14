#include "packet_submitter.h"
#include "scanner_module.h"

#include <linux/kthread.h>
#include <linux/socket.h>
#include <linux/delay.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/checksum.h>
#include <linux/inet.h>

#include <linux/rwsem.h>
#include <asm/div64.h>

#define TCP_OPTIONS_LEN 4


/* TODO: The following code is used to calculate IP-checksums.
 * The linux-kernel, of course, provides functions to 
 * calculate these checksums so all calls of these 
 * functions should be replaced by calls to the kernel's
 * checksum-calculation-routines.
 */

static struct {
		struct cmsghdr cm;
		struct in_pktinfo ipi;
	} cmsg = { {sizeof(struct cmsghdr) + sizeof(struct in_pktinfo), SOL_IP, IP_PKTINFO},
		   {0, }};



unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;
	
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	
	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

/************/

struct psd_tcp {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	unsigned short tcp_len;
	struct tcphdr tcp;
	char options[TCP_OPTIONS_LEN];
};


unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len)
{
	struct psd_tcp buf;
	u_short ans;

	memset(&buf, 0, sizeof(buf));
	buf.src.s_addr = src;
	buf.dst.s_addr = dst;
	buf.pad = 0;
	buf.proto = IPPROTO_TCP;
	buf.tcp_len = htons(len);
	memcpy(&(buf.tcp), addr, len);
	ans = in_cksum((unsigned short *)&buf, 12 + len);
	return (ans);
}

/**
    \addtogroup PacketSubmitter            
    @{    
*/


/* Submitters */


/**

   @name Public functions
   @{

*/

/** icmp-submitter */

int send_icmp_packet(u32 destination, u32 icmp_type,
		     u32 icmp_code,
		     unsigned int icmp_data_size,
		     char *data,
		     u32 batch_id)			    
{
	
	int size;	
	
	int len = icmp_data_size + sizeof(struct icmphdr);
	char outbuf[len];

	struct iovec iov;
	struct socket *sock;
	struct sockaddr_in whereto;
	
	struct icmphdr *icmp = (struct icmphdr *) outbuf;

	int ret = sock_create(AF_INET, SOCK_RAW, IPPROTO_ICMP, &sock);
	struct msghdr msg = { &whereto, sizeof(whereto),
			      &iov, 1, &cmsg, 0, 0 };
			
	/* check if socket-creation was successful */
	if(ret < 0){
		printk("error creating socket\n");
		return FAILURE;
	}
	

	/* fillout sockaddr_in-structure whereto */
	
	
	memset(&whereto, 0, sizeof(whereto));
	whereto.sin_family = AF_INET;
	whereto.sin_addr.s_addr = destination;


	/* construct packet */
	memcpy((outbuf + sizeof(struct icmphdr)), data, icmp_data_size);	
		
	icmp->type = icmp_type;
	icmp->code = icmp_code;
	
	if((icmp->type == ICMP_ECHO) || (icmp->type == ICMP_TIMESTAMP)){
		/* Note: id is only 16 bit wide. */
		icmp->un.echo.id = batch_id;		
		icmp->un.echo.sequence = 0;
		
	}

	icmp->checksum = 0;

	iov.iov_base = outbuf;
	iov.iov_len = sizeof(outbuf);
	
	/* calculate icmp-checksum */
	icmp->checksum = in_cksum((ushort *)&outbuf, len);

	/* fire! */

	while(len > 0){
		size = sock_sendmsg(sock, &msg, len);
		
		if (size < 0 ){			
			/* If an error occurs, just don't deliver the
			 * packet but keep on going. */
			printk("sock_sendmsg error: %d\n", size);
			break;
		}
		
		len -= size;
	}
	
	sock_release(sock);
	sock = NULL;

	return 0;
}


static u32 get_our_ip(struct sockaddr_in *whereto)
{	
	struct socket *temp_sock;
	u32 our_ip;
	
	/* create a udp-socket for the given destination
	 * and 'connects'. Since udp is actually a
	 * connectionless protocol, 'connecting' does not
	 * involve any packet-exchange but has the side-effect
	 * of retrieving the interface which will be used to
	 * communicate with the given destination.
	 * This allows us to retrieve our ip.
	 */

	if((sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &temp_sock)) < 0){  		
		return 0;
	}
	
	if( (temp_sock->ops->connect(temp_sock, (struct sockaddr *)whereto,
				     sizeof(struct sockaddr), 0) )< 0){
		

		sock_release(temp_sock);
		temp_sock = NULL;
		return 0;
	}
	
	
	our_ip = inet_sk(temp_sock->sk)->rcv_saddr;
	
	sock_release(temp_sock);
	temp_sock = NULL;

	return our_ip;
	
}


static int send_tcp_packet(u32 destination, u16 port, u16 src_ports,
			   u32 seq_num, boolean ack)
{
		
	/* local used for socket-communication */
	struct socket *sock;
	struct sockaddr_in whereto;
	struct iovec iov;
	struct msghdr msg = { &whereto, sizeof(whereto),
			      &iov, 1, &cmsg, 0, 0 };

	u16 len;
	int size;
	const int on = 1;

	/* locals used for packet-creation */
	struct iphdr  ip;
	struct tcphdr tcp;
	char options[TCP_OPTIONS_LEN];		
	u32 our_ip;
	int ret = sock_create(AF_INET, SOCK_RAW, IPPROTO_TCP, &sock);
	const int out_buf_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + TCP_OPTIONS_LEN;
	char out_buf[out_buf_len];
	
	
	/* set MSS */	
	*((__be32 *) (&options[0])) = htonl(0x020405b4);		
	
	/* check if socket-creation was successful */
	if(ret < 0){		
		printk("error creating socket\n");
		return -1;
	}

	/* convert to network-byte-order */
	
	port = htons(port);
	seq_num = htonl(seq_num);
	
	/* fillout sockaddr_in-structure whereto */
	
	memset(&whereto, 0, sizeof(whereto));
	whereto.sin_family = AF_INET;
	whereto.sin_addr.s_addr = destination;
	whereto.sin_port = port;
				
	our_ip = get_our_ip(&whereto);	
	
	/* fillout ip-header */
	memset(&ip, 0, sizeof(struct iphdr));
		
	ip.tot_len = out_buf_len;	
	
	ip.ihl = 0x5;
	ip.version = 0x4;
	ip.tos = 0x0;
	ip.id = htons(12831);
	ip.frag_off = 0x0;
	ip.ttl = 64;
	ip.protocol = IPPROTO_TCP;
	ip.check = 0x0;
	
	ip.saddr = our_ip;
	ip.daddr = destination;
	
	ip.check = in_cksum((unsigned short *)&ip, sizeof(ip));
	/* copy ip-header into out_buf */
	memcpy(out_buf, &ip, sizeof(struct iphdr));
		
	/* fillout tcp-header */
	memset(&tcp, 0, sizeof(struct tcphdr));
	tcp.source = htons(src_ports);

	tcp.dest = port;
		
	if(!ack){
		tcp.syn = 1;
		tcp.seq = seq_num;
		tcp.window = 0;
	}else{
		tcp.ack = 1;
		tcp.ack_seq = seq_num;
		tcp.window = htons(3072);
	}

	
	tcp.doff = (sizeof(struct tcphdr) + TCP_OPTIONS_LEN ) / 4 ;
	
	
	tcp.urg_ptr = 0;	
	tcp.check = 0;
	
	/* copy tcp-header into out_buf */
	memcpy((out_buf + sizeof(struct iphdr)), &tcp, sizeof(struct tcphdr));
	
	/* copy options into ouf_buf */
	memcpy((out_buf + sizeof(struct iphdr) + sizeof(struct tcphdr)), &options, TCP_OPTIONS_LEN);
	
	tcp.check = in_cksum_tcp(our_ip, ip.daddr,
				 (unsigned short *) (out_buf + sizeof(struct iphdr)),
				 sizeof(struct tcphdr) + TCP_OPTIONS_LEN);
	
	/* copy tcp-header into out_buf */
	memcpy((out_buf + sizeof(struct iphdr)), &tcp, sizeof(struct tcphdr));
	
	iov.iov_base = out_buf;
	iov.iov_len = out_buf_len;	
	
	sock->ops->setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (void *) &on, sizeof(on));	
			
	
	/* fire! */
	len = iov.iov_len;	
	while(len != 0){
		size = sock_sendmsg(sock, &msg, len);
		
		if (size < 0){
			printk("sock_sendmsg error: %d\n", size);
			break;
		}
		
		len -= size;
	}
	
	
	sock_release(sock);
	sock = NULL;
		
	return 0;
}

int send_tcp_syn_packet(u32 destination, u16 port, u16 src_ports,
			u32 seq_num)
{
	return send_tcp_packet(destination, port, src_ports, seq_num, FALSE);
}

int send_tcp_ack_packet(u32 destination, u16 port, u16 src_ports,
			u32 seq_num)
{
	return send_tcp_packet(destination, port, src_ports, seq_num, TRUE);
}



/**
   submitter for udp-packets.
*/

int send_udp_packet(u32 destination, u16 port, u16 id)
{
		
	struct socket *sock;
	struct msghdr msg;
        struct iovec iov;
	struct sockaddr_in whereto;
	int size;	

	__be16 outbuf = htons(id);
	int len = sizeof(u16);
	
	
	int ret = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
	
	
        if(ret < 0) return -1;			
	
	/* fillout sockaddr_in-structure whereto */

	port = htons(port);

	memset(&whereto, 0, sizeof(whereto));
	whereto.sin_family = AF_INET;
	whereto.sin_addr.s_addr = destination;
	whereto.sin_port = port;

	/* "connect" */
	if( (sock->ops->connect(sock, (struct sockaddr *)&whereto,
				sizeof(struct sockaddr), 0) )< 0)
		return -1;

        iov.iov_base = &outbuf;
        iov.iov_len = len;
	
        msg.msg_flags = 0;
        msg.msg_name = &whereto;
        msg.msg_namelen  = sizeof(struct sockaddr_in);
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;

	
        /* fire! */
	len = iov.iov_len;
	while(len != 0){
		size = sock_sendmsg(sock, &msg, len);
		
		if (size < 0){
			printk("sock_sendmsg error: %d\n", size);			
			break;
		}

		len -= size;
	}
	
	sock_release(sock);
	

	return 0;
}

int send_ip_prot_packet(u32 destination, u8 prot, u16 id)
{
	struct socket *sock;
	struct sockaddr_in whereto;
	struct iovec iov;
	struct msghdr msg = { &whereto, sizeof(whereto),
			      &iov, 1, &cmsg, 0, 0 };
	
	u16 len;
	int size;
	const int on = 1;
		
	/* locals used for packet-creation */
	struct iphdr  ip;
	u32 our_ip;

	int ret = sock_create(AF_INET, SOCK_RAW, IPPROTO_TCP, &sock);
	const int out_buf_len = sizeof(struct iphdr) + sizeof(u16);
	char out_buf[out_buf_len];
	
	/* check if socket-creation was successful */
	if(ret < 0){		
		printk("error creating socket\n");
		return -1;
	}

	/* fillout sockaddr_in-structure whereto */
	
	memset(&whereto, 0, sizeof(whereto));
	whereto.sin_family = AF_INET;
	whereto.sin_addr.s_addr = destination;
	whereto.sin_port = 1; /* does not matter */
				
	our_ip = get_our_ip(&whereto);	
	
	/* fillout ip-header */
	memset(&ip, 0, sizeof(struct iphdr));
		
	ip.tot_len = out_buf_len; 
	
	ip.ihl = 0x5;
	ip.version = 0x4;
	ip.tos = 0x0;
	ip.id = htons(12831);
	ip.frag_off = 0x0;
	ip.ttl = 64;
	ip.protocol = prot;
	ip.check = 0x0;
	
	ip.saddr = our_ip;
	ip.daddr = destination;
	
	ip.check = in_cksum((unsigned short *)&ip, sizeof(ip));

	/* copy ip-header into out_buf */
	memcpy(out_buf, &ip, sizeof(struct iphdr));
	
	/* append payload */
	
	*((u16 *)(out_buf + sizeof(struct iphdr))) =  htons(id);
	
	iov.iov_base = out_buf;
	iov.iov_len = out_buf_len;
		
	sock->ops->setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (void *) &on, sizeof(on));	
	
	/* fire! */
	len = iov.iov_len;	
	while(len != 0){
		size = sock_sendmsg(sock, &msg, len);
		
		if (size < 0){
			printk("sock_sendmsg error: %d\n", size);
			break;
		}
		
		len -= size;
	}
	
	
	sock_release(sock);
	sock = NULL;
		
	return 0;
}


/** @} */ /* End Public Functions */


/** @} */  /* End PacketSubmitter-Group */


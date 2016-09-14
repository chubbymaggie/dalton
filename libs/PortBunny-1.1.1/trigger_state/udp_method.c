#include "state.h"
#include "udp_method.h"
#include "trigger_finding_methods.h"

#include "../scanner_module.h"
#include "../packet_submitter.h"
#include "../scan_job_states.h"

#include "../sniffer/sniffed_packet.h"
#include "../flood_state/packet_batch.h"

#include <linux/time.h>
#include <net/ip.h>


static int udp_context_init(struct trigger_instance *this,
			    s32 round)
{
	
	/*
	  Allocate memory for context and copy default
	  port-list into context.
	*/
	
	struct udp_context *udp_context =
		this->context = kmalloc(sizeof(struct udp_context), GFP_KERNEL);

	if(!udp_context)
		return FAILURE;
	
	
	/* 
	 * Initialize a data-field of 32 bit which will be used 
	 * to store the packet_batch-id of the packet_batch
	 * the trigger was sent in. Only 16 bit are used.
	 */
	
	udp_context->data = 0;				
	udp_context->port = round;		
	this->quality = UDP_QUALITY;

	return SUCCESS;
}



static void udp_sender(struct scan_job_t *this,
		       struct trigger_instance *method_instance)
{		
	struct udp_context *udp_context = 
		method_instance->context;	
		
	send_udp_packet(this->addr, udp_context->port,
			udp_context->data);
	
}

static int udp_receiver(struct scan_job_t *this,
			struct trigger_instance *method_instance,
			struct sniffed_packet_descr_t *descr)
{	
	struct trigger_state_context *context =
		this->state_context;	
	
	struct udp_context *udp_context = 
		method_instance->context;	
				
	/* If protocol and icmp-type is correct, the packet
	   is from the host this scan-job is scanning and
	   this trigger has not been reported, report it.
	*/
	if( (descr->protocol == IPPROTO_ICMP) &&
	    (descr->icmp.type == ICMP_DEST_UNREACH) &&
	    (descr->icmp.code == ICMP_PORT_UNREACH) &&
	    (descr->src == this->addr) && 
	    (descr->icmp.unreach_port == udp_context->port)){
	  
		trigger_instance_out(method_instance, this, descr->icmp.unreach_port);		
		context->ntriggers_found++;
		return FINISHED;
	}			
	
	
	return CALL_AGAIN;

}


static void udp_context_fini(struct trigger_instance *this)
{
	struct udp_context *udp_context = this->context;	
	kfree(udp_context);
}


static int udp_is_response(struct sniffed_packet_descr_t *descr,
			   struct packet_batch *batch)
{
	struct trigger_instance *method_instance = 
		batch->trigger;
	
	struct udp_context *udp_context = 
		method_instance->context;
	u16 port_expected, port_received;
	boolean is_response;
	
	
	port_expected = udp_context->port;
	port_received = descr->icmp.unreach_port;


	is_response =  (descr->protocol == IPPROTO_ICMP) &&
		(descr->icmp.type == ICMP_DEST_UNREACH) &&
		(descr->icmp.code == ICMP_PORT_UNREACH) &&
		(port_expected == port_received) &&
		(descr->icmp.unreach_data == batch->port_indices[0]);
		
	return is_response;

}

static u32 udp_extract_batch_id(struct sniffed_packet_descr_t *descr)
{
	if ((descr->protocol == IPPROTO_ICMP) &&
	    (descr->icmp.type == ICMP_DEST_UNREACH) &&
	    (descr->icmp.code == ICMP_PORT_UNREACH))
		return descr->icmp.unreach_data;
	
	return 0;
}



static void udp_register_batch_id(struct trigger_instance *this,
				  u32 batch_id)
{
	struct udp_context *context = this->context;
	
	/* Save batch_id in id */
	context->data = batch_id;	

}

static void *
udp_context_copy(struct trigger_instance *this)
{
	struct udp_context *context = this->context;
	
	struct udp_context *new_context = 
		kmalloc(sizeof(struct udp_context), GFP_KERNEL);

	if(!new_context)
		return NULL;

	memcpy(new_context, context, sizeof(struct udp_context));
	
	return new_context;
	
}

static s32 udp_get_round_by_descr(struct sniffed_packet_descr_t *descr)
{
	return descr->icmp.unreach_port;
}

static s32 udp_get_round(void *context)
{
	struct udp_context *c = context;

	return c->port;
}

static u8 udp_get_default_quality(void)
{
	return UDP_QUALITY;
}

struct trigger_finding_method udp_method = {
	.name = "UDP",
	.sender_func = &udp_sender,
	.large_sender_func = NULL,
	.receiver_func = &udp_receiver,

	.is_response = &udp_is_response,

	.register_batch_id = &udp_register_batch_id,
	.extract_batch_id  = &udp_extract_batch_id,
	
	.get_round_by_descr = &udp_get_round_by_descr,
	.get_round          = &udp_get_round,

	.get_default_quality = &udp_get_default_quality,

	.context_init = udp_context_init,
	.context_fini = udp_context_fini,

	.context_copy = udp_context_copy,
	
};

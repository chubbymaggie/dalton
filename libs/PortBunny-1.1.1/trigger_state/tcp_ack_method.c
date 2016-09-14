#include "state.h"
#include "tcp_ack_method.h"

#include "trigger_finding_methods.h"

#include "../scanner_module.h"
#include "../packet_submitter.h"
#include "../scan_job_states.h"

#include "../sniffer/sniffed_packet.h"
#include "../flood_state/packet_batch.h"

#include <linux/time.h>
#include <net/ip.h>


#define TRIGGER_SRC_PORT 61373
#define MAX_TRIGGER_SRC_PORT 61380

static int tcp_ack_context_init(struct trigger_instance *this, s32 round)
{
	
	/*
	  Allocate memory for context and copy default
	  port-list into context.
	*/
	
	struct tcp_ack_context *ack_context =
		this->context = kmalloc(sizeof(struct tcp_ack_context), GFP_KERNEL);

	if(!ack_context)
		return FAILURE;
	
	ack_context->port = round;	
	ack_context->src_port = TRIGGER_SRC_PORT;
	this->quality = TCP_ACK_QUALITY;
	
	return SUCCESS;
}


static int tcp_ack_is_response(struct sniffed_packet_descr_t *descr,
			   struct packet_batch *batch)
{		
	struct trigger_instance *method_instance = 
		batch->trigger;
	struct tcp_ack_context *ack_context = 
		method_instance->context;
	
	printk("reached\n");
	
	return (descr->protocol == IPPROTO_TCP) &&
		( (ack_context->port == 0) || (descr->tcp.port == ack_context->port) ) &&
		(descr->tcp.seq == batch->port_indices[0])  &&
		(descr->tcp.rst == TRUE);
}


static u32 tcp_ack_extract_batch_id(struct sniffed_packet_descr_t *descr)
{
	if ((descr->protocol == IPPROTO_TCP) && descr->tcp.rst){
		return descr->tcp.seq;
	}	
	
	return 0;
}


static void tcp_ack_sender(struct scan_job_t *this,
			   struct trigger_instance *method_instance)
{
	
	struct tcp_ack_context *ack_context = 
		method_instance->context;
	
	
	send_tcp_ack_packet(this->addr, ack_context->port,
			    ack_context->src_port, ack_context->batch_id);
		
}


static int tcp_ack_receiver(struct scan_job_t *this,
			    struct trigger_instance *method_instance,
			    struct sniffed_packet_descr_t *descr)
{
  
	struct trigger_state_context *context =
		this->state_context;
	
	struct tcp_ack_context *ack_context = 
		method_instance->context;
	
	
	if( (descr->protocol == IPPROTO_TCP) &&  
	    (descr->src == this->addr)){		
		
		/* if the probe was actually sent on this port */
		if(ack_context->port == descr->tcp.port){
			
			
			trigger_instance_out(method_instance, this, descr->tcp.port);			
			context->ntriggers_found++;
			return FINISHED;
		}
	}			
				
	return CALL_AGAIN;
	
}

static void tcp_ack_register_batch_id(struct trigger_instance *this,
				      unsigned int batch_id)
{
	struct tcp_ack_context *context = this->context;

	context->batch_id = batch_id;
}


static void tcp_ack_context_fini(struct trigger_instance *this)
{
	struct tcp_ack_context *ack_context = this->context;				
	kfree(ack_context);
}

static void *
tcp_ack_context_copy(struct trigger_instance *this)
{
	struct tcp_ack_context *context = this->context;
	
	struct tcp_ack_context *new_context = 
		kmalloc(sizeof(struct tcp_ack_context), GFP_KERNEL);

	if(!new_context)
		return NULL;

	memcpy(new_context, context, sizeof(struct tcp_ack_context));
					
	if(++context->src_port > MAX_TRIGGER_SRC_PORT){
		context->src_port = TRIGGER_SRC_PORT;
	}	
	
	return new_context;
	
}

static s32 tcp_ack_get_round_by_descr(struct sniffed_packet_descr_t *descr)
{
	return descr->tcp.port;
}

static s32 tcp_ack_get_round(void *context)
{
	struct tcp_ack_context *c = context;

	return c->port;
}

static u8 tcp_ack_get_default_quality(void)
{
	return TCP_ACK_QUALITY;
}

struct trigger_finding_method tcp_ack_method = {
	.name = "TCP_ACK",
	
	.sender_func = &tcp_ack_sender,
	.large_sender_func = NULL,
	.receiver_func = &tcp_ack_receiver,

	.is_response = &tcp_ack_is_response,
	
	.register_batch_id = &tcp_ack_register_batch_id,
	.extract_batch_id  = &tcp_ack_extract_batch_id,

	.get_round_by_descr = &tcp_ack_get_round_by_descr,
	.get_round          = &tcp_ack_get_round,

	.get_default_quality = &tcp_ack_get_default_quality,

	.context_init = tcp_ack_context_init,
	.context_fini = tcp_ack_context_fini,

	.context_copy = tcp_ack_context_copy,
	
};

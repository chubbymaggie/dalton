#include "state.h"
#include "tcp_syn_method.h"

#include "trigger_finding_methods.h"

#include "../scanner_module.h"
#include "../packet_submitter.h"
#include "../scan_job_states.h"

#include "../sniffer/sniffed_packet.h"
#include "../flood_state/packet_batch.h"

#include <linux/time.h>
#include <net/ip.h>


#define TRIGGER_SRC_PORT 61373
#define MAX_TRIGGER_SRC_PORT 61400
//#define MAX_TRIGGER_SRC_PORT 61380


static int tcp_syn_context_init(struct trigger_instance *this, s32 round)
{
	
	/*
	  Allocate memory for context and register
	  values.
	*/
	
	struct tcp_syn_context *syn_context =
		this->context = kmalloc(sizeof(struct tcp_syn_context), GFP_KERNEL);

	if(!syn_context)
		return FAILURE;
			
	
	syn_context->port = round;		
	syn_context->src_port = TRIGGER_SRC_PORT;	
	this->quality = TCP_SYN_NEG_QUALITY;
		
	return SUCCESS;
}


static int tcp_is_response(struct sniffed_packet_descr_t *descr,
			   struct packet_batch *batch)
{		
	struct trigger_instance *method_instance = 
		batch->trigger;
	struct tcp_syn_context *syn_context = 
		method_instance->context;
	
	return (descr->protocol == IPPROTO_TCP) &&	  
		( (syn_context->port == 0) || (descr->tcp.port == syn_context->port) ) &&
		(((descr->tcp.ack_seq - 1) == batch->port_indices[0]));
}


static u32 tcp_syn_extract_batch_id(struct sniffed_packet_descr_t *descr)
{
	if ((descr->protocol == IPPROTO_TCP) && descr->tcp.ack &&
	    (descr->tcp.rst || descr->tcp.syn))
		
		
		/* filter batch-0 responses. */
		if(descr->tcp.ack_seq != 1){
			
			return (descr->tcp.ack_seq - 1);
		}		
	
	return 0;
}


/*
  
  Adds tcp-syn-packets for each port specified in
  the method-instance.
  
*/

static void tcp_syn_sender(struct scan_job_t *this,
			   struct trigger_instance *method_instance)
{
	
	struct tcp_syn_context *syn_context = 
		method_instance->context;
	
		
	send_tcp_syn_packet(this->addr, syn_context->port,
			    syn_context->src_port, syn_context->batch_id);
	
}


static void tcp_syn_large_sender(struct scan_job_t *this,
				 struct trigger_instance *method_instance)
{
	
	struct tcp_syn_context *syn_context = 
		method_instance->context;
	
	u16 udp_data = 0;
		
	/* send background-traffic first */
	
	send_udp_packet(this->addr, 23, udp_data);	
	
	/* then send normal tcp-packets */	
	
	send_tcp_syn_packet(this->addr, syn_context->port,
			    syn_context->src_port, syn_context->batch_id);
	

}

static int tcp_syn_receiver(struct scan_job_t *this,
			    struct trigger_instance *method_instance,
			    struct sniffed_packet_descr_t *descr)
{
	
	struct tcp_syn_context *syn_context = 
		method_instance->context;
	
	struct trigger_state_context *context =
		this->state_context;
		

	if( (descr->protocol == IPPROTO_TCP) &&  
	    (descr->src == this->addr)){
	  				
		
		/* if the probe was sent on this port */
		if(syn_context->port == descr->tcp.port){					
			struct port_result p = {
				.port = syn_context->port,
				.exists = FALSE,
				.state = (descr->tcp.syn?OPEN:CLOSED),
			};
			
			trigger_instance_out(method_instance, this, descr->tcp.port);			
			
			/* output port-state */
			output_port_result(&p, this->addr_str);

			
			context->ntriggers_found++;
			return FINISHED;
		}
	}			
	
	
	return CALL_AGAIN;
	
}

static void tcp_syn_register_batch_id(struct trigger_instance *this,
				      u32 batch_id)
{
	struct tcp_syn_context *context = this->context;

	context->batch_id = batch_id;
}


static void tcp_syn_context_fini(struct trigger_instance *this)
{
	struct tcp_syn_context *syn_context = this->context;				
	kfree(syn_context);
}

static void *
tcp_syn_context_copy(struct trigger_instance *this)
{
	struct tcp_syn_context *context = this->context;
	
	struct tcp_syn_context *new_context = 
		kmalloc(sizeof(struct tcp_syn_context), GFP_KERNEL);

	if(!new_context)
		return NULL;

	memcpy(new_context, context, sizeof(struct tcp_syn_context));
		
	
	if(++context->src_port > MAX_TRIGGER_SRC_PORT){
		context->src_port = TRIGGER_SRC_PORT;
	}	
	
	
	return new_context;
	
}

static s32 tcp_syn_get_round_by_descr(struct sniffed_packet_descr_t *descr)
{
	return descr->tcp.port;
}

static s32 tcp_syn_get_round(void *context)
{
	struct tcp_syn_context *c = context;

	return c->port;
}

static u8 tcp_syn_get_default_quality(void)
{
	return TCP_SYN_POS_QUALITY;
}

struct trigger_finding_method tcp_syn_method = {
	.name = "TCP_SYN",
	
	.sender_func = &tcp_syn_sender,
	.large_sender_func = tcp_syn_large_sender,
	
	.receiver_func = &tcp_syn_receiver,
	.is_response = &tcp_is_response,
	
	.register_batch_id = &tcp_syn_register_batch_id,
	.extract_batch_id  = &tcp_syn_extract_batch_id,

	.get_round_by_descr = &tcp_syn_get_round_by_descr,
	.get_round          = &tcp_syn_get_round,

	.get_default_quality = &tcp_syn_get_default_quality,
	
	.context_init = tcp_syn_context_init,
	.context_fini = tcp_syn_context_fini,

	.context_copy = tcp_syn_context_copy,
	
};

#include "ip_prot_method.h"
#include "trigger_finding_methods.h"
#include "state.h"

#include "../scanner_module.h"
#include "../packet_submitter.h"
#include "../scan_job_states.h"

#include "../sniffer/sniffed_packet.h"
#include "../flood_state/packet_batch.h"

#include <linux/time.h>
#include <net/ip.h>


static int ip_prot_receiver(struct scan_job_t *this,
			    struct trigger_instance *method_instance,
			    struct sniffed_packet_descr_t *descr)
{
  
	struct trigger_state_context *context =
		(struct trigger_state_context *) this->state_context;
	
			
	struct ip_prot_context *ip_prot_context =
		method_instance->context;
		
	/* If protocol and icmp-type is correct, the packet
	   is from the host this scan-job is scanning and
	   this trigger has not been reported, report it.
	*/
	if( (descr->protocol == IPPROTO_ICMP) &&
	    (descr->icmp.type == ICMP_DEST_UNREACH) &&
	    (descr->icmp.code == ICMP_PROT_UNREACH) &&
	    (descr->src == this->addr) &&
	    (descr->icmp.unreach_protocol == ip_prot_context->protocol)){
				
		
		trigger_instance_out(method_instance, this, ip_prot_context->protocol);
		context->ntriggers_found++;
		return FINISHED;
	}			
	
	
	return CALL_AGAIN;	
}

static int ip_prot_context_init(struct trigger_instance *this,
				s32 round)
{
	
	/*
	  Allocate memory for context and copy default
	  port-list into context.
	*/
	
	struct ip_prot_context *ip_prot_context =
		this->context = kmalloc(sizeof(struct ip_prot_context), GFP_KERNEL);

	if(!ip_prot_context)
		return FAILURE;
	
	
	/* 
	 * Initialize a data-field of 32 bit which will be used 
	 * to store the packet_batch-id of the packet_batch
	 * the trigger was sent in. Only 16 bit are used.
	 */
	
	ip_prot_context->data = 0;				
	ip_prot_context->protocol = round;		
	this->quality = IP_PROT_QUALITY;

	return SUCCESS;
}



static void ip_prot_sender(struct scan_job_t *this,
			   struct trigger_instance *method_instance)
{		
	struct ip_prot_context *ip_prot_context = 
		method_instance->context;	
	
	send_ip_prot_packet(this->addr, ip_prot_context->protocol,
			    ip_prot_context->data);
	
}

static void ip_prot_context_fini(struct trigger_instance *this)
{
	struct ip_prot_context *ip_prot_context = this->context;	
	kfree(ip_prot_context);
}


static int ip_prot_is_response(struct sniffed_packet_descr_t *descr,
			   struct packet_batch *batch)
{
	struct trigger_instance *method_instance = 
		batch->trigger;
	
	struct ip_prot_context *ip_prot_context = 
		method_instance->context;
	u16 prot_expected, prot_received;
	boolean is_response;
	
	
	prot_expected = ip_prot_context->protocol;
	prot_received = descr->icmp.unreach_protocol;


	is_response =  (descr->protocol == IPPROTO_ICMP) &&
		(descr->icmp.type == ICMP_DEST_UNREACH) &&
		(descr->icmp.code == ICMP_PROT_UNREACH) &&
		(prot_expected == prot_received) &&
		(descr->icmp.unreach_data == batch->port_indices[0]);
		
	return is_response;
	
}

static u32 ip_prot_extract_batch_id(struct sniffed_packet_descr_t *descr)
{
	if ((descr->protocol == IPPROTO_ICMP) &&
	    (descr->icmp.type == ICMP_DEST_UNREACH) &&
	    (descr->icmp.code == ICMP_PROT_UNREACH))
		return (u32) descr->icmp.unreach_data;
	
	return 0;
}



static void ip_prot_register_batch_id(struct trigger_instance *this,
				      u32 batch_id)
{
	struct ip_prot_context *context = this->context;
	
	/* Save batch_id in id */
	context->data = batch_id;	

}

static void *
ip_prot_context_copy(struct trigger_instance *this)
{
	struct ip_prot_context *context = this->context;
	
	struct ip_prot_context *new_context = 
		kmalloc(sizeof(struct ip_prot_context), GFP_KERNEL);

	if(!new_context)
		return NULL;

	memcpy(new_context, context, sizeof(struct ip_prot_context));
	
	return new_context;
	
}


static s32 ip_prot_get_round_by_descr(struct sniffed_packet_descr_t *descr)
{
	return descr->icmp.unreach_protocol;
}

static s32 ip_prot_get_round(void *context)
{
	struct ip_prot_context *c = context;

	return c->protocol;
}

static u8 ip_prot_get_default_quality(void)
{
	return IP_PROT_QUALITY;
}

struct trigger_finding_method ip_prot_method = {
	.name = "IP_PROT",
	.sender_func = &ip_prot_sender,
	.receiver_func = &ip_prot_receiver,

	.is_response = &ip_prot_is_response,

	.register_batch_id = &ip_prot_register_batch_id,
	.extract_batch_id  = &ip_prot_extract_batch_id,
	
	.get_round_by_descr = &ip_prot_get_round_by_descr,
	.get_round          = &ip_prot_get_round,

	.get_default_quality = &ip_prot_get_default_quality,

	.context_init = ip_prot_context_init,
	.context_fini = ip_prot_context_fini,

	.context_copy = ip_prot_context_copy,
	
};


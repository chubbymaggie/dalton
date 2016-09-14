#include "icmp_addr_mask_method.h"
#include "trigger_finding_methods.h"
#include "state.h"

#include "../scanner_module.h"
#include "../packet_submitter.h"
#include "../scan_job_states.h"

#include <linux/time.h>
#include <net/ip.h>

#include "../sniffer/sniffed_packet.h"
#include "../flood_state/packet_batch.h"

static void icmp_addr_mask_sender(struct scan_job_t *this,
				  struct trigger_instance *method_instance)
{
	struct icmp_addr_mask_context *context = method_instance->context;
	int icmp_data_size = 4;
	char *icmp_data = kmalloc(icmp_data_size, GFP_KERNEL);		
	
	if(!icmp_data) return;

	/* prepare icmp-data: Just a 32bit NULL-field. */
	memset(icmp_data, 0, icmp_data_size);
	

	send_icmp_packet(this->addr, ICMP_ADDRESS,
			 0, icmp_data_size,
			 icmp_data, context->batch_id);	
	
	kfree(icmp_data);
	
}

static int icmp_addr_mask_receiver(struct scan_job_t *this,
				   struct trigger_instance *method_instance,
				   struct sniffed_packet_descr_t *descr)
{
  
	struct trigger_state_context *context =
		(struct trigger_state_context *) this->state_context;
	
	
	/* If protocol and icmp-type is correct, the packet
	   is from the host this scan-job is scanning and
	   this trigger has not been reported, report it.
	*/
	
	if( (descr->protocol == IPPROTO_ICMP) &&
	    (descr->icmp.type == ICMP_ADDRESSREPLY) &&
	    (descr->src == this->addr)){
		
		trigger_instance_out(method_instance, this, 0);
		context->ntriggers_found++;
		return FINISHED;
	}			
	
	return CALL_AGAIN;
}

static int icmp_addr_mask_is_response(struct sniffed_packet_descr_t *descr,
				      struct packet_batch *batch)
{
	u32 batch_id = descr->icmp.id;
	       
	return  (batch_id == batch->port_indices[0]) &&
		(descr->protocol == IPPROTO_ICMP) &&
		(descr->icmp.type == ICMP_ADDRESSREPLY);
	
}

static int icmp_addr_mask_context_init(struct trigger_instance *this,
				       s32 unused)
{
	struct icmp_addr_mask_context *context = 
		this->context = kmalloc(sizeof(struct icmp_addr_mask_context),
					GFP_KERNEL);
	
	if(!context)
		return FAILURE;
	memset(this->context, 0, sizeof(struct icmp_addr_mask_context));
	
	this->quality = ICMP_ADDR_MASK_QUALITY;
	
	return SUCCESS;
	
}

static u32 icmp_addr_mask_extract_batch_id(struct sniffed_packet_descr_t *descr)
{
	if ((descr->protocol == IPPROTO_ICMP) &&
	    (descr->icmp.type == ICMP_ADDRESSREPLY))
		return descr->icmp.id;
	
	return 0;
}



static void icmp_addr_mask_register_batch_id(struct trigger_instance *this,
					     u32 batch_id)
{
	struct icmp_addr_mask_context *context = this->context;
	
	/* Save batch_id in id */
	context->batch_id = batch_id;
	
}

static void icmp_addr_mask_context_fini(struct trigger_instance *this)
{
	struct icmp_addr_mask_context *context = this->context;
	
	kfree(context);	
}


static void *
icmp_addr_mask_context_copy(struct trigger_instance *this)
{
	struct icmp_addr_mask_context *context = this->context;
	
	struct icmp_addr_mask_context *new_context = 
		kmalloc(sizeof(struct icmp_addr_mask_context), GFP_KERNEL);

	if(!new_context)
		return NULL;

	memcpy(new_context, context, sizeof(struct icmp_addr_mask_context));
	
	return new_context;
	
}

s32 icmp_addr_mask_get_round_by_descr(struct sniffed_packet_descr_t *descr)
{
	return 0;
}

s32 icmp_addr_mask_get_round(void *context)
{
	return 0;
}

static u8 icmp_addr_mask_get_default_quality(void)
{
	return ICMP_ADDR_MASK_QUALITY;
}

struct trigger_finding_method icmp_addr_mask_method = {
	.name = "ICMP_ADDR",
	.sender_func = &icmp_addr_mask_sender,
	.large_sender_func = NULL,
	.receiver_func = &icmp_addr_mask_receiver,
	
	.is_response = &icmp_addr_mask_is_response,
	.register_batch_id = &icmp_addr_mask_register_batch_id,
	.extract_batch_id  = &icmp_addr_mask_extract_batch_id,

	.get_round_by_descr = &icmp_addr_mask_get_round_by_descr,
	.get_round          = &icmp_addr_mask_get_round,

	.get_default_quality = &icmp_addr_mask_get_default_quality,

	.context_init = icmp_addr_mask_context_init,
	.context_fini = icmp_addr_mask_context_fini,

	.context_copy = icmp_addr_mask_context_copy,
	
};



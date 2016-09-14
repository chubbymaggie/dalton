#include "icmp_er_method.h"
#include "trigger_finding_methods.h"
#include "state.h"

#include "../scanner_module.h"
#include "../packet_submitter.h"
#include "../scan_job_states.h"

#include "../sniffer/sniffed_packet.h"
#include "../flood_state/packet_batch.h"

#include <linux/time.h>
#include <net/ip.h>


static int icmp_er_receiver(struct scan_job_t *this,
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
	    (descr->icmp.type == ICMP_ECHOREPLY) &&
	    (descr->src == this->addr)){
		
		trigger_instance_out(method_instance, this, 0);
		context->ntriggers_found++;
		return FINISHED;
	}			
	
	
	return CALL_AGAIN;
}


/*
  Options: icmp_er_data_size
           icmp_er_data

  Note: Currently the trigger-sending-functions
  are used by flood-state as well as trigger-state
  scanjob's which means you'll have to be careful
  when dereferencing this->state_context. Depending
  on this->state it can either be a trigger_state_context
  or a flood_state_context.
  
	   
*/

static void icmp_er_sender(struct scan_job_t *this,
			   struct trigger_instance *method_instance)
{
	struct icmp_er_context *context = method_instance->context;
	
	
	const int icmp_data_size = 1;
	char icmp_data[icmp_data_size];
	
	memset(icmp_data, 'a', icmp_data_size);
	
	send_icmp_packet(this->addr, ICMP_ECHO,
			 0, icmp_data_size,
			 icmp_data, context->batch_id);
	
}

static void icmp_er_large_sender(struct scan_job_t *this,
				 struct trigger_instance *method_instance)
{
	struct icmp_er_context *context = method_instance->context;
	
	
	const int icmp_data_size = 2048;
	char icmp_data[icmp_data_size];
	
	memset(icmp_data, 'a', icmp_data_size);
	
	send_icmp_packet(this->addr, ICMP_ECHO,
			 0, icmp_data_size,
			 icmp_data, context->batch_id);
	
}


static int icmp_er_context_init(struct trigger_instance *this,
				s32 unused)
{
		
	/* Allocate space for icmp_er_context */
	struct icmp_er_context *er_context = 
		this->context = kmalloc(sizeof(struct icmp_er_context), GFP_KERNEL);
	
	if(!er_context)
		return FAILURE;			
	
	this->quality = ICMP_ER_QUALITY;
	
	return SUCCESS;
}

static int icmp_er_is_response(struct sniffed_packet_descr_t *descr,
			       struct packet_batch *batch)
{
	
	u32 batch_id = descr->icmp.id;
	

	return (batch_id == batch->port_indices[0]) &&
		(descr->protocol == IPPROTO_ICMP) &&
		(descr->icmp.type == ICMP_ECHOREPLY);
	
}

static u32 icmp_er_extract_batch_id(struct sniffed_packet_descr_t *descr)
{
	if ((descr->protocol == IPPROTO_ICMP) &&
	    (descr->icmp.type == ICMP_ECHOREPLY))
		return descr->icmp.id;
	
	return 0;
}


static void icmp_register_batch_id(struct trigger_instance *this,
				   u32 batch_id)
{
	struct icmp_er_context *er_context = this->context;
		

	/* Save batch_id in id */
	er_context->batch_id = batch_id;
       	
	

}


static void icmp_er_context_fini(struct trigger_instance *this)
{	
	
}

static void *
icmp_er_context_copy(struct trigger_instance *this)
{
	struct icmp_er_context *context = this->context;
	
	struct icmp_er_context *new_context = 
		kmalloc(sizeof(struct icmp_er_context), GFP_KERNEL);

	if(!new_context)
		return NULL;

	memcpy(new_context, context, sizeof(struct icmp_er_context));
		
	return new_context;
	
}

static s32 icmp_er_get_round_by_descr(struct sniffed_packet_descr_t *descr)
{
	return 0;
}

static s32 icmp_er_get_round(void *context)
{
	return 0;
}

static u8 icmp_er_get_default_quality(void)
{
	return ICMP_ER_QUALITY;
}

struct trigger_finding_method icmp_er_method = {
	
	.name = "ICMP_ER",
	.sender_func = &icmp_er_sender,
	.large_sender_func = icmp_er_large_sender,
	.receiver_func = &icmp_er_receiver,
	
	.is_response = &icmp_er_is_response,
	.register_batch_id = &icmp_register_batch_id,
	.extract_batch_id  = &icmp_er_extract_batch_id,

	.get_round_by_descr = &icmp_er_get_round_by_descr,
	.get_round          = &icmp_er_get_round,

	.get_default_quality = &icmp_er_get_default_quality,

	.context_init = icmp_er_context_init,
	.context_fini = icmp_er_context_fini,
	
	.context_copy = icmp_er_context_copy,		
	
};

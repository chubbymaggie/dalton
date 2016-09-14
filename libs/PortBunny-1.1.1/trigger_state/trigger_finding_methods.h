#ifndef _TRIGGER_FINDING_METHODS_H
#define _TRIGGER_FINDING_METHODS_H

#include <linux/time.h>

#include "../scan_jobs.h"

#include "trigger_instance.h"


#define NO_FINDING_METHOD                  255
#define ICMP_ER_FINDING_METHOD               0
#define ICMP_TS_FINDING_METHOD               1
#define ICMP_ADDR_MASK_FINDING_METHOD        2
#define UDP_FINDING_METHOD                   3
#define TCP_SYN_FINDING_METHOD               4
#define TCP_ACK_FINDING_METHOD               5
#define IP_PROTO_FINDING_METHOD              6
#define N_FINDING_METHODS                    7

#define ALL_ROUNDS                           -1

extern struct trigger_finding_method *trigger_finding_methods[];

struct packet_batch;
struct sniffed_packet_descr_t;


typedef void (*trigger_sender_func)(struct scan_job_t *this,
				    struct trigger_instance *method_instance);
typedef int (*trigger_receiver_func)(struct scan_job_t * this,
				     struct trigger_instance *method_instance,
				     struct sniffed_packet_descr_t *descr);

typedef int (*trigger_is_response_func)(struct sniffed_packet_descr_t *descr,
					struct packet_batch *batch
					);

typedef void (*trigger_register_batch_id_func)(struct trigger_instance *method_instance,
					       u32 batch_id);

typedef int (*trigger_context_init)(struct trigger_instance *this, s32 round);
typedef void (*trigger_context_fini)(struct trigger_instance *this);

typedef void * (*trigger_copy_context)
(struct trigger_instance *node);

typedef u32 (*trigger_extract_batch_id_func)(struct sniffed_packet_descr_t *descr);

typedef s32 (*trigger_get_round_by_descr_func)(struct sniffed_packet_descr_t *descr);

typedef s32 (*trigger_get_round_func)(void *);

typedef u8 (*trigger_get_default_quality_func)(void);



struct trigger_finding_method{
	
	const char *name;	
	trigger_sender_func               sender_func;
	trigger_sender_func               large_sender_func;
	
	trigger_receiver_func             receiver_func;

	trigger_is_response_func          is_response;
	trigger_register_batch_id_func    register_batch_id;
	trigger_extract_batch_id_func     extract_batch_id;

	trigger_get_round_by_descr_func   get_round_by_descr;
	trigger_get_round_func            get_round;
	
	trigger_get_default_quality_func  get_default_quality;

	trigger_context_init context_init;
	trigger_context_fini  context_fini;
	
	trigger_copy_context context_copy;
 	
};

int method_id_by_method_name(const char *name);


#endif

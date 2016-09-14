#ifndef _SCANNER_OUTPUT_QUEUE
#define _SCANNER_OUTPUT_QUEUE

#include <linux/rwsem.h>

#include "../scanner_module.h"


/*
  As specified in the architecture-paper,
  the scanner_output_queue is a queue
  of null-terminated Strings.
*/

struct scanner_output_queue_node{
	struct rw_semaphore *lock;
	struct list_head list;
	const char *str;
};


void scanner_output_queue_add(const char *msg);
char *scanner_output_queue_head(void);

boolean scanner_output_queue_is_empty(void);

void output_msg_header(const char *addr_str,
			 const char *event_class,
			 const char *type,
			 boolean output_timestamp);

void scanner_output_queue_clear(void);

void scanner_output_queue_flush(void);

#endif

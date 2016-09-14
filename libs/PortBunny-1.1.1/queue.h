#ifndef _SCANNER_QUEUE_H
#define _SCANNER_QUEUE_H

#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/semaphore.h>
#include "scanner_module.h"


typedef int (*compare_func)(void *a, void *b);
typedef void (*delete_data_func)(void *item);
typedef boolean (*match_func)(void *item, void *aux);

/* Since locking is in kernel-space done
 * in many different ways, the user may provide
 * a lock and an up and down-function for this lock
 * which the queue will honor.
 */

struct queue_lock_t{
	
	void *lock;	
	void (*up_lock)(void *lk);
	void (*down_lock)(void *lk);
	
};

void queue_lock_up(struct queue_lock_t *this);
void queue_lock_down(struct queue_lock_t *this);

struct queue_node_t{	
	struct list_head list;
	void *data;
};

/* queue_node_t */



struct queue_t{
			
	struct queue_lock_t lock;
	int kmalloc_flags;
	struct queue_node_t root;
	struct semaphore nelems_sem;
	boolean blocking;

};

/*
   Public functions
*/

/* Constructor */

struct queue_t *create_queue(struct queue_lock_t *lock, int kmalloc_flags,
			     boolean blocking);

/* Destructor */

void delete_queue(struct queue_t *this, delete_data_func delete_data);

/* Queue-Operations */

void queue_add(struct queue_t *this, void *data);
void queue_add_front(struct queue_t *this, void *data);
void queue_ordered_add(struct queue_t *this, void *data, compare_func cmp_func);
void queue_add_limited(struct queue_t *this, void *data,
		       void (*data_destructor)(void *),
		       unsigned int max_elems);

void *queue_read_head(struct queue_t *this);
void *queue_head(struct queue_t *this, boolean block_if_empty);
void queue_clear(struct queue_t *this, delete_data_func delete_data);
int queue_remove_item(struct queue_t *this, match_func m_func,
		      void *match_aux,
		      delete_data_func delete_data);

int queue_remove_all(struct queue_t *this, match_func m_func,
		     void *match_aux,
		     delete_data_func delete_data);

void *queue_get_item(struct queue_t *this, match_func m_func, void *match_aux);

boolean is_queue_empty(struct queue_t *this);
unsigned int queue_length(struct queue_t *this);
struct queue_node_t *get_root(struct queue_t *this);

#endif

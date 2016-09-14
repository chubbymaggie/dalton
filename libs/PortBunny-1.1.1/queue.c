#include "queue.h"
#include "scanner_module.h"

#include <linux/list.h>
#include <linux/module.h>
#include <linux/kernel.h>

/* Constructor */

struct queue_t *create_queue(struct queue_lock_t *lock,
			     int kmalloc_flags, boolean blocking)
{
	/* Allocate queue  */

	struct queue_t *this = kmalloc(sizeof(struct queue_t), kmalloc_flags);
	

	if(!this)
		return NULL;
	
	if(lock)
		memcpy(&this->lock, lock, sizeof(struct queue_lock_t));
	else
		memset(&this->lock, 0, sizeof(struct queue_lock_t));
	
	this->kmalloc_flags = kmalloc_flags;
	this->blocking = blocking;
	
	/* Initialize root-node */

	INIT_LIST_HEAD(&this->root.list);
	this->root.data = NULL;

	/* Initialize nelems_sem */
	
	sema_init(&this->nelems_sem, 0);
	
	return this;
       	
}

/* Destructor */

void delete_queue(struct queue_t *this, void (*delete_data)(void *))
{
	struct queue_lock_t lock;
	
	if(!this) return;		
	
	lock = this->lock;
	
	queue_clear(this, delete_data);	
	
	queue_lock_down(&lock);
	kfree(this);
	queue_lock_up(&lock);
	
}

/* Queue-Operations */

void queue_clear(struct queue_t *this, void (*data_destructor)(void *))
{
	
	if(!this) return;
	
	if(this->lock.lock)
		queue_lock_down(&this->lock);
	

	while(!list_empty(&this->root.list)){
		
		/* retrieve next entry */

		void *data = queue_head(this, FALSE);
		
		/* Call entries destructor */

		if(data_destructor)
			data_destructor(data);
						
		if(this->blocking)
			down(&this->nelems_sem);
		
	}	

	
	
	if(this->lock.lock)
		queue_lock_up(&this->lock);
}

void queue_add(struct queue_t *this, void *data)
{
	struct queue_node_t *new_node;
	
	if(!this) return;
	
	new_node =
		kmalloc(sizeof(struct queue_node_t), this->kmalloc_flags);
	
	if(!new_node) return;
	
	if(this->lock.lock)
		queue_lock_down(&this->lock);
	

	new_node->data = data;
	INIT_LIST_HEAD(&new_node->list);
	
	list_add_tail(&new_node->list, &this->root.list);
	
	/* up the empty-mutex if we have just provided 
	 * the first element in the list.
	 */
	
	if(this->blocking)
		up(&this->nelems_sem);	

	if(this->lock.lock)
		queue_lock_up(&this->lock);
}


void queue_add_front(struct queue_t *this, void *data)
{
	
	struct queue_node_t *new_node;

	if(!this) return;

	new_node =
		kmalloc(sizeof(struct queue_node_t), this->kmalloc_flags);
	
	if(!new_node) return;
	
	if(this->lock.lock)
		queue_lock_down(&this->lock);
	

	new_node->data = data;
	INIT_LIST_HEAD(&new_node->list);
	
	list_add(&new_node->list, &this->root.list);
	
	/* up the empty-mutex if we have just provided 
	 * the first element in the list.
	 */
	
	if(this->blocking)
		up(&this->nelems_sem);	

	if(this->lock.lock)
		queue_lock_up(&this->lock);

}

void queue_ordered_add(struct queue_t *this, void *new_data, compare_func cmp_func)
{
	struct list_head *p;
	struct queue_node_t *entry;
	
	boolean queue_was_empty;
	boolean inserted = FALSE;
	
	struct queue_node_t *new_node;

	if(!this) return;

	new_node =
		kmalloc(sizeof(struct queue_node_t), this->kmalloc_flags);
	

	if(!new_node)
		return;
	
	if(this->lock.lock)
		queue_lock_down(&this->lock);
	
	queue_was_empty = list_empty(&this->root.list);
	
	new_node->data = new_data;
	INIT_LIST_HEAD(&new_node->list);
	
	
	/* add newly created node to the queue. */

	/* if list is empty, just insert the element */

	if(queue_was_empty){
		
		list_add_tail(&new_node->list, &this->root.list);
		
		if(this->blocking)
			up(&this->nelems_sem);
				
		if(this->lock.lock)
			queue_lock_up(&this->lock);
		return;
	}
		
	
	/* Search the first 'bigger' entry */
	list_for_each(p, &this->root.list){
		
		entry = list_entry(p, struct queue_node_t, list);
		
		
		/* Place to insert found */
		if(cmp_func(new_node->data, entry->data) < 0){
			
			list_add(&new_node->list, p->prev);
			inserted = TRUE;
			break;
		}

	}
	
	/* if item was not inserted, just add it to the back of the list */
	if(!inserted)
		list_add_tail(&new_node->list, &this->root.list);
		
	if(this->blocking)
		up(&this->nelems_sem);
	
	if(this->lock.lock)
		queue_lock_up(&this->lock);

}

/*
  Add data to the end of the queue.
  If the queue then contains more than
  max_elems, discard the first element
  
*/

void queue_add_limited(struct queue_t *this, void *data,
		       void (*data_destructor)(void *),
		       unsigned int max_elems)
{
	unsigned int q_length;
	
	if(!this) return;
	
	queue_add(this, data);
	
	q_length = queue_length(this);
	
	if(q_length > max_elems){
		void *head = queue_head(this, FALSE);			
		data_destructor(head);
		
	}
	

}


void *queue_read_head(struct queue_t *this)
{
	
	struct queue_node_t *entry;
	void *retval;
	
	if(!this) return NULL;

	if(this->lock.lock)
		queue_lock_down(&this->lock);
	
	if(list_empty(&this->root.list)){
		
		/* Used for non-blocking queues. */
		
		if(this->lock.lock)
			queue_lock_up(&this->lock);
		
		return NULL;
	}

	entry = list_entry( this->root.list.next,
			    struct queue_node_t, list);

	retval = entry->data;
	
	if(this->lock.lock)
		queue_lock_up(&this->lock);
	
	return retval;

}

void *queue_head(struct queue_t *this, boolean block_if_empty)
{
	struct queue_node_t *entry;
	void *retval;
	
	if(!this) return NULL;
	
	if(this->lock.lock)
		queue_lock_down(&this->lock);

	if(this->blocking && block_if_empty){
		
		if(this->lock.lock)
			queue_lock_up(&this->lock);
		
		
		down(&this->nelems_sem);
		
		if(this->lock.lock)
			queue_lock_down(&this->lock);
		
	}

	if(list_empty(&this->root.list)){
		
		/* Used for non-blocking queues. */
		
		if(this->lock.lock)
			queue_lock_up(&this->lock);
		
		return NULL;
	}

	entry = list_entry( this->root.list.next,
			    struct queue_node_t, list);

	retval = entry->data;

	list_del(&entry->list);
	kfree(entry);

	if(this->lock.lock)
		queue_lock_up(&this->lock);
	
	return retval;
}



int queue_remove_item(struct queue_t *this, match_func m_func, void *match_aux,
		      delete_data_func delete_data)
{
	struct list_head *p, *n;
	
	if(!m_func || !this)
		return FAILURE;	
	
	if(this->lock.lock)
		queue_lock_down(&this->lock);
	
	list_for_each_safe(p, n, &this->root.list){
		struct queue_node_t *entry =
			list_entry(p, struct queue_node_t, list);
		
		if( m_func(entry, match_aux) ){
			
			list_del(&entry->list);
			
			if(delete_data)
				delete_data(entry->data);
			
			kfree(entry);
			
			/* removed an element, decrease
			   semaphore-counter
			*/
			
			if(this->blocking)
				down(&this->nelems_sem);
			
			if(this->lock.lock)
				queue_lock_up(&this->lock);

			return SUCCESS;
		}
	}

	if(this->lock.lock)
		queue_lock_up(&this->lock);
	
	return FAILURE;

}


/* Remove all items from queue which match */

int queue_remove_all(struct queue_t *this, match_func m_func, void *match_aux,
		      delete_data_func delete_data)
{
	struct list_head *p, *n;
	boolean removed = FALSE;

	if(!m_func || !this)
		return FAILURE;

	
	if(this->lock.lock)
		queue_lock_down(&this->lock);
	
	list_for_each_safe(p, n, &this->root.list){
		struct queue_node_t *entry =
			list_entry(p, struct queue_node_t, list);
		
		if( m_func(entry, match_aux) ){
			
			list_del(&entry->list);
			
			if(delete_data)
				delete_data(entry->data);
			
			kfree(entry);
			
			/* removed an element, decrease
			   semaphore-counter
			*/
			
			if(this->blocking)
				down(&this->nelems_sem);
			
			if(this->lock.lock)
				queue_lock_up(&this->lock);

			removed = TRUE;
		}
	}

	if(this->lock.lock)
		queue_lock_up(&this->lock);
	
	return removed;

}



void *queue_get_item(struct queue_t *this, match_func m_func,
		     void *match_aux)
{
	struct list_head *p;
	struct queue_node_t *entry;
	
	if(!this) return NULL;

	
	list_for_each(p, &this->root.list){
		entry = list_entry(p, struct queue_node_t, list);
		
		if(m_func(entry->data, match_aux))
			return entry->data;
		
	}

	return NULL;	
}



unsigned int queue_length(struct queue_t *this)
{
	struct list_head *p;	
	unsigned int retval = 0;
	
	if(!this) return retval;
	
	list_for_each(p, &this->root.list){
				
		retval++;
		
	}

	return retval;	
}

struct queue_node_t *get_root(struct queue_t *this){ return &this->root; }

boolean is_queue_empty(struct queue_t *this)
{
	if(!this) return TRUE;
	return list_empty(&this->root.list);
}

void queue_lock_up(struct queue_lock_t *this)
{
	if(!this) return;
	if(this->lock)
		this->up_lock(this->lock);
}

void queue_lock_down(struct queue_lock_t *this)
{
	if(!this) return;
	if(this->lock)
		this->down_lock(this->lock);
}

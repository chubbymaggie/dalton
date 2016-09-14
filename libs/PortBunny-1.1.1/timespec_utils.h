#ifndef _TIME_UTILS_PATCH_H
#define _TIME_UTILS_PATCH_H

#include <linux/version.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,15)

static inline int timespec_compare(struct timespec *lhs, struct timespec *rhs)
{
         if (lhs->tv_sec < rhs->tv_sec)
                 return -1;
         if (lhs->tv_sec > rhs->tv_sec)
                 return 1;
         return lhs->tv_nsec - rhs->tv_nsec;
}

static inline s64 timespec_to_ns(const struct timespec *ts)
{
         return ((s64) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}


#endif


#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,17)

static inline void timespec_add_ns(struct timespec *a, u64 ns)
{
         ns += a->tv_nsec;
         while(unlikely(ns >= NSEC_PER_SEC)) {
                 ns -= NSEC_PER_SEC;
                 a->tv_sec++;
         }
         a->tv_nsec = ns;
}


static inline struct timespec timespec_sub(struct timespec lhs,
                                                 struct timespec rhs)
{
	struct timespec ts_delta;
	set_normalized_timespec(&ts_delta, lhs.tv_sec - rhs.tv_sec,
				lhs.tv_nsec - rhs.tv_nsec);
	return ts_delta;
}



static inline int list_is_last(const struct list_head *list,
                                 const struct list_head *head)
{
         return list->next == head;
}

#endif

#endif

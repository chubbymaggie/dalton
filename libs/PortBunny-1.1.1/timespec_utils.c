#include <linux/version.h>
#include <asm/div64.h>
#include <linux/time.h>

/*
  Hack: fixme, if you can.

  'set_normalized_timespec' is usually
  provided by linux/time.c and is declared as
  'extern' in linux/time.h. However, when
  building a module, only the kernel-headers
  are available so we are left with an undefined
  reference to 'set_normalized_timespec'.

  Since set_normalized timespec is used by
  various important timespec-utility-functions
  such as timespec_sub or ns_to_timespec, I have
  decided to provide it myself. 

*/


#ifndef div_long_long_rem

static inline unsigned long do_div_llr(const long long dividend,
                                        const long divisor, long *remainder)
{
         u64 result = dividend;
 
         *(remainder) = do_div(result, divisor);
         return (unsigned long) result;
}

#define div_long_long_rem(dividend, divisor, remainder) \
         do_div_llr((dividend), divisor, remainder)


#endif
 
static inline long div_long_long_rem_signed(const long long dividend,
                                             const long divisor, long *remainder)
{
         long res;
 
         if (unlikely(dividend < 0)) {
                 res = -div_long_long_rem(-dividend, divisor, remainder);
                 *remainder = -(*remainder);
         } else
                 res = div_long_long_rem(dividend, divisor, remainder);
 
         return res;
 }
 

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)

void set_normalized_timespec(struct timespec *ts, time_t sec, long nsec)
{
         while (nsec >= NSEC_PER_SEC) {
                 nsec -= NSEC_PER_SEC;
                 ++sec;
         }
         while (nsec < 0) {
                 nsec += NSEC_PER_SEC;
                 --sec;
        }
         ts->tv_sec = sec;
         ts->tv_nsec = nsec;
}

#endif


struct timespec ns_to_timespec(const s64 nsec)
{
	struct timespec ts;
	
	if (!nsec)
		return (struct timespec) {0, 0};
 
	ts.tv_sec = div_long_long_rem_signed(nsec, NSEC_PER_SEC, &ts.tv_nsec);
	if (unlikely(nsec < 0))
		set_normalized_timespec(&ts, ts.tv_sec, ts.tv_nsec);
	
	return ts;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,17)

static inline struct timespec timespec_sub(struct timespec lhs,
					   struct timespec rhs)
{
	struct timespec ts_delta;
	set_normalized_timespec(&ts_delta, lhs.tv_sec - rhs.tv_sec,
				lhs.tv_nsec - rhs.tv_nsec);
	return ts_delta;
}


void  __stack_chk_fail(void)
{
         panic("stack-protector: Kernel stack is corrupted");
}

//EXPORT_SYMBOL(__stack_chk_fail);

#endif

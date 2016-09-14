#ifndef _SCANNER_MODULE_H
#define _SCANNER_MODULE_H

#include <linux/time.h>

#undef SUCCESS
#define SUCCESS 0
#undef FAILURE
#define FAILURE -1

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

typedef __u8 boolean;

#undef FINISHED
#define FINISHED 0
#undef CALL_AGAIN
#define CALL_AGAIN 1

#undef NSEC_PER_MSEC
#define NSEC_PER_MSEC   1000000L

#define PBUNNY_VERSION "1.1.1"

#endif

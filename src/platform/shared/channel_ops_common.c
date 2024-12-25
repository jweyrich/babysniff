#include "channel_ops_common.h"
//#include <errno.h>
//#include <stdio.h>
#include <string.h>

// NOTE: Not thread-safe! We should use strerror_r instead.
const char *sniff_strerror(int errcode) {
//#if defined(HAVE_STRERROR) || defined(_LIBC)
	return strerror(errcode);
// #else
// 	static char buffer[64];
// 	if (errcode < sys_nerr)
// 		return sys_errlist[errcode];
// 	snprintf(buffer, sizeof(buffer), "Unknown error: %d", errcode);
// 	return buffer;
// #endif
}

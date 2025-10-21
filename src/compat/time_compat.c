#include "compat/time_compat.h"

#include "system.h"

#ifdef OS_WINDOWS
struct tm *gmtime_r(const time_t *timep, struct tm *result) {
	// Windows has gmtime_s instead of gmtime_r
	// gmtime_s has different parameter order: gmtime_s(result, timep)
	// Returns 0 on success, non-zero on failure
	if (gmtime_s(result, timep) == 0) {
		return result;
	}
	return NULL;
}
#endif // OS_WINDOWS

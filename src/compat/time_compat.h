#pragma once

#include "system.h"

#include <time.h>

#ifdef OS_WINDOWS
struct tm *gmtime_r(const time_t *timep, struct tm *result);
#endif

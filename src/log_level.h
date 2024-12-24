#pragma once

#include <stdbool.h>

typedef enum {
	LOGLEVEL_FATAL = 0,
	LOGLEVEL_ERROR, // Default log level
	LOGLEVEL_WARN,
	LOGLEVEL_INFO,
	LOGLEVEL_DEBUG,
	LOGLEVEL_TRACE,
} log_level_e;


bool log_level_is_valid(int level);
int log_level_set(int level);
log_level_e log_level_get(void);
const char *log_level_name(log_level_e level);

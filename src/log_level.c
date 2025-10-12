#include "log_level.h"
#include <stdio.h>

static log_level_e g_loglevel = LOGLEVEL_WARN;

bool log_level_is_valid(int level) {
    return level >= LOGLEVEL_FATAL && level <= LOGLEVEL_TRACE;
}

int log_level_set(int level) {
    if (!log_level_is_valid(level)) {
        fprintf(stderr, "Invalid log level %d\n", level);
        return -1;
    }
    g_loglevel = level;
    return 0;
}

log_level_e log_level_get(void) {
	return g_loglevel;
}

const char *log_level_name(log_level_e level) {
    if (!log_level_is_valid(level)) {
        fprintf(stderr, "Invalid log level %d\n", level);
        return "UNKNOWN";
    }

    static const char *level_name[] = {
		"UNSET",
        "FATAL",
        "ERROR",
        "WARN",
        "INFO",
        "DEBUG",
        "TRACE",
    };
    return level_name[level];
}

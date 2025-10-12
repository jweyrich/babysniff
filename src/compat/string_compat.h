#pragma once

#include "system.h"

#include <stddef.h>

#ifdef OS_WINDOWS
// Windows doesn't have strndup
char *strndup(char const *s, size_t n);

// Windows doesn't have strtok_r, so we provide a wrapper for strtok_s
char *strtok_r(char *str, const char *delim, char **saveptr);
#endif

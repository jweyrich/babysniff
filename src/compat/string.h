#pragma once

#include <stddef.h>
#include <string.h>

#ifndef strnlen
size_t strnlen(const char *s, size_t maxlen);
#endif

#ifndef strndup
char *strndup(char const *s, size_t n);
#endif

#ifndef fast_strcat
char *fast_strcat(char *dest, char *src);
#endif

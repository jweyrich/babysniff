#include "compat/string_compat.h"

#include "system.h"

#include <stdlib.h> // for malloc
#include <string.h> // for memcpy, strnlen, strtok_s

#ifdef OS_WINDOWS

// Windows doesn't have strndup
char *strndup(const char *str, size_t n) {
	size_t len = strnlen(str, n);
	char *result = malloc(len + 1);
	if (result == NULL)
		return NULL;
	result[len] = '\0';
	return memcpy(result, str, len);
}

// Windows doesn't have strtok_r, so we provide a wrapper for strtok_s
char *strtok_r(char *str, const char *delim, char **saveptr) {
	return strtok_s(str, delim, saveptr);
}
#endif // OS_WINDOWS

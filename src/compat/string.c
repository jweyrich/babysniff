#include "compat/string.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef strnlen
size_t strnlen(const char *s, size_t maxlen) {
	const char *p;
	for (p = s; *p && maxlen--; ++p);
	return p - s;
}
#endif // ifndef strnlen

#ifndef strndup
char *strndup(const char *str, size_t n) {
	size_t len = strnlen(str, n);
	char *result = malloc(len + 1);
	if (result == NULL)
		return NULL;
	result[len] = '\0';
	return memcpy(result, str, len);
}
#endif // ifndef strndup

#ifndef fast_strcat
char *fast_strcat(char *dest, char *src) {
	 while (*dest != '\0') dest++;
	 while ((*dest++ = *src++) != '\0');
	 return --dest;
}
#endif // ifndef fast_strcat

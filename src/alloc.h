#pragma once

#include <stdlib.h>

#define BASE_SAFE_FREE(p) \
	do { \
		if ((p) != NULL) { \
			free((p)); \
			(p) = NULL; \
		} \
	} while (0)

//
// Use these
//
#define safe_free(p)			BASE_SAFE_FREE(p)

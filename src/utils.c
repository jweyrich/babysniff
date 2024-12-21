#include "utils.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

char *utils_in_addr_to_str(char *output, size_t output_len, const struct in_addr *input) {
	char buf[INET_ADDRSTRLEN];

	if (output_len < INET_ADDRSTRLEN) {
        return NULL;
    }
	if (!inet_ntop(AF_INET, input, buf, (socklen_t)sizeof(buf))) {
		return NULL;
    }

	int w = snprintf(output, output_len, "%s", buf);
	// Check error and truncation
	if (w < 0 || w >= (int)output_len) {
		return NULL;
	}
	return output;
}

char *utils_in6_addr_to_str(char *output, size_t output_len, const struct in6_addr *input) {
#ifdef AF_INET6
	char buf[INET6_ADDRSTRLEN];

	if (output_len < INET6_ADDRSTRLEN) {
        return NULL;
    }
	if (!inet_ntop(AF_INET6, input, buf, (socklen_t)sizeof(buf))) {
		return NULL;
    }

	int w = snprintf(output, output_len, "%s", buf);
	// Check error and truncation
	if (w < 0 || w >= (int)output_len) {
		return NULL;
	}
	return output;
#else
	return NULL;
#endif
}

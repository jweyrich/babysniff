#include "utils.h"
#include <arpa/inet.h> // for struct in_addr + in6_addr
#include <netinet/if_ether.h> // for struct ether_addr
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>

char *utils_ether_addr_to_str(char *output, size_t output_size, const struct ether_addr *input) {
	if (output_size < ETHER_ADDR_LEN * 3) { // Minimum size is 18 bytes including the null terminator
        return NULL;
    }
	const unsigned char *buffer = input->ether_addr_octet;
	int w = snprintf(output, output_size, "%02x:%02x:%02x:%02x:%02x:%02x",
		buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
	// Check error and truncation
	if (w < 0 || w >= (int)output_size) {
		return NULL;
	}
	return output;
}

char *utils_in_addr_to_str(char *output, size_t output_size, const struct in_addr *input) {
	char buf[INET_ADDRSTRLEN];

	if (output_size < INET_ADDRSTRLEN) {
        return NULL;
    }
	if (!inet_ntop(AF_INET, input, buf, (socklen_t)sizeof(buf))) {
		return NULL;
    }

	int w = snprintf(output, output_size, "%s", buf);
	// Check error and truncation
	if (w < 0 || w >= (int)output_size) {
		return NULL;
	}
	return output;
}

char *utils_in6_addr_to_str(char *output, size_t output_size, const struct in6_addr *input) {
#ifdef AF_INET6
	char buf[INET6_ADDRSTRLEN];

	if (output_size < INET6_ADDRSTRLEN) {
        return NULL;
    }
	if (!inet_ntop(AF_INET6, input, buf, (socklen_t)sizeof(buf))) {
		return NULL;
    }

	int w = snprintf(output, output_size, "%s", buf);
	// Check error and truncation
	if (w < 0 || w >= (int)output_size) {
		return NULL;
	}
	return output;
#else
	return NULL;
#endif
}

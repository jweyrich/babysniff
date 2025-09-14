#include "utils.h"
#include <arpa/inet.h> // for struct in_addr + in6_addr
#include <netinet/if_ether.h> // for struct ether_addr
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h> // for strlen

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

int utils_relative_path(char *output, size_t output_size, const char *absolute_path) {
	static const char *current_file_path = __FILE__; // Current file path
	size_t abs_len = strlen(absolute_path);
	if (abs_len >= output_size) {
		return -1; // Output buffer too small
	}
	// Find the last '/' in both paths
	const char *cur_last_slash = strrchr(current_file_path, '/');
	const char *abs_last_slash = strrchr(absolute_path, '/');
	if (!cur_last_slash || !abs_last_slash) {
		return -1; // Invalid path format
	}
	size_t cur_dir_len = cur_last_slash - current_file_path + 1; // Include the '/'
	size_t abs_dir_len = abs_last_slash - absolute_path + 1; // Include the '/'
	// Compare directory parts
	if (cur_dir_len > abs_dir_len || strncmp(current_file_path, absolute_path, cur_dir_len) != 0) {
		// No common directory, return the original absolute path
		if (abs_len + 1 > output_size) {
			return -1; // Output buffer too small
		}
		strncpy(output, absolute_path, output_size);
		output[output_size - 1] = '\0'; // Ensure null termination
		return 0;
	}
	// Common directory found, construct relative path
	const char *relative_part = absolute_path + cur_dir_len;
	size_t relative_part_len = abs_len - cur_dir_len;
	if (relative_part_len + 1 > output_size) {
		return -1; // Output buffer too small
	}
	strncpy(output, relative_part, relative_part_len);
	output[relative_part_len] = '\0'; // Ensure null termination
	return 0;
}

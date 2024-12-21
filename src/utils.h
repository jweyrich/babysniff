#pragma once

#include <netinet/in.h>
#include <stddef.h>

// Convert a `dns_rdata_a_t` structure to a string representation.
char *utils_in_addr_to_str(char *output, size_t output_len, const struct in_addr *input);

// Convert a `dns_rdata_aaaa_t` structure to a string representation.
char *utils_in6_addr_to_str(char *output, size_t output_len, const struct in6_addr *input);

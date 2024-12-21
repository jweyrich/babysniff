#pragma once

#include <stddef.h>

struct ether_addr; // Forward declaration
struct in_addr; // Forward declaration
struct in6_addr; // Forward declaration

// Convert a `struct ether_addr` structure to a string representation.
char *utils_ether_addr_to_str(char *output, size_t output_size, const struct ether_addr *input);

// Convert a `dns_rdata_a_t` structure to a string representation.
char *utils_in_addr_to_str(char *output, size_t output_size, const struct in_addr *input);

// Convert a `dns_rdata_aaaa_t` structure to a string representation.
char *utils_in6_addr_to_str(char *output, size_t output_size, const struct in6_addr *input);

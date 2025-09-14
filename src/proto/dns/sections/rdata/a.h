#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef struct dns_rr dns_rr_t;

//
// A
//
typedef struct dns_rdata_a {
	uint32_t	address[1]; // Internet address
} dns_rdata_a_t;

int parse_rdata_a(dns_rr_t *rr, buffer_t *buffer);
void free_rdata_a(dns_rr_t *rr);

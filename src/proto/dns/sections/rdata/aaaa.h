#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef struct dns_rr dns_rr_t;

//
// AAAA
//
typedef struct dns_rdata_aaaa {
	uint32_t	address[4]; // Internet address
} dns_rdata_aaaa_t;

int parse_rdata_aaaa(dns_rr_t *rr, buffer_t *buffer);
void free_rdata_aaaa(dns_rr_t *rr);

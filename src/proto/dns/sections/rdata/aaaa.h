#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef union dns_rdata dns_rdata_t;

//
// AAAA
//
typedef struct dns_rdata_aaaa {
	uint32_t	address[4]; // Internet address
} dns_rdata_aaaa_t;

int parse_rdata_aaaa(dns_rdata_t *rdata, buffer_t *buffer);
void free_rdata_aaaa(dns_rdata_t *rdata);
void print_rdata_aaaa(dns_rdata_t *rdata);

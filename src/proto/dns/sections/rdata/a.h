#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef union dns_rdata dns_rdata_t;

//
// A
//
typedef struct dns_rdata_a {
	uint32_t	address[1]; // Internet address
} dns_rdata_a_t;

int parse_rdata_a(dns_rdata_t *rdata, buffer_t *buffer);
void free_rdata_a(dns_rdata_t *rdata);
void print_rdata_a(dns_rdata_t *rdata);

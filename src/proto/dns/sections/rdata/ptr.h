#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef struct dns_rr dns_rr_t;

//
// PTR
//
typedef struct dns_rdata_ptr {
	char *	name; // Domain name which points to some location in the domain name space
} dns_rdata_ptr_t;

int parse_rdata_ptr(dns_rr_t *rr, buffer_t *buffer);
void free_rdata_ptr(dns_rr_t *rr);

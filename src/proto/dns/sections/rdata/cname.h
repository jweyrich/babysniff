#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef struct dns_rr dns_rr_t;

//
// CNAME
//
typedef struct dns_rdata_cname {
	char *	name; // Canonical or primary name for the owner. The owner name is an alias
} dns_rdata_cname_t;

int parse_rdata_cname(dns_rr_t *rr, buffer_t *buffer);
void free_rdata_cname(dns_rr_t *rr);

#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef union dns_rdata dns_rdata_t;

//
// CNAME
//
typedef struct dns_rdata_cname {
	char *	name; // Canonical or primary name for the owner. The owner name is an alias
} dns_rdata_cname_t;

int parse_rdata_cname(dns_rdata_t *rdata, buffer_t *buffer);
void free_rdata_cname(dns_rdata_t *rdata);
void print_rdata_cname(dns_rdata_t *rdata);

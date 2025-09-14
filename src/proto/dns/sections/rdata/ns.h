#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef union dns_rdata dns_rdata_t;

//
// NS
//
typedef struct dns_rdata_ns {
	char *	name; // Host which should be authoritative for the specified class and domain
} dns_rdata_ns_t;

int parse_rdata_ns(dns_rdata_t *rdata, buffer_t *buffer);
void free_rdata_ns(dns_rdata_t *rdata);
void print_rdata_ns(dns_rdata_t *rdata);

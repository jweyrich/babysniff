#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef struct dns_rr dns_rr_t;

//
// MX
//
typedef struct dns_rdata_mx {
	uint16_t	preference; // Preference given to this RR among others at the same owner
	char *	  exchange; // Host willing to act as a mail exchange for the owner name
} dns_rdata_mx_t;

int parse_rdata_mx(dns_rr_t *rr, buffer_t *buffer);
void free_rdata_mx(dns_rr_t *rr);
void print_rdata_mx(dns_rr_t *rr);

#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef union dns_rdata dns_rdata_t;

//
// RRSIG
//
// REFERENCE: https://datatracker.ietf.org/doc/html/rfc4034#section-3.1
typedef struct dnssec_rrsig {
	uint16_t	typec;	// Type covered
	uint8_t		algnum; // Algorithm number
	uint8_t		labels;
	uint32_t	original_ttl;
	uint32_t	signature_expiration;
	uint32_t	signature_inception;
	uint16_t	key_tag;
	char *		signer_name;
	char *		signature;
} dnssec_rdata_rrsig_t;

int parse_rdata_rrsig(dns_rdata_t *rdata, buffer_t *buffer);
void free_rdata_rrsig(dns_rdata_t *rdata);
void print_rdata_rrsig(dns_rdata_t *rdata);

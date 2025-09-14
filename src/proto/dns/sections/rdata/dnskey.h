#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef union dns_rdata dns_rdata_t;

//
// DNSKEY
//
// REFERENCE: https://datatracker.ietf.org/doc/html/rfc4034#section-2.1
typedef struct dnssec_dnskey {
	uint16_t	flags;		// Flags
	uint8_t		protocol;	// Protocol
	uint8_t		algorithm;	// Algorithm
	char *		public_key;	// Public key
} dnssec_rdata_dnskey_t;

int parse_rdata_dnskey(dns_rdata_t *rdata, buffer_t *buffer);
void free_rdata_dnskey(dns_rdata_t *rdata);
void print_rdata_dnskey(dns_rdata_t *rdata);

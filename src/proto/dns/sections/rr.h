#pragma once

#include "proto/dns/sections/rdata.h"
#include "proto/dns/types.h"

typedef struct buffer buffer_t; // Forward declaration

//
// RR
//
typedef struct dns_rr {
	char *			name; // Domain name
	dns_qtype_e		qtype:16; // Type of the data in the RDATA field
	dns_qclass_e	qclass:16; // Class of the data in the RDATA field
	uint32_t		ttl; // How long to keep it cached, in seconds (0 = do not cache)
	uint16_t		rdlen; // Length of the RDATA field, in bytes
	dns_rdata_t		rdata;
} dns_rr_t;

dns_rr_t *parse_rr(buffer_t *buffer);
void free_rr(dns_rr_t *rr);
void print_rr(dns_rr_t *rr);

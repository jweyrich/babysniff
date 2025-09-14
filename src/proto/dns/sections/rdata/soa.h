#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef struct dns_rr dns_rr_t;

//
// SOA
//
typedef struct dns_rdata_soa {
	char *  	mname; // Server that was the original or primary source of data for this zone
	char *  	rname; // Mailbox mailbox of the person responsible for this zone
	uint32_t	serial; // Version number of the original copy of the zone
	int32_t	 	refresh; // Time interval before the zone should be refreshed
	int32_t 	retry; // Time interval that should elapse before a failed refresh should be retried
	int32_t	 	expire; // Upper limit on the time interval that can elapse before the zone is no longer authoritative
	uint32_t	minimum; // Minimum TTL for any RR from this zone
} dns_rdata_soa_t;

int parse_rdata_soa(dns_rr_t *rr, buffer_t *buffer);
void free_rdata_soa(dns_rr_t *rr);

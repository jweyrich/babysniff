/**
 *	References:
 *		http://svn.apache.org/repos/asf/httpd/sandbox/mod_domain
 *		http://svn.skullsecurity.org:81/ron/security/nbtool/dns.c
 **/

#pragma once

#include "proto/dns/types.h"
#include <stdint.h>

//
// Flags
//
#pragma pack(1)
typedef struct dns_hdr_flags {
#if BYTE_ORDER == BIG_ENDIAN
	dns_flag_e		qr:1; // Flag for query (0) or response (1)
	dns_opcode_e	opcode:4; // Kind of query
	dns_flag_e		aa:1; // Authoritative Answer
	dns_flag_e		tc:1; // Truncated response
	dns_flag_e		rd:1; // Recursion desired
	// byte boundry
	dns_flag_e		ra:1; // Recursion allowed
	uint8_t			z:1; // Unused bit - Reserved for future use
	uint8_t			ad:1; // Authenticated data
	uint8_t			cd:1; // Checking disabled
	dns_rcode_e		rcode:4; // Response code
#elif BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN
	dns_rcode_e		rcode:4; // Response code
	uint8_t			cd:1; // Checking disabled
	uint8_t			ad:1; // Authentic data
	uint8_t			z:1; // Unused bit
	dns_flag_e		ra:1; // Recursion allowed
	// byte boundry
	dns_flag_e		rd:1; // Recursion desired
	dns_flag_e		tc:1; // Truncated response
	dns_flag_e		aa:1; // Authoritative Answer
	dns_opcode_e	opcode:4; // Operation Code
	dns_flag_e		qr:1; // Query/Response flag
#endif
} dns_hdr_flags_t;
#pragma pack()

//
// Header
//
typedef struct dns_hdr {
	uint16_t	id;
	union {
		uint16_t		single;
		dns_hdr_flags_t	expanded;
	} flags;
	uint16_t	qd_c; // # of entries in the question section
	uint16_t	an_c; // # of resource records in the answer section
	uint16_t	ns_c; // # of resource records in the authority section
	uint16_t	ar_c; // # of resource records in the additional section
} dns_hdr_t;

#define DNS_HDR_LEN 12


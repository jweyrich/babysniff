#pragma once

#include "proto/dns/sections/rdata/a.h"
#include "proto/dns/sections/rdata/aaaa.h"
#include "proto/dns/sections/rdata/cname.h"
#include "proto/dns/sections/rdata/mx.h"
#include "proto/dns/sections/rdata/ns.h"
#include "proto/dns/sections/rdata/ptr.h"
#include "proto/dns/sections/rdata/rrsig.h"
#include "proto/dns/sections/rdata/soa.h"
#include "proto/dns/sections/rdata/txt.h"
#include "proto/dns/sections.h"

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
	union rdata {
		dns_rdata_a_t			a;
		dns_rdata_aaaa_t		aaaa;
		dns_rdata_ns_t			ns;
		dns_rdata_cname_t		cname;
		dns_rdata_soa_t			soa;
		dns_rdata_ptr_t			ptr;
		dns_rdata_mx_t			mx;
		dns_rdata_txt_t			txt;
		dnssec_rdata_rrsig_t	rrsig;
	} rdata;
} dns_rr_t;

dns_rr_t *parse_rr(buffer_t *buffer);
void free_rr(dns_rr_t *rr);
void print_rr(dns_rr_t *rr);

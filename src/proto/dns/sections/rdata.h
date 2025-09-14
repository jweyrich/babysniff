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

// Forward declarations
typedef struct buffer buffer_t;
typedef struct dns_rr dns_rr_t;

//
// RDATA
//
typedef union dns_rdata {
	dns_rdata_a_t			a;
	dns_rdata_aaaa_t		aaaa;
	dns_rdata_ns_t			ns;
	dns_rdata_cname_t		cname;
	dns_rdata_soa_t			soa;
	dns_rdata_ptr_t			ptr;
	dns_rdata_mx_t			mx;
	dns_rdata_txt_t			txt;
	dnssec_rdata_rrsig_t	rrsig;
} dns_rdata_t;

int parse_rdata(dns_rr_t *rr, buffer_t *buffer);
void free_rdata(dns_rr_t *rr);
void print_rdata(dns_rr_t *rr);

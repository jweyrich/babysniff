#pragma once

typedef struct dns_hdr_flags dns_hdr_flags_t; // Forward declaration
typedef struct pair_array pair_array_t; // Forward declaration

typedef enum dns_array {
	DNS_ARRAY_OPCODE,
	DNS_ARRAY_RCODE,
	DNS_ARRAY_QTYPE,
	DNS_ARRAY_QCLASS,
	DNSSEC_ARRAY_ALGORITHM
} dns_array_e;

const pair_array_t *select_array(dns_array_e type);
const char *totext(dns_array_e type, int key);
int fromtext(dns_array_e type, const char *value);
const char *flags_totext(const dns_hdr_flags_t *value);

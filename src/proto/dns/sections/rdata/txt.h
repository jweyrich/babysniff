#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef struct dns_rr dns_rr_t;

//
// TXT
//
typedef struct dns_rdata_txt {
	char *	data; // Descriptive human-readable text
} dns_rdata_txt_t;

int parse_rdata_txt(dns_rr_t *rr, buffer_t *buffer);
void free_rdata_txt(dns_rr_t *rr);

#pragma once

#include <stdint.h>

// Forward declarations
typedef struct buffer buffer_t;
typedef union dns_rdata dns_rdata_t;

//
// TXT
//
typedef struct dns_rdata_txt {
	char *	data; // Descriptive human-readable text
} dns_rdata_txt_t;

int parse_rdata_txt(dns_rdata_t *rdata, buffer_t *buffer);
void free_rdata_txt(dns_rdata_t *rdata);
void print_rdata_txt(dns_rdata_t *rdata);

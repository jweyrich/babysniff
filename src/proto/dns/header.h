#pragma once

typedef struct buffer buffer_t; // Forward declaration
typedef struct dns_hdr dns_hdr_t; // Forward declaration

dns_hdr_t *parse_header(buffer_t *buffer);
void free_header(dns_hdr_t *header);
void print_header(dns_hdr_t *header);

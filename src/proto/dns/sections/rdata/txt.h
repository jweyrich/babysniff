#pragma once

typedef struct buffer buffer_t; // Forward declaration

//
// TXT
//
typedef struct dns_rdata_txt {
	char *	data; // Descriptive human-readable text
} dns_rdata_txt_t;

char *parse_txtdata(buffer_t *buffer);
void free_txtdata(char *data);

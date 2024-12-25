#pragma once

#include <stddef.h>

typedef struct buffer buffer_t; // Forward declaration

//
// Labels
//
//typedef struct dns_label {
//	uint8	length;
//	char *	partial;
//} dns_label_t;

#define DNS_NAME_MAXLEN			255 // Max length of an uncompressed domain name
#define DNS_LABEL_MAXLEN		63
#define DNS_LABEL_COMPRESS_MASK	(DNS_NAME_MAXLEN - DNS_LABEL_MAXLEN)

char *parse_name(buffer_t *buffer);
void free_name(char *name);
size_t predict_name_length(buffer_t *buffer);

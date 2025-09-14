#pragma once

#include "proto/dns/types.h"

// Forward declarations
typedef struct buffer buffer_t;

//
// Question
//
typedef struct dns_question {
	char *			name; // Domain name
	dns_qtype_e		qtype:16; // Type of the query
	dns_qclass_e	qclass:16; // Class of the query
} dns_question_t;

dns_question_t *parse_question(buffer_t *buffer);
void free_question(dns_question_t *question);
void print_question(dns_question_t *question);

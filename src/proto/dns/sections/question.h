#pragma once

typedef struct buffer buffer_t; // Forward declaration
typedef struct dns_question dns_question_t; // Forward declaration

dns_question_t *parse_question(buffer_t *buffer);
void free_question(dns_question_t *question);
void print_question(dns_question_t *question);

#pragma once

typedef struct buffer buffer_t; // Forward declaration

char *parse_rrsig_signature(buffer_t *buffer);

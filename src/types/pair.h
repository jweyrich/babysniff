#pragma once

#include <stddef.h>
#include <inttypes.h>

typedef struct pair {
    int				key;
    const char *	value;
} pair_t;

typedef struct pair_array {
    size_t			count;
    const pair_t	*data;
} pair_array_t;

pair_t *pair_array_first(const pair_array_t *array);
pair_t *pair_array_last(const pair_array_t *array);
pair_t *pair_array_lookup_key(const pair_array_t *array, int key);
pair_t *pair_array_lookup_value(const pair_array_t *array, const char *value);

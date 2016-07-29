#pragma once

#include <stdio.h>
#include <stddef.h>
#include "types.h"

void print_bits(FILE *stream, uint64_t value, size_t size);
void dump_hex(FILE *stream, const byte *data, size_t size, uint32_t offset);

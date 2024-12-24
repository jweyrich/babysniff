#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

void print_bits(FILE *stream, uint64_t value, size_t size);
void dump_hex(FILE *stream, const uint8_t *data, size_t size, uint32_t offset);

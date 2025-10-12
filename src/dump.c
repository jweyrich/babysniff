#include "dump.h"
#include <ctype.h>

void print_bits(FILE *stream, uint64_t value, size_t size) {
    size *= 8;
    for (size_t i = 0; i < size; ++i) {
        size_t bit_pos = size - 1 - i;
        fputc((value & (1ULL << bit_pos)) == 0 ? '0' : '1', stream);
    }
}

void dump_hex(FILE *stream, const uint8_t *data, size_t size, uint32_t offset) {
    int ch;
    size_t i, j;
    uint32_t cols;

    for (i = 0; i < size; i += 16) {
        fprintf(stream, "%04x: ", (uint32_t)i + offset);
        size_t remaining = size - i;
        cols = remaining > 16 ? 16 : (uint32_t)remaining;

        for (j = 0; j < cols; ++j) {
            if ((j % 2) == 0)
                fprintf(stream, "%02x", (uint32_t)data[i+j]);
            else
                fprintf(stream, "%02x ", (uint32_t)data[i+j]);
        }
        for (; j < 16; ++j) {
            fprintf(stream, "%*s", (j % 2) == 0 ? 2 : 3, " ");
        }
        fprintf(stream, " ");

        for (j = 0; j < cols; ++j) {
            ch = data[i+j];
            ch = isprint(ch) ? ch : '.';
            fprintf(stream, "%c", ch);
        }
        fprintf(stream, "\n");
    }
}

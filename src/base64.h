#pragma once

#include <stddef.h>

size_t base64_encoded_size(size_t input_size);
int base64_encode(char *result, size_t resultSize, const void *input, size_t inputSize);

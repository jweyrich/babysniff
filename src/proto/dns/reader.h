#pragma once

#include "types/buffer.h"

uint8_t *read_bytes(buffer_t *from_buffer, int *error, size_t size);
char *read_bytes_and_base64(buffer_t *from_buffer, int *error, size_t size);

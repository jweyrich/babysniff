
#include "reader.h"
#include "base64.h"
#include "types/buffer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

uint8_t *read_bytes(buffer_t *from_buffer, int *error, size_t size) {
    if (from_buffer == NULL || error == NULL) {
        *error = -1; // Invalid parameters
        return NULL;
    }

    if (buffer_has_error(from_buffer)) {
        *error = -2; // Buffer has an error
        return NULL;
    }

    uint8_t *data = malloc(size);
    if (data == NULL) {
        *error = -4; // Memory allocation failed
        return NULL;
    }

    int read = buffer_read(from_buffer, data, size);
    if (read <= 0) {
        *error = -5; // Buffer read failed
        free(data);
        return NULL;
    }
    return data;
}

char *read_bytes_and_base64(buffer_t *from_buffer, int *error, size_t size) {
	uint8_t *data = read_bytes(from_buffer, error, size);
    if (data == NULL) {
        // error is already set by read_bytes
        return NULL;
    }

    // encode to base64
    size_t encoded_size = base64_encoded_size(size) + 1; // +1 for null terminator
    char *encoded = malloc(encoded_size);
    if (encoded == NULL) {
        *error = -4; // Memory allocation failed
        free(data);
        return NULL;
    }

    int encode_ret = base64_encode(encoded, encoded_size, data, size);
    if (encode_ret != 1) {
        *error = -6; // Base64 encoding failed
        free(data);
        free(encoded);
        return NULL;
    }
    free(data);
    return encoded;
}

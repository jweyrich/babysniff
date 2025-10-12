#include "types/buffer.h"

#include "compat/string_compat.h"
#include "log.h"
#include "system.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int buffer_can_access_relative_offset(buffer_t *buffer, size_t relative_offset) {
    if (buffer->current + relative_offset > buffer->size) {
        buffer->error.code = BUFFER_EOVERFLOW;
        buffer->error.info.memreq = buffer->current + relative_offset;
        LOG_WARN("Attempt to access an invalid offset (buffer=%p size=%zu offset=%zu)",
            buffer, buffer->size, relative_offset);
        return 0;
    }
    return 1;
}

static int buffer_can_access_absolute_offset(buffer_t *buffer, size_t offset) {
    if (offset >= buffer->size) {
        buffer->error.code = BUFFER_EOVERFLOW;
        buffer->error.info.memreq = offset;
        LOG_WARN("Attempt to access an invalid offset (buffer=%p size=%zu offset=%zu)",
            buffer, buffer->size, offset);
        return 0;
    }
    return 1;
}

// static void *buffer_safe_alloc(buffer_t *buffer, size_t size) {
//     void *ptr = malloc(size);
//     if (ptr == NULL) {
//         buffer->error.code = BUFFER_ENOMEM;
//         LOG_ERROR("Allocation failure (size=%zd)", size);
//         return NULL;
//     }
//     return ptr;
// }

static void *buffer_safe_realloc(buffer_t *buffer, void *ptr, size_t size) {
    ptr = realloc(ptr, size);
    if (ptr == NULL && size != 0) {
        buffer->error.code = BUFFER_ENOMEM;
        LOG_ERROR("Reallocation failure (ptr=%p size=%zd)", ptr, size);
        return NULL;
    }
    return ptr;
}

buffer_t *buffer_alloc(size_t size) {
    buffer_t *buffer = malloc(sizeof(buffer_t));
    if (buffer == NULL)
        return NULL;
    BUFFER_INIT(buffer);
    buffer->size = size;
    buffer->data = malloc(size);
    if (size != 0 && buffer->data == NULL) {
        free(buffer);
        LOG_ERROR("Allocation failure (size=%zd)", size);
        return NULL;
    }
    return buffer;
}

int buffer_realloc_data(buffer_t *buffer, size_t size) {
    if (size == buffer->size)
        return 0; // nothing to do
    buffer->data = buffer_safe_realloc(buffer, buffer->data, size);
    if (size != 0 && buffer->data == NULL)
        return -1; // error already set by buffer_safe_realloc
    // decreased size
    if (size < buffer->size) {
        if (size < buffer->current)
            buffer->current = size;
        if (size < buffer->used)
            buffer->used = size;
    }
    buffer->size = size;
    return 0;
}

buffer_t *buffer_free(buffer_t *buffer) {
    if (buffer == NULL)
        return NULL;
    free(buffer->data);
    free(buffer);
    return NULL;
}

int buffer_error(const buffer_t *buffer) {
    return buffer->error.code;
}

size_t buffer_error_memreq(const buffer_t *buffer) {
    return buffer->error.info.memreq;
}

int buffer_has_error(const buffer_t *buffer) {
    return buffer->error.code == BUFFER_NOERROR ? 0 : 1;
}

void buffer_clear_error(buffer_t *buffer) {
    buffer->error.code = BUFFER_NOERROR;
}

void buffer_set_data(buffer_t *buffer, uint8_t *data, size_t size) {
    buffer->data = data;
    buffer->size = size;
    buffer->used = size;
    buffer->current = 0;
}

uint8_t *buffer_data(const buffer_t *buffer) {
    return buffer->data;
}

uint8_t *buffer_data_ptr(const buffer_t *buffer) {
    return buffer->data + buffer->current;
}

size_t buffer_size(const buffer_t *buffer) {
    return buffer->size;
}

size_t buffer_used(const buffer_t *buffer) {
    return buffer->used;
}

void buffer_clear(buffer_t *buffer) {
    buffer->used = 0;
}

size_t buffer_left(const buffer_t *buffer) {
    return buffer->size - buffer->used;
}

size_t buffer_tell(const buffer_t *buffer) {
    return buffer->current;
}

size_t buffer_seek(buffer_t *buffer, size_t offset) {
    if (!buffer_can_access_absolute_offset(buffer, offset))
        return 0;
    buffer->current = offset;
    return offset;
}

/**
 * @brief
 * Skip _offset_ bytes from the current position.
 * If _offset_ is negative, it will rewind the buffer.
 * If the _offset_ is not reachable, it will return 0.
 *
 * @param buffer    The buffer to skip
 * @param offset    The number of bytes to skip
 * @return uint32_t The absolute number of bytes skipped, otherwise 0.
 */
size_t buffer_skip(buffer_t *buffer, ptrdiff_t offset) {
    if (offset == 0)
        return 0;

    size_t new_offset;
    if (offset > 0) {
        new_offset = buffer->current + (size_t)offset;
    } else {
        if ((size_t)(-offset) > buffer->current) {
            buffer->error.code = BUFFER_EUNDERFLOW;
            LOG_WARN("Attempt to skip to negative position (buffer=%p current=%zu offset=%td)",
                buffer, buffer->current, offset);
            return 0;
        }
        new_offset = buffer->current - (size_t)(-offset);
    }

    if (!buffer_can_access_absolute_offset(buffer, new_offset))
        return 0;
    buffer->current = new_offset;
    return (size_t)(offset > 0 ? offset : -offset);
}

size_t buffer_rewind(buffer_t *buffer) {
    return buffer_seek(buffer, 0);
}

size_t buffer_remaining(const buffer_t *buffer) {
    return buffer->size - buffer->current;
}

size_t buffer_read(buffer_t *buffer, uint8_t *output, size_t size) {
    uint8_t *data = buffer_data_ptr(buffer);
    if (!buffer_can_access_relative_offset(buffer, size))
        return 0;
    memcpy(output, (const void*)data, size);
    buffer->current += size;
    return size;
}

uint8_t buffer_read_byte(buffer_t *buffer) {
    if (!buffer_can_access_relative_offset(buffer, 1))
        return 0;
    uint8_t *data = buffer_data_ptr(buffer);
    buffer->current += 1;
    uint8_t output = ((uint8_t)data[0]);
    return output;
}

int8_t buffer_read_int8(buffer_t *buffer) {
    return buffer_read_byte(buffer);
}

int16_t buffer_read_int16(buffer_t *buffer) {
    if (!buffer_can_access_relative_offset(buffer, 2))
        return 0;
    uint8_t *data = buffer_data_ptr(buffer);
    buffer->current += 2;
    int16_t output = ((int16_t)data[1]) << 8;
    output |= ((int16_t)data[0]);
    return output;
}

int32_t buffer_read_int32(buffer_t *buffer) {
    if (!buffer_can_access_relative_offset(buffer, 4))
        return 0;
    uint8_t *data = buffer_data_ptr(buffer);
    buffer->current += 4;
    int32_t output = ((int32_t)data[3]) << 24;
    output |= ((int32_t)data[2]) << 16;
    output |= ((int32_t)data[1]) << 8;
    output |= ((int32_t)data[0]);
    return output;
}

int64_t buffer_read_int64(buffer_t *buffer) {
    if (!buffer_can_access_relative_offset(buffer, 8))
        return 0;
    uint8_t *data = buffer_data_ptr(buffer);
    buffer->current += 8;
    int64_t output = ((int64_t)data[7]) << 56;
    output |= ((int64_t)data[6]) << 48;
    output |= ((int64_t)data[5]) << 40;
    output |= ((int64_t)data[4]) << 32;
    output |= ((int64_t)data[3]) << 24;
    output |= ((int64_t)data[2]) << 16;
    output |= ((int64_t)data[1]) << 8;
    output |= ((int64_t)data[0]);
    return output;
}

uint8_t buffer_read_uint8(buffer_t *buffer) {
    return buffer_read_int8(buffer);
}

uint16_t buffer_read_uint16(buffer_t *buffer) {
    return buffer_read_int16(buffer);
}

uint32_t buffer_read_uint32(buffer_t *buffer) {
    return buffer_read_int32(buffer);
}

uint64_t buffer_read_uint64(buffer_t *buffer) {
    return buffer_read_int64(buffer);
}

char *buffer_strncpy(buffer_t *buffer, char *output, size_t size) {
    if (!buffer_can_access_relative_offset(buffer, size))
        return NULL;
    // Copy _size_ characters, or until a \0 is found
    strncpy(output, (const char *)buffer_data_ptr(buffer), size);
    // TODO(jweyrich): should we advance only strlen(output) bytes ?
    buffer->current += size; // No \0 here
    return output;
}

char *buffer_strdup(buffer_t *buffer) {
    char *copy;
#ifdef OS_WINDOWS
    copy = _strdup((const char *)buffer_data_ptr(buffer));
#else
    copy = strdup((const char *)buffer_data_ptr(buffer));
#endif
    buffer->current += strlen(copy) + 1; // length + \0
    return copy;
}

char *buffer_strndup(buffer_t *buffer, size_t size) {
    char *copy;
    if (!buffer_can_access_relative_offset(buffer, size))
        return NULL;
    copy = strndup((const char *)buffer_data_ptr(buffer), size);
    buffer->current += strlen(copy); // No \0 here
    return copy;
}

size_t buffer_write(buffer_t *buffer, const uint8_t *input, size_t size) {
    uint8_t *data = buffer_data_ptr(buffer);
    if (!buffer_can_access_relative_offset(buffer, size))
        return 0;
    memcpy(data, input, size);
    buffer->current += size;
    buffer->used += size;
    return size;
}

void buffer_write_byte(buffer_t *buffer, uint8_t input) {
    // TODO(jweyrich): rewrite this like the read functions
    uint8_t *data = buffer_data_ptr(buffer);
    if (!buffer_can_access_relative_offset(buffer, 1))
        return;
    *data = input & 0xff;
    ++buffer->current;
    ++buffer->used;
}

void buffer_write_int8(buffer_t *buffer, int8_t input) {
    buffer_write_byte(buffer, input);
}

void buffer_write_int16(buffer_t *buffer, int16_t input) {
    buffer_write_int8(buffer, input >> 8);
    buffer_write_int8(buffer, input & 0xff);
}

void buffer_write_int32(buffer_t *buffer, int32_t input) {
    buffer_write_int16(buffer, input >> 16);
    buffer_write_int16(buffer, input & 0xffff);
}

void buffer_write_int64(buffer_t *buffer, int64_t input) {
    buffer_write_int32(buffer, input >> 32);
    buffer_write_int32(buffer, input & 0xffffffff);
}

void buffer_write_uint8(buffer_t *buffer, uint8_t input) {
    buffer_write_int8(buffer, input);
}

void buffer_write_uint16(buffer_t *buffer, uint16_t input) {
    buffer_write_int16(buffer, input);
}

void buffer_write_uint32(buffer_t *buffer, uint32_t input) {
    buffer_write_int32(buffer, input);
}

void buffer_write_uint64(buffer_t *buffer, uint64_t input) {
    buffer_write_int64(buffer, input);
}

void buffer_write_string(buffer_t *buffer, const char *input) {
    uint8_t *data = buffer_data_ptr(buffer);
    size_t size = strlen(input) + 1; // length + \0
    if (!buffer_can_access_relative_offset(buffer, size))
        return;
    strcpy((char *)data, input);
    buffer->current += size;
    buffer->used += size;
}

int buffer_write_format(buffer_t *buffer, const char *format, ...) {
    uint8_t *data = buffer_data_ptr(buffer);
    size_t available = buffer_left(buffer);
    va_list ap;
    va_start(ap, format);
    int length = vsnprintf((char *)data, available, format, ap);
    va_end(ap);
    if (length > 0) {
        size_t written = (size_t)(length + 1); // length + \0
        buffer->current += written;
        buffer->used += written;
    }
    return length;
}

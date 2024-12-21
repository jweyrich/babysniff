#include "types/buffer.h"
#include "compat/string_compat.h"
#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int buffer_safe_size(buffer_t *buffer, uint32_t offset) {
    if (buffer->size < buffer->current + offset) {
        buffer->error.code = BUFFER_EOVERFLOW;
        buffer->error.info.memreq = buffer->current + offset;
        LOG_WARN("Attempt to access an invalid offset (buffer=%p size=%u offset=%u)",
            buffer, buffer->size, offset);
        return 0;
    }
    return 1;
}

static int buffer_safe_offset(buffer_t *buffer, int offset) {
    int cur_size = (int)buffer->size;
    if (offset >= cur_size) {
        buffer->error.code = BUFFER_EOVERFLOW;
        buffer->error.info.memreq = offset;
        LOG_WARN("Attempt to access an invalid offset (buffer=%p size=%u offset=%d)",
            buffer, buffer->size, offset);
        return 0;
    }
    if (offset < 0) {
        buffer->error.code = BUFFER_EUNDERFLOW;
        LOG_WARN("Attempt to access an invalid offset (buffer=%p size=%u offset=%d)",
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

buffer_t *buffer_alloc(uint32_t size) {
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

int buffer_realloc_data(buffer_t *buffer, uint32_t size) {
    if (size == buffer->size)
        return size;
    buffer->data = buffer_safe_realloc(buffer, buffer->data, size);
    if (size != 0 && buffer->data == NULL)
        return -1;
    // decreased size
    if (size < buffer->size) {
        if (size < buffer->current)
            buffer->current = size;
        if (size < buffer->used)
            buffer->used = size;
    }
    buffer->size = size;
    return size;
}

buffer_t *buffer_free(buffer_t *buffer) {
    if (buffer->data != NULL)
        free(buffer->data);
    free(buffer);
    return NULL;
}

inline int buffer_error(const buffer_t *buffer) {
    return buffer->error.code;
}

inline int buffer_error_memreq(const buffer_t *buffer) {
    return buffer->error.info.memreq;
}

inline int buffer_has_error(const buffer_t *buffer) {
    return buffer->error.code == BUFFER_NOERROR ? 0 : 1;
}

inline void buffer_clear_error(buffer_t *buffer) {
    buffer->error.code = BUFFER_NOERROR;
}

inline void buffer_set_data(buffer_t *buffer, byte *data, uint32_t size) {
    buffer->data = data;
    buffer->size = size;
    buffer->used = size;
    buffer->current = 0;
}

inline byte *buffer_data(const buffer_t *buffer) {
    return buffer->data;
}

inline byte *buffer_data_ptr(const buffer_t *buffer) {
    return buffer->data + buffer->current;
}

inline uint32_t buffer_size(const buffer_t *buffer) {
    return buffer->size;
}

inline uint32_t buffer_used(const buffer_t *buffer) {
    return buffer->used;
}

inline void buffer_clear(buffer_t *buffer) {
    buffer->used = 0;
}

inline uint32_t buffer_left(const buffer_t *buffer) {
    return buffer->size - buffer->used;
}

inline uint32_t buffer_tell(const buffer_t *buffer) {
    return buffer->current;
}

uint32_t buffer_seek(buffer_t *buffer, uint32_t offset) {
    if (!buffer_safe_offset(buffer, offset))
        return 0;
    buffer->current = offset;
    return offset;
}

uint32_t buffer_skip(buffer_t *buffer, int offset) {
    if (offset == 0)
        return 0;
    int new_offset = offset + (int)buffer->current;
    if (!buffer_safe_offset(buffer, new_offset))
        return 0;
    buffer->current = (uint32_t)new_offset;
    return abs(offset);
}

uint32_t buffer_rewind(buffer_t *buffer) {
    return buffer_seek(buffer, 0);
}

int buffer_read(buffer_t *buffer, byte *output, size_t size) {
    byte *data = buffer_data_ptr(buffer);
    if (!buffer_safe_size(buffer, size))
        return 0;
    memcpy(output, (const void*)data, size);
    buffer->current += size;
    return size;
}

byte buffer_read_byte(buffer_t *buffer) {
    if (!buffer_safe_size(buffer, 1))
        return 0;
    byte *data = buffer_data_ptr(buffer);
    buffer->current += 1;
    byte output = ((byte)data[0]);
    return output;
}

inline int8_t buffer_read_int8(buffer_t *buffer) {
    return buffer_read_byte(buffer);
}

int16_t buffer_read_int16(buffer_t *buffer) {
    if (!buffer_safe_size(buffer, 2))
        return 0;
    byte *data = buffer_data_ptr(buffer);
    buffer->current += 2;
    int16_t output = ((int16_t)data[1]) << 8;
    output |= ((int16_t)data[0]);
    return output;
}

int32_t buffer_read_int32(buffer_t *buffer) {
    if (!buffer_safe_size(buffer, 4))
        return 0;
    byte *data = buffer_data_ptr(buffer);
    buffer->current += 4;
    int32_t output = ((int32_t)data[3]) << 24;
    output |= ((int32_t)data[2]) << 16;
    output |= ((int32_t)data[1]) << 8;
    output |= ((int32_t)data[0]);
    return output;
}

int64_t buffer_read_int64(buffer_t *buffer) {
    if (!buffer_safe_size(buffer, 8))
        return 0;
    byte *data = buffer_data_ptr(buffer);
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

inline uint8_t buffer_read_uint8(buffer_t *buffer) {
    return buffer_read_int8(buffer);
}

inline uint16_t buffer_read_uint16(buffer_t *buffer) {
    return buffer_read_int16(buffer);
}

inline uint32_t buffer_read_uint32(buffer_t *buffer) {
    return buffer_read_int32(buffer);
}

inline uint64_t buffer_read_uint64(buffer_t *buffer) {
    return buffer_read_int64(buffer);
}

char *buffer_strncpy(buffer_t *buffer, char *output, size_t size) {
    if (!buffer_safe_size(buffer, size))
        return NULL;
    // Copy _size_ characters, or until a \0 is found
    strncpy(output, (const char *)buffer_data_ptr(buffer), size);
    // TODO(jweyrich): should we advance only strlen(output) bytes ?
    buffer->current += size; // No \0 here
    return output;
}

char *buffer_strdup(buffer_t *buffer) {
    char *copy;
    copy = strdup((const char *)buffer_data_ptr(buffer));
    buffer->current += strlen(copy) + 1; // length + \0
    return copy;
}

char *buffer_strndup(buffer_t *buffer, size_t size) {
    char *copy;
    if (!buffer_safe_size(buffer, size))
        return NULL;
    copy = strndup((const char *)buffer_data_ptr(buffer), size);
    buffer->current += strlen(copy); // No \0 here
    return copy;
}

int buffer_write(buffer_t *buffer, const byte *input, size_t size) {
    byte *data = buffer_data_ptr(buffer);
    if (!buffer_safe_size(buffer, size))
        return 0;
    memcpy(data, input, size);
    buffer->current += size;
    buffer->used += size;
    return size;
}

void buffer_write_byte(buffer_t *buffer, byte input) {
    // TODO(jweyrich): rewrite this like the read functions
    byte *data = buffer_data_ptr(buffer);
    if (!buffer_safe_size(buffer, 1))
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

inline void buffer_write_uint8(buffer_t *buffer, uint8_t input) {
    buffer_write_int8(buffer, input);
}

inline void buffer_write_uint16(buffer_t *buffer, uint16_t input) {
    buffer_write_int16(buffer, input);
}

inline void buffer_write_uint32(buffer_t *buffer, uint32_t input) {
    buffer_write_int32(buffer, input);
}

inline void buffer_write_uint64(buffer_t *buffer, uint64_t input) {
    buffer_write_int64(buffer, input);
}

void buffer_write_string(buffer_t *buffer, const char *input) {
    byte *data = buffer_data_ptr(buffer);
    size_t size = strlen(input) + 1; // length + \0
    if (!buffer_safe_size(buffer, size))
        return;
    strcpy((char *)data, input);
    buffer->current += size;
    buffer->used += size;
}

int buffer_write_format(buffer_t *buffer, const char *format, ...) {
    byte *data = buffer_data_ptr(buffer);
    int length = buffer_left(buffer);
    va_list ap;
    va_start(ap, format);
    length = vsnprintf((char *)data, length, format, ap);
    va_end(ap);
    buffer->current += length + 1; // length + \0
    buffer->used += length + 1; // length + \0
    return length;
}

#pragma once

#include <stdint.h>
#include <stddef.h>

//
// Types
//
typedef struct buffer {
    uint8_t *data;
    uint32_t size;
    uint32_t used;
    uint32_t current;
    struct {
        int code;
        union info {
            uint32_t memreq;
        } info;
    } error;
} buffer_t;

typedef enum {
    BUFFER_NOERROR		= 0,
    BUFFER_EOVERFLOW	= -1,
    BUFFER_EUNDERFLOW	= -2,
    BUFFER_ENOMEM		= -3
} buffer_error_e;

//
// Initialization
//
#define BUFFER_INITIALIZER \
    { NULL, 0, 0, 0, { BUFFER_NOERROR, { 0 } } }
#define BUFFER_INIT(var) \
    do { \
        buffer_t *ptr = (var); \
        ptr->data = NULL; \
        ptr->size = (var)->used = (var)->current = 0; \
        ptr->error.code = BUFFER_NOERROR; \
        memset(&ptr->error.info, 0, sizeof(ptr->error.info)); \
    } while (0)

//
// Allocation
//
buffer_t *buffer_alloc(uint32_t length);
buffer_t *buffer_free(buffer_t *buffer);
int buffer_realloc_data(buffer_t *buffer, uint32_t size);

//
// Error handling
//
int buffer_error(const buffer_t *buffer);
int buffer_error_memreq(const buffer_t *buffer);
int buffer_has_error(const buffer_t *buffer);
void buffer_clear_error(buffer_t *buffer);

//
// ...
//
uint8_t *buffer_data_ptr(const buffer_t *buffer);
// TODO(jweyrich): create int buffer_search(input, size)
// TODO(jweyrich): create int buffer_compare(input, size)


//
// Properties
//
void buffer_set_data(buffer_t *buffer, uint8_t *data, uint32_t size);
uint8_t *buffer_data(const buffer_t *buffer);
uint32_t buffer_size(const buffer_t *buffer);
uint32_t buffer_used(const buffer_t *buffer);
void buffer_clear(buffer_t *buffer);
uint32_t buffer_left(const buffer_t *buffer);

//
// Position
//
uint32_t buffer_tell(const buffer_t *buffer);
uint32_t buffer_seek(buffer_t *buffer, uint32_t offset);
uint32_t buffer_skip(buffer_t *buffer, int offset);
uint32_t buffer_rewind(buffer_t *buffer);
uint32_t buffer_remaining(const buffer_t *buffer);

//
// Reading (from network-byte-order to host-byte-order)
//
int buffer_read(buffer_t *buffer, uint8_t *output, size_t size);
uint8_t buffer_read_byte(buffer_t *buffer);
int8_t buffer_read_int8(buffer_t *buffer);
int16_t buffer_read_int16(buffer_t *buffer);
int32_t buffer_read_int32(buffer_t *buffer);
int64_t buffer_read_int64(buffer_t *buffer);
uint8_t buffer_read_uint8(buffer_t *buffer);
uint16_t buffer_read_uint16(buffer_t *buffer);
uint32_t buffer_read_uint32(buffer_t *buffer);
uint64_t buffer_read_uint64(buffer_t *buffer);
char *buffer_strncpy(buffer_t *buffer, char *output, size_t size);
char *buffer_strdup(buffer_t *buffer);
char *buffer_strndup(buffer_t *buffer, size_t size);

//
// Writing (from host-byte-order to network-byte-order)
//
// TODO(jweyrich): how to deal with _used_ on writing operations?
int buffer_write(buffer_t *buffer, const uint8_t *input, size_t size);
void buffer_write_byte(buffer_t *buffer, uint8_t input);
void buffer_write_int8(buffer_t *buffer, int8_t input);
void buffer_write_int16(buffer_t *buffer, int16_t input);
void buffer_write_int32(buffer_t *buffer, int32_t input);
void buffer_write_int64(buffer_t *buffer, int64_t input);
void buffer_write_uint8(buffer_t *buffer, uint8_t input);
void buffer_write_uint16(buffer_t *buffer, uint16_t input);
void buffer_write_uint32(buffer_t *buffer, uint32_t input);
void buffer_write_uint64(buffer_t *buffer, uint64_t input);
void buffer_write_string(buffer_t *buffer, const char *input);
int buffer_write_format(buffer_t *buffer, const char *format, ...);

#include "name.h"
#include "log.h"
#include "types/buffer.h"
#include <stdlib.h>
#include <string.h>

char *parse_name(buffer_t *buffer) {
	int label_count = 0;
	int compressed = 0;
	size_t total_len = 0, orig_pos = 0, label_len;

	char *name = malloc(DNS_NAME_MAXLEN+1);
	if (name == NULL)
		return NULL;

	for (;;) {
		label_len = buffer_read_uint8(buffer);
		// LOG_DEBUG("label_len is %zd", label_len);
		if (buffer_has_error(buffer))
			goto error;
		if (label_len == 0) { // null label?
			// A null label indicates the end of the name.
			// LOG_DEBUG("null label");
			break;
		}
		if (label_len & DNS_LABEL_COMPRESS_MASK) { // compressed label?
			uint32_t new_off;
			compressed++;
			// get the new offset
			new_off = buffer_read_uint8(buffer);
			// LOG_DEBUG("new_off is %#zx", new_off);
			if (buffer_has_error(buffer))
				goto error;
			// keep the original position
			if (compressed == 1) {
				orig_pos = buffer_tell(buffer);
				// LOG_DEBUG("orig_pos is %#zx", orig_pos);
			}
			// move to new offset
			buffer_seek(buffer, new_off);
			if (buffer_has_error(buffer))
				goto error;
			continue;
		} else if (label_len > DNS_LABEL_MAXLEN) { // invalid size?
			LOG_WARN("DNS name label size is invalid (exceeded max label size)");
			goto error;
		}
		total_len += label_len;
		if (total_len > DNS_NAME_MAXLEN) { // overflow?
			LOG_WARN("DNS name size is invalid (exceeded max name size)");
			goto error;
		}
		// LOG_DEBUG("copying from %#x", buffer_tell(buffer));
		buffer_strncpy(buffer, name + total_len - label_len, label_len);
		if (buffer_has_error(buffer))
			goto error;
		memset(name + total_len, '.', 1);
		total_len += 1;
		++label_count;
	}
	if (compressed != 0) {
		// move back to original position
		buffer_seek(buffer, orig_pos);
		// LOG_DEBUG("jumped back to %#zx", orig_pos);
	}
	if (label_count > 0) {
		name[total_len - 1] = 0;
		return name;
	} else {
		// LOG_WARN("DNS name has no labels");
		return NULL;
	}
error:
	LOG_WARN("DNS name is invalid");
	free(name);
	return NULL;
}

void free_name(char *name) {
	free(name);
}

size_t predict_name_length(buffer_t *buffer) {
	int label_count = 0;
	size_t orig_pos, label_len, total_len = 0;

	orig_pos = buffer_tell(buffer);
	// LOG_DEBUG("starting at %#x", orig_pos);
	for (;;) {
		label_len = buffer_read_uint8(buffer);
		// LOG_DEBUG("label_len = %zd", label_len);
		if (buffer_has_error(buffer))
			goto error;
		if (label_len == 0) // null label?
			break;
		if (label_len & DNS_LABEL_COMPRESS_MASK) { // compressed label?
			// get the new offset
			uint32_t new_off = buffer_read_uint8(buffer);
			// LOG_DEBUG("new offset is %#zx", new_off);
			if (buffer_has_error(buffer))
				goto error;
			buffer_seek(buffer, new_off);
			if (buffer_has_error(buffer))
				goto error;
			continue;
		} else if (label_len > DNS_LABEL_MAXLEN) { // invalid size?
			goto error;
		}
		total_len += label_len;
		if (total_len > DNS_NAME_MAXLEN) // overflow?
			goto error;
		// LOG_DEBUG("skiping from %#x", buffer_tell(buffer));
		buffer_skip(buffer, label_len);
		if (buffer_has_error(buffer))
			goto error;
		total_len += 1; // dot separator
		++label_count;
	}
	// move back to original position
	buffer_seek(buffer, orig_pos);
	// LOG_DEBUG("jumped back to %#zx", orig_pos);
	if (label_count > 0)
		return total_len;
error:
	LOG_WARN("DNS name is invalid");
	return 0;
}


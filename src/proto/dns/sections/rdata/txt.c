#include "txt.h"
#include "log.h"
#include "types/buffer.h"
#include <stdlib.h>

char *parse_txtdata(buffer_t *buffer) {
	char *data = NULL;
	size_t length;

	length = buffer_read_uint8(buffer);
	if (buffer_has_error(buffer))
		goto error;
	if (length == 0)
		goto error;
	data = malloc(length+1);
	if (data == NULL)
		return NULL;
	buffer_strncpy(buffer, data, length);
	if (buffer_has_error(buffer))
		goto error;
	data[length] = 0;
	return data;
error:
	if (data != NULL) {
		LOG_WARN("Invalid data");
		free(data);
	}
	return NULL;
}

void free_txtdata(char *data) {
	if (data == NULL)
		return;
	free(data);
}

#include "txt.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/sections/rr.h"
#include <stdlib.h>

static char *parse_data(buffer_t *buffer) {
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

int parse_rdata_txt(dns_rr_t *rr, buffer_t *buffer) {
	rr->rdata.txt.data = parse_data(buffer);
	if (rr->rdata.txt.data == NULL) {
		LOG_WARN("TXT data is NULL");
		return -1;
	}
	return 0;
}

void free_rdata_txt(dns_rr_t *rr) {
	free(rr->rdata.txt.data);
}

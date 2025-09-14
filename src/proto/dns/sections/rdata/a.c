#include "a.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/sections/rr.h"
#include <stdlib.h>

int parse_rdata_a(dns_rr_t *rr, buffer_t *buffer) {
	rr->rdata.a.address[0] = buffer_read_uint32(buffer);
	if (buffer_has_error(buffer)) {
		LOG_WARN("detected an error in the buffer while reading RR of type A");
		return -1;
	}
	return 0;
}

void free_rdata_a(dns_rr_t *rr) {
    // Nothing to do
}

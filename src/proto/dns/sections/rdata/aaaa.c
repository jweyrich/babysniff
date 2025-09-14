#include "aaaa.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/sections/rr.h"

int parse_rdata_aaaa(dns_rr_t *rr, buffer_t *buffer) {
	for (size_t i=0; i<4; i++) {
		rr->rdata.aaaa.address[i] = buffer_read_uint32(buffer);
		if (buffer_has_error(buffer)) {
			LOG_WARN("detected an error in the buffer while reading RR of type AAAA");
			return -1;
		}
	}
	return 0;
}

void free_rdata_aaaa(dns_rr_t *rr) {
    // Nothing to do
}

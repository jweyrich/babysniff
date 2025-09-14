#include "ptr.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rr.h"

int parse_rdata_ptr(dns_rr_t *rr, buffer_t *buffer) {
	rr->rdata.ptr.name = parse_name(buffer);
	if (rr->rdata.ptr.name == NULL) {
		LOG_WARN("PTR name is NULL");
		return -1;
	}
	return 0;
}

void free_rdata_ptr(dns_rr_t *rr) {
    free_name(rr->rdata.ptr.name);
}

void print_rdata_ptr(dns_rr_t *rr) {
	LOG_PRINTF("%s\n", rr->rdata.ptr.name);
}

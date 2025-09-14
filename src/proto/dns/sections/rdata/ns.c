#include "ns.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rr.h"

int parse_rdata_ns(dns_rr_t *rr, buffer_t *buffer) {
	rr->rdata.ns.name = parse_name(buffer);
	if (rr->rdata.ns.name == NULL) {
		LOG_WARN("NS name is NULL");
		return -1;
	}
	return 0;
}

void free_rdata_ns(dns_rr_t *rr) {
    free_name(rr->rdata.ns.name);
}

void print_rdata_ns(dns_rr_t *rr) {
	LOG_PRINTF("%s\n", rr->rdata.ns.name);
}

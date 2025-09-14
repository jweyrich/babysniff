#include "cname.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rr.h"

int parse_rdata_cname(dns_rr_t *rr, buffer_t *buffer) {
	rr->rdata.cname.name = parse_name(buffer);
	if (rr->rdata.cname.name == NULL) {
		LOG_WARN("CNAME name is NULL");
		return -1;
	}
	return 0;
}

void free_rdata_cname(dns_rr_t *rr) {
    free_name(rr->rdata.cname.name);
}

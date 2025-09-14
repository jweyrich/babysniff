#include "cname.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rdata.h"

int parse_rdata_cname(dns_rdata_t *rdata, buffer_t *buffer) {
	rdata->cname.name = parse_name(buffer);
	if (rdata->cname.name == NULL) {
		LOG_WARN("CNAME name is NULL");
		return -1;
	}
	return 0;
}

void free_rdata_cname(dns_rdata_t *rdata) {
    free_name(rdata->cname.name);
}

void print_rdata_cname(dns_rdata_t *rdata) {
	LOG_PRINTF("%s\n", rdata->cname.name);
}

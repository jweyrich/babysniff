#include "ns.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rdata.h"

int parse_rdata_ns(dns_rdata_t *rdata, buffer_t *buffer) {
	rdata->ns.name = parse_name(buffer);
	if (rdata->ns.name == NULL) {
		LOG_WARN("NS name is NULL");
		return -1;
	}
	return 0;
}

void free_rdata_ns(dns_rdata_t *rdata) {
    free_name(rdata->ns.name);
}

void print_rdata_ns(dns_rdata_t *rdata) {
	LOG_PRINTF("%s\n", rdata->ns.name);
}

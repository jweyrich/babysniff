#include "ptr.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rdata.h"

int parse_rdata_ptr(dns_rdata_t *rdata, buffer_t *buffer) {
	rdata->ptr.name = parse_name(buffer);
	if (rdata->ptr.name == NULL) {
		LOG_WARN("PTR name is NULL");
		return -1;
	}
	return 0;
}

void free_rdata_ptr(dns_rdata_t *rdata) {
    free_name(rdata->ptr.name);
}

void print_rdata_ptr(dns_rdata_t *rdata) {
	LOG_PRINTF("%s\n", rdata->ptr.name);
}

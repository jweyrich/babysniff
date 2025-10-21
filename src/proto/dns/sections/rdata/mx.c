#include "mx.h"

#include "compat/network_compat.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rdata.h"

int parse_rdata_mx(dns_rdata_t *rdata, buffer_t *buffer) {
	rdata->mx.preference = buffer_read_uint16(buffer);
	if (buffer_has_error(buffer)) {
		LOG_WARN("detected an error in the buffer while reading RR of type MX");
		return -1;
	}
	rdata->mx.exchange = parse_name(buffer);
	if (rdata->mx.exchange == NULL) {
		LOG_WARN("MX exchange is NULL");
		return -1;
	}
	rdata->mx.preference = ntohs(rdata->mx.preference);
	return 0;
}

void free_rdata_mx(dns_rdata_t *rdata) {
    free_name(rdata->mx.exchange);
}

void print_rdata_mx(dns_rdata_t *rdata) {
	LOG_PRINTF("%u\t%s\n",
		rdata->mx.preference,
		rdata->mx.exchange);
}

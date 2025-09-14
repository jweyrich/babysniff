#include "mx.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rr.h"
#include <netinet/in.h> // for ntohs

int parse_rdata_mx(dns_rr_t *rr, buffer_t *buffer) {
	rr->rdata.mx.preference = buffer_read_uint16(buffer);
	if (buffer_has_error(buffer)) {
		LOG_WARN("detected an error in the buffer while reading RR of type MX");
		return -1;
	}
	rr->rdata.mx.exchange = parse_name(buffer);
	if (rr->rdata.mx.exchange == NULL) {
		LOG_WARN("MX exchange is NULL");
		return -1;
	}
	rr->rdata.mx.preference = ntohs(rr->rdata.mx.preference);
	return 0;
}

void free_rdata_mx(dns_rr_t *rr) {
    free_name(rr->rdata.mx.exchange);
}

void print_rdata_mx(dns_rr_t *rr) {
	LOG_PRINTF("%u\t%s\n",
		rr->rdata.mx.preference,
		rr->rdata.mx.exchange);
}

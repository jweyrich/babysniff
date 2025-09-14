#include "soa.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rr.h"

int parse_rdata_soa(dns_rr_t *rr, buffer_t *buffer) {
	rr->rdata.soa.mname = parse_name(buffer);
	if (rr->rdata.soa.mname == NULL) {
		LOG_WARN("SOA mname is NULL");
		return -1;
	}
	rr->rdata.soa.rname = parse_name(buffer);
	if (rr->rdata.soa.rname == NULL) {
		LOG_WARN("SOA rname is NULL");
		return -1;
	}
	rr->rdata.soa.serial = buffer_read_uint32(buffer);
	rr->rdata.soa.refresh = buffer_read_int32(buffer);
	rr->rdata.soa.retry = buffer_read_int32(buffer);
	rr->rdata.soa.expire = buffer_read_int32(buffer);
	rr->rdata.soa.minimum = buffer_read_uint32(buffer);
	if (buffer_has_error(buffer)) {
		LOG_WARN("detected an error in the buffer while reading RR of type SOA");
		return -1;
	}
	rr->rdata.soa.serial = ntohl(rr->rdata.soa.serial);
	rr->rdata.soa.refresh = ntohl(rr->rdata.soa.refresh);
	rr->rdata.soa.retry = ntohl(rr->rdata.soa.retry);
	rr->rdata.soa.expire = ntohl(rr->rdata.soa.expire);
	rr->rdata.soa.minimum = ntohl(rr->rdata.soa.minimum);
	return 0;
}

void free_rdata_soa(dns_rr_t *rr) {
    free_name(rr->rdata.soa.mname);
	free_name(rr->rdata.soa.rname);
}

void print_rdata_soa(dns_rr_t *rr) {
	LOG_PRINTF("%s %s %u %d %d %d %u\n",
		rr->rdata.soa.mname,
		rr->rdata.soa.rname,
		rr->rdata.soa.serial,
		rr->rdata.soa.refresh,
		rr->rdata.soa.retry,
		rr->rdata.soa.expire,
		rr->rdata.soa.minimum);
}

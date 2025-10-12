#include "soa.h"

#include "compat/network_compat.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rdata.h"

int parse_rdata_soa(dns_rdata_t *rdata, buffer_t *buffer) {
	rdata->soa.mname = parse_name(buffer);
	if (rdata->soa.mname == NULL) {
		LOG_WARN("SOA mname is NULL");
		return -1;
	}
	rdata->soa.rname = parse_name(buffer);
	if (rdata->soa.rname == NULL) {
		LOG_WARN("SOA rname is NULL");
		return -1;
	}
	rdata->soa.serial = buffer_read_uint32(buffer);
	rdata->soa.refresh = buffer_read_int32(buffer);
	rdata->soa.retry = buffer_read_int32(buffer);
	rdata->soa.expire = buffer_read_int32(buffer);
	rdata->soa.minimum = buffer_read_uint32(buffer);
	if (buffer_has_error(buffer)) {
		LOG_WARN("detected an error in the buffer while reading RR of type SOA");
		return -1;
	}
	rdata->soa.serial = ntohl(rdata->soa.serial);
	rdata->soa.refresh = ntohl(rdata->soa.refresh);
	rdata->soa.retry = ntohl(rdata->soa.retry);
	rdata->soa.expire = ntohl(rdata->soa.expire);
	rdata->soa.minimum = ntohl(rdata->soa.minimum);
	return 0;
}

void free_rdata_soa(dns_rdata_t *rdata) {
    free_name(rdata->soa.mname);
	free_name(rdata->soa.rname);
}

void print_rdata_soa(dns_rdata_t *rdata) {
	LOG_PRINTF("%s %s %u %d %d %d %u\n",
		rdata->soa.mname,
		rdata->soa.rname,
		rdata->soa.serial,
		rdata->soa.refresh,
		rdata->soa.retry,
		rdata->soa.expire,
		rdata->soa.minimum);
}

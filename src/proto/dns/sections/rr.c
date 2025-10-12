#include "rr.h"

#include "compat/network_compat.h"
#include "log.h"
#include "proto/dns/arrays.h"
#include "proto/dns/name.h"
#include "types/buffer.h"

#include <stdlib.h> // for malloc
#include <string.h> // for memset

dns_rr_t *parse_rr(buffer_t *buffer) {
	dns_rr_t *rr = malloc(sizeof(dns_rr_t));
	if (rr == NULL)
		return NULL;
	memset(rr, 0, sizeof(dns_rr_t));
	{
		rr->name = parse_name(buffer);
		if (rr->name == NULL) {
			// An empty name is acceptable in null RRs.
			free_rr(rr);
			return NULL;
		}
		rr->qtype = buffer_read_uint16(buffer);
		rr->qclass = buffer_read_uint16(buffer);
		rr->ttl = buffer_read_uint32(buffer);
		rr->rdlen = buffer_read_uint16(buffer);
		if (buffer_has_error(buffer)) {
			LOG_WARN("detected an error in the buffer while reading RR");
			goto error;
		}
		rr->qtype = ntohs(rr->qtype);
		rr->qclass = ntohs(rr->qclass);
		rr->ttl = ntohl(rr->ttl);
		rr->rdlen = ntohs(rr->rdlen);
	}

	if (parse_rdata(rr, buffer) != 0) {
		LOG_WARN("failed to parse RDATA");
		goto error;
	}
	return rr;
error:
	LOG_WARN("invalid resource record");
	free_rr(rr);
	return NULL;
}

void free_rr(dns_rr_t *rr) {
	if (rr == NULL)
		return;
	free_rdata(rr);
	free_name(rr->name);
	free(rr);
}

void print_rr(dns_rr_t *rr) {
	LOG_PRINTF_INDENT(4, "%s\t\t%u\t%s\t%s\t",
		rr->name, rr->ttl,
		totext(DNS_ARRAY_QCLASS, rr->qclass),
		totext(DNS_ARRAY_QTYPE, rr->qtype));
	print_rdata(rr);
}

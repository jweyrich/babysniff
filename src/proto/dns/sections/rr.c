#include "rr.h"
#include "log.h"
#include "proto/dns/arrays.h"
#include "proto/dns/name.h"
#include "proto/dns/sections.h"
#include "types/buffer.h"
#include "utils.h"
#include <arpa/inet.h> // for ntohs + struct in_addr + in6_addr
#include <stdlib.h>
#include <string.h>
#include <time.h> // for gmtime_r + strftime

static char *parse_timestamp(char *out, size_t out_size, time_t in) {
	struct tm tm;
	gmtime_r(&in, &tm);
	strftime(out, out_size, "%Y%m%d%H%M%S", &tm); // YYYYMMDDHHmmSS
	return out;
}

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

	switch (rr->qtype) {
		case DNS_TYPE_A:
			if (parse_rdata_a(rr, buffer) != 0) goto error;
			break;
		case DNS_TYPE_AAAA:
			if (parse_rdata_aaaa(rr, buffer) != 0) goto error;
			break;
		case DNS_TYPE_NS:
			if (parse_rdata_ns(rr, buffer) != 0) goto error;
			break;
		case DNS_TYPE_CNAME:
			if (parse_rdata_cname(rr, buffer) != 0) goto error;
			break;
		case DNS_TYPE_SOA:
			if (parse_rdata_soa(rr, buffer) != 0) goto error;
			break;
		case DNS_TYPE_PTR:
			if (parse_rdata_ptr(rr, buffer) != 0) goto error;
			break;
		case DNS_TYPE_MX:
			if (parse_rdata_mx(rr, buffer) != 0) goto error;
			break;
		case DNS_TYPE_TXT:
			if (parse_rdata_txt(rr, buffer) != 0) goto error;
			break;
		case DNS_TYPE_RRSIG:
			if (parse_rdata_rrsig(rr, buffer) != 0) goto error;
			break;
		case DNS_TYPE_NSEC3:
			break;
		default:
			break;
	}
	return rr;
error:
	LOG_WARN("Invalid resource record");
	free_rr(rr);
	return NULL;
}

void free_rr(dns_rr_t *rr) {
	if (rr == NULL)
		return;
	switch (rr->qtype) {
		case DNS_TYPE_A:
			free_rdata_a(rr);
			break;
		case DNS_TYPE_AAAA:
			free_rdata_aaaa(rr);
			break;
		case DNS_TYPE_NS:
			free_rdata_ns(rr);
			break;
		case DNS_TYPE_CNAME:
			free_rdata_cname(rr);
			break;
		case DNS_TYPE_SOA:
			free_rdata_soa(rr);
			break;
		case DNS_TYPE_PTR:
			free_rdata_ptr(rr);
			break;
		case DNS_TYPE_MX:
			free_rdata_mx(rr);
			break;
		case DNS_TYPE_TXT:
			free_rdata_txt(rr);
			break;
		case DNS_TYPE_RRSIG:
			free_rdata_rrsig(rr);
			break;
		case DNS_TYPE_NSEC3:
			break;
		default:
			break;
	}
	free_name(rr->name);
	free(rr);
}

void print_rr(dns_rr_t *rr) {
	LOG_PRINTF_INDENT(4, "%s\t\t%u\t%s\t%s\t",
		rr->name, rr->ttl,
		totext(DNS_ARRAY_QCLASS, rr->qclass),
		totext(DNS_ARRAY_QTYPE, rr->qtype));
	switch (rr->qtype) {
		case DNS_TYPE_A:
		{
			char ip_as_str[INET_ADDRSTRLEN];
			const char *ip_addr = utils_in_addr_to_str(ip_as_str, sizeof(ip_as_str), (struct in_addr *)rr->rdata.a.address);
			LOG_PRINTF("%s\n", ip_addr);
			break;
		}
		case DNS_TYPE_AAAA:
		{
			char ip_as_str[INET6_ADDRSTRLEN];
			const char *ip_addr = utils_in6_addr_to_str(ip_as_str, sizeof(ip_as_str), (struct in6_addr *)rr->rdata.aaaa.address);
			LOG_PRINTF("%s\n", ip_addr);
			break;
		}
		case DNS_TYPE_NS:
			LOG_PRINTF("%s\n", rr->rdata.ns.name);
			break;
		case DNS_TYPE_CNAME:
			LOG_PRINTF("%s\n", rr->rdata.cname.name);
			break;
		case DNS_TYPE_SOA:
			LOG_PRINTF("%s %s %u %d %d %d %u\n",
				rr->rdata.soa.mname,
				rr->rdata.soa.rname,
				rr->rdata.soa.serial,
				rr->rdata.soa.refresh,
				rr->rdata.soa.retry,
				rr->rdata.soa.expire,
				rr->rdata.soa.minimum);
			break;
		case DNS_TYPE_PTR:
			LOG_PRINTF("%s\n", rr->rdata.ptr.name);
			break;
		case DNS_TYPE_MX:
			LOG_PRINTF("%u\t%s\n",
				rr->rdata.mx.preference,
				rr->rdata.mx.exchange);
			break;
		case DNS_TYPE_TXT:
			LOG_PRINTF("\"%s\" \n", rr->rdata.txt.data);
			break;
		case DNS_TYPE_RRSIG:
		{
			char sig_expiration[15];
			char sig_inception[15];
			LOG_PRINTF("%s %s %u %u %s %s %u %s %s\n",
				totext(DNS_ARRAY_QTYPE, rr->rdata.rrsig.typec),
				totext(DNSSEC_ARRAY_ALGORITHM, rr->rdata.rrsig.algnum),
				rr->rdata.rrsig.labels,
				rr->rdata.rrsig.original_ttl,
				parse_timestamp(sig_expiration, sizeof(sig_expiration), rr->rdata.rrsig.signature_expiration),
				parse_timestamp(sig_inception, sizeof(sig_inception), rr->rdata.rrsig.signature_inception),
				rr->rdata.rrsig.key_tag,
				rr->rdata.rrsig.signer_name,
				rr->rdata.rrsig.signature
			);
			break;
		}
		case DNS_TYPE_NSEC3:
			break;
		default:
			//LOG_PRINTF("\n");
			LOG_WARN("Unhandled qtype (%u -> %s)", rr->qtype, totext(DNS_ARRAY_QTYPE, rr->qtype));
			break;
	}
}

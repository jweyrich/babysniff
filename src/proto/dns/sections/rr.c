#include "rr.h"
#include "alloc.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/arrays.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rdata/rrsig.h"
#include "proto/dns/sections.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <time.h> // for gmtime_r + strftime

#include <arpa/inet.h> // for ntohs + struct in_addr + in6_addr

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
		{
			rr->rdata.a.address[0] = buffer_read_uint32(buffer);
			if (buffer_has_error(buffer)) {
				LOG_WARN("detected an error in the buffer while reading RR record A");
				goto error;
			}
			break;
		}
		case DNS_TYPE_AAAA:
		{
			for (size_t i=0; i<4; i++) {
				rr->rdata.aaaa.address[i] = buffer_read_uint32(buffer);
				if (buffer_has_error(buffer)) {
					LOG_WARN("detected an error in the buffer while reading RR record AAAA");
					goto error;
				}
			}
			break;
		}
		case DNS_TYPE_NS:
			rr->rdata.ns.name = parse_name(buffer);
			if (rr->rdata.ns.name == NULL) {
				LOG_WARN("NS name is NULL");
				goto error;
			}
			break;
		case DNS_TYPE_CNAME:
			rr->rdata.cname.name = parse_name(buffer);
			if (rr->rdata.cname.name == NULL) {
				LOG_WARN("CNAME name is NULL");
				goto error;
			}
			break;
		case DNS_TYPE_SOA:
			rr->rdata.soa.mname = parse_name(buffer);
			if (rr->rdata.soa.mname == NULL) {
				LOG_WARN("SOA mname is NULL");
				goto error;
			}
			rr->rdata.soa.rname = parse_name(buffer);
			if (rr->rdata.soa.rname == NULL) {
				LOG_WARN("SOA rname is NULL");
				goto error;
			}
			rr->rdata.soa.serial = buffer_read_uint32(buffer);
			rr->rdata.soa.refresh = buffer_read_int32(buffer);
			rr->rdata.soa.retry = buffer_read_int32(buffer);
			rr->rdata.soa.expire = buffer_read_int32(buffer);
			rr->rdata.soa.minimum = buffer_read_uint32(buffer);
			if (buffer_has_error(buffer)) {
				LOG_WARN("detected an error in the buffer while reading RR record SOA");
				goto error;
			}
			rr->rdata.soa.serial = ntohl(rr->rdata.soa.serial);
			rr->rdata.soa.refresh = ntohl(rr->rdata.soa.refresh);
			rr->rdata.soa.retry = ntohl(rr->rdata.soa.retry);
			rr->rdata.soa.expire = ntohl(rr->rdata.soa.expire);
			rr->rdata.soa.minimum = ntohl(rr->rdata.soa.minimum);
			break;
		case DNS_TYPE_PTR:
			rr->rdata.ptr.name = parse_name(buffer);
			if (rr->rdata.ptr.name == NULL) {
				LOG_WARN("PTR name is NULL");
				goto error;
			}
			break;
		case DNS_TYPE_MX:
			rr->rdata.mx.preference = buffer_read_uint16(buffer);
			if (buffer_has_error(buffer)) {
				LOG_WARN("detected an error in the buffer while reading RR record MX");
				goto error;
			}
			rr->rdata.mx.exchange = parse_name(buffer);
			if (rr->rdata.mx.exchange == NULL) {
				LOG_WARN("MX exchange is NULL");
				goto error;
			}
			rr->rdata.mx.preference = ntohs(rr->rdata.mx.preference);
			break;
		case DNS_TYPE_TXT:
			rr->rdata.txt.data = parse_txtdata(buffer);
			if (rr->rdata.txt.data == NULL) {
				LOG_WARN("TXT data is NULL");
				goto error;
			}
			break;
		case DNS_TYPE_RRSIG:
			rr->rdata.rrsig.typec = buffer_read_uint16(buffer);
			rr->rdata.rrsig.algnum = buffer_read_uint8(buffer);
			rr->rdata.rrsig.labels = buffer_read_uint8(buffer);
			rr->rdata.rrsig.original_ttl = buffer_read_uint32(buffer);
			rr->rdata.rrsig.signature_expiration = buffer_read_uint32(buffer);
			rr->rdata.rrsig.signature_inception = buffer_read_uint32(buffer);
			rr->rdata.rrsig.key_tag = buffer_read_uint16(buffer);
			if (buffer_has_error(buffer)) {
				LOG_WARN("detected an error in the buffer while reading RR record RRSIG");
				goto error;
			}
			rr->rdata.rrsig.signer_name = parse_name(buffer);
			if (rr->rdata.rrsig.signer_name == NULL) {
				LOG_WARN("RRSIG signer name is NULL");
				goto error;
			}
			// FIXME(jweyrich): parse_rrsig_signature is not working properly.
			// rr->rdata.rrsig.signature = parse_rrsig_signature(buffer);
			// if (rr->rdata.rrsig.signature == NULL) {
			// 	LOG_WARN("RRSIG signature is NULL");
			// 	goto error;
			// }
			rr->rdata.rrsig.typec = ntohs(rr->rdata.rrsig.typec);
			rr->rdata.rrsig.original_ttl = ntohl(rr->rdata.rrsig.original_ttl);
			rr->rdata.rrsig.signature_expiration = ntohl(rr->rdata.rrsig.signature_expiration);
			rr->rdata.rrsig.signature_inception = ntohl(rr->rdata.rrsig.signature_inception);
			rr->rdata.rrsig.key_tag = ntohs(rr->rdata.rrsig.key_tag);
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
			break;
		case DNS_TYPE_NS:
			free_name(rr->rdata.ns.name);
			break;
		case DNS_TYPE_CNAME:
			free_name(rr->rdata.cname.name);
			break;
		case DNS_TYPE_SOA:
			free_name(rr->rdata.soa.mname);
			free_name(rr->rdata.soa.rname);
			break;
		case DNS_TYPE_PTR:
			free_name(rr->rdata.ptr.name);
			break;
		case DNS_TYPE_MX:
			free_name(rr->rdata.mx.exchange);
			break;
		case DNS_TYPE_TXT:
			free_txtdata(rr->rdata.txt.data);
			break;
		case DNS_TYPE_RRSIG:
			free_name(rr->rdata.rrsig.signer_name);
			safe_free(rr->rdata.rrsig.signature);
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

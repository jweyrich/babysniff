#include "rdata.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/sections/rr.h"
#include "proto/dns/arrays.h"
#include <stdlib.h>

int parse_rdata(dns_rr_t *rr, buffer_t *buffer) {
	switch (rr->qtype) {
		case DNS_TYPE_A:
			if (parse_rdata_a(&rr->rdata, buffer) != 0) return -1;
		case DNS_TYPE_AAAA:
			if (parse_rdata_aaaa(&rr->rdata, buffer) != 0) return -1;
		case DNS_TYPE_NS:
			if (parse_rdata_ns(&rr->rdata, buffer) != 0) return -1;
			break;
		case DNS_TYPE_CNAME:
			if (parse_rdata_cname(&rr->rdata, buffer) != 0) return -1;
			break;
		case DNS_TYPE_SOA:
			if (parse_rdata_soa(&rr->rdata, buffer) != 0) return -1;
			break;
		case DNS_TYPE_PTR:
			if (parse_rdata_ptr(&rr->rdata, buffer) != 0) return -1;
			break;
		case DNS_TYPE_MX:
			if (parse_rdata_mx(&rr->rdata, buffer) != 0) return -1;
			break;
		case DNS_TYPE_TXT:
			if (parse_rdata_txt(&rr->rdata, buffer) != 0) return -1;
			break;
		case DNS_TYPE_RRSIG:
			if (parse_rdata_rrsig(&rr->rdata, buffer) != 0) return -1;
			break;
		case DNS_TYPE_DNSKEY:
			if (parse_rdata_dnskey(&rr->rdata, buffer) != 0) return -1;
			break;
		case DNS_TYPE_NSEC3:
			break;
		default:
			break;
	}
	return 0;
}

void free_rdata(dns_rr_t *rr) {
	switch (rr->qtype) {
		case DNS_TYPE_A:
			free_rdata_a(&rr->rdata);
			break;
		case DNS_TYPE_AAAA:
			free_rdata_aaaa(&rr->rdata);
			break;
		case DNS_TYPE_NS:
			free_rdata_ns(&rr->rdata);
			break;
		case DNS_TYPE_CNAME:
			free_rdata_cname(&rr->rdata);
			break;
		case DNS_TYPE_SOA:
			free_rdata_soa(&rr->rdata);
			break;
		case DNS_TYPE_PTR:
			free_rdata_ptr(&rr->rdata);
			break;
		case DNS_TYPE_MX:
			free_rdata_mx(&rr->rdata);
			break;
		case DNS_TYPE_TXT:
			free_rdata_txt(&rr->rdata);
			break;
		case DNS_TYPE_RRSIG:
			free_rdata_rrsig(&rr->rdata);
			break;
		case DNS_TYPE_DNSKEY:
			free_rdata_dnskey(&rr->rdata);
			break;
		case DNS_TYPE_NSEC3:
			break;
		default:
			break;
	}
}

void print_rdata(dns_rr_t *rr) {
	switch (rr->qtype) {
		case DNS_TYPE_A:
			print_rdata_a(&rr->rdata);
			break;
		case DNS_TYPE_AAAA:
			print_rdata_aaaa(&rr->rdata);
			break;
		case DNS_TYPE_NS:
			print_rdata_ns(&rr->rdata);
			break;
		case DNS_TYPE_CNAME:
			print_rdata_cname(&rr->rdata);
			break;
		case DNS_TYPE_SOA:
			print_rdata_soa(&rr->rdata);
			break;
		case DNS_TYPE_PTR:
			print_rdata_ptr(&rr->rdata);
			break;
		case DNS_TYPE_MX:
			print_rdata_mx(&rr->rdata);
			break;
		case DNS_TYPE_TXT:
			print_rdata_txt(&rr->rdata);
			break;
		case DNS_TYPE_RRSIG:
			print_rdata_rrsig(&rr->rdata);
			break;
		case DNS_TYPE_DNSKEY:
			print_rdata_dnskey(&rr->rdata);
			break;
		case DNS_TYPE_NSEC3:
			break;
		default:
			//LOG_PRINTF("\n");
			LOG_WARN("Unhandled qtype (%u -> %s)", rr->qtype, totext(DNS_ARRAY_QTYPE, rr->qtype));
			break;
	}
}

#include "proto_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <arpa/inet.h>

#include <sys/types.h>
#include <time.h>
#include "proto/dns/dns.h"
#include "base64.h"
#include "alloc.h"
#include "config.h"
#include "dump.h"
#include "log.h"
#include "types/buffer.h"
#include "types/pair.h"
#include "utils.h"

typedef enum dns_array {
	DNS_ARRAY_OPCODE,
	DNS_ARRAY_RCODE,
	DNS_ARRAY_QTYPE,
	DNS_ARRAY_QCLASS,
	DNSSEC_ARRAY_ALGORITHM
} dns_array_e;

static const pair_t dns_array_opcode_data[] = {
	{ DNS_OP_QUERY,		"QUERY" },
	{ DNS_OP_IQUERY_,	"IQUERY" },
	{ DNS_OP_STATUS,	"STATUS" },
	{ DNS_OP_NOTIFY,	"NOTIFY" },
	{ DNS_OP_UPDATE,	"UPDATE" },
	{ 0,				"UNKNOWN" }
};

static const pair_array_t dns_array_opcode = {
	.count = sizeof(dns_array_opcode_data) / sizeof(pair_t),
	.data = dns_array_opcode_data
};

static const pair_t dns_array_rcode_data[] = {
	{ DNS_RC_FORMERR,	"FORMERR" },
	{ DNS_RC_NOERROR,	"NOERROR" },
	{ DNS_RC_SERVFAIL,	"SERVFAIL" },
	{ DNS_RC_NXDOMAIN,	"NXDOMAIN" },
	{ DNS_RC_NOTIMP,	"NOTIMP" },
	{ DNS_RC_REFUSED,	"REFUSED" },
	{ DNS_RC_YXDOMAIN,	"YXDOMAIN" },
	{ DNS_RC_YXRRSET,	"YXRRSET" },
	{ DNS_RC_NXRRSET,	"NXRRSET" },
	{ DNS_RC_NOTAUTH,	"NOTAUTH" },
	{ DNS_RC_NOTZONE,	"NOTZONE" },
	{ DNS_RC_BADVERS,	"BADOPTVER" },
	{ DNS_RC_BADSIG,	"BADTSIG" },
	{ DNS_RC_BADKEY,	"BADKEY" },
	{ DNS_RC_BADTIME,	"BADTIME" },
	{ DNS_RC_BADMODE,	"BADTKEYMODE" },
	{ DNS_RC_BADNAME,	"DUPKEY" },
	{ DNS_RC_BADALG,	"BADALG" },
	{ DNS_RC_BADTRUNC,	"BADTRUNC" },
	{ 0,				"UNKNOWN" }
};

static const pair_array_t dns_array_rcode = {
	.count = sizeof(dns_array_rcode_data) / sizeof(pair_t),
	.data = dns_array_rcode_data
};

static const pair_t dns_array_qtype_data[] = {
	{ DNS_TYPE_A,			"A" },
	{ DNS_TYPE_NS,			"NS" },
	{ DNS_TYPE_MD_,			"MD" },
	{ DNS_TYPE_MF_,			"MF" },
	{ DNS_TYPE_CNAME,		"CNAME" },
	{ DNS_TYPE_SOA,			"SOA" },
	{ DNS_TYPE_MB_,			"MB" },
	{ DNS_TYPE_MG_,			"MG" },
	{ DNS_TYPE_MR_,			"MR" },
	{ DNS_TYPE_NULL_,		"NULL" },
	{ DNS_TYPE_WKS_,		"WKS" },
	{ DNS_TYPE_PTR,			"PTR" },
	{ DNS_TYPE_HINFO_,		"HINFO" },
	{ DNS_TYPE_MINFO_,		"MINFO" },
	{ DNS_TYPE_MX,			"MX" },
	{ DNS_TYPE_TXT,			"TXT" },
	{ DNS_TYPE_RP_,			"RP" },
	{ DNS_TYPE_AFSDB,		"AFSDB" },
	{ DNS_TYPE_X25_,		"X25" },
	{ DNS_TYPE_ISDN_,		"ISDN" },
	{ DNS_TYPE_RT_,			"RT" },
	{ DNS_TYPE_NSAP_,		"NSAP" },
	{ DNS_TYPE_NSAPPTR_,	"NSAPPTR" },
	{ DNS_TYPE_SIG,			"SIG" },
	{ DNS_TYPE_KEY,			"KEY" },
	{ DNS_TYPE_PX_,			"PX" },
	{ DNS_TYPE_GPOS_,		"GPOS" },
	{ DNS_TYPE_AAAA,		"AAAA" },
	{ DNS_TYPE_LOC,			"LOC" },
	{ DNS_TYPE_NXT_,		"NXT" },
	{ DNS_TYPE_EID_,		"EID" },
	{ DNS_TYPE_NIMLOC_,		"NIMLOC" },
	{ DNS_TYPE_SRV,			"SRV" },
	{ DNS_TYPE_ATMA_,		"ATMA" },
	{ DNS_TYPE_NAPTR,		"NAPTR" },
	{ DNS_TYPE_KX_,			"KX" },
	{ DNS_TYPE_CERT,		"CERT" },
	{ DNS_TYPE_A6_,			"A6" },
	{ DNS_TYPE_DNAME,		"DNAME" },
	{ DNS_TYPE_SINK_,		"SINK" },
	{ DNS_QTYPE_OPT,		"OPT" },
	{ DNS_TYPE_APL_,		"APL" },
	{ DNS_TYPE_DS,			"DS" },
	{ DNS_TYPE_SSHFP,		"SSHFP" },
	{ DNS_TYPE_IPSECKEY,	"IPSECKEY" },
	{ DNS_TYPE_RRSIG,		"RRSIG" },
	{ DNS_TYPE_NSEC,		"NSEC" },
	{ DNS_TYPE_DNSKEY,		"DNSKEY" },
	{ DNS_TYPE_DHCID,		"DHCID" },
	{ DNS_TYPE_NSEC3,		"NSEC3" },
	{ DNS_TYPE_NSEC3PARAM,	"NSEC3PARAM" },
	{ DNS_TYPE_HIP,			"HIP" },
	{ DNS_TYPE_NINFO,		"NINFO" },
	{ DNS_TYPE_RKEY,		"RKEY" },
	{ DNS_TYPE_SPF,			"SPF" },
	{ DNS_TYPE_UINFO_,		"UINFO" },
	{ DNS_TYPE_UID_,		"UID" },
	{ DNS_TYPE_GID_,		"GID" },
	{ DNS_TYPE_UNSPEC_,		"UNSPEC" },
	{ DNS_TYPE_ADDRS,		"ADDRS" },
	{ DNS_QTYPE_TKEY,		"TKEY" },
	{ DNS_TYPE_TSIG,		"TSIG" },
	{ DNS_QTYPE_IXFR,		"IXFR" },
	{ DNS_QTYPE_AXFR,		"AXFR" },
	{ DNS_QTYPE_MAILB_,		"MAILB" },
	{ DNS_QTYPE_MAILA_,		"MAILA" },
	{ DNS_QTYPE_ANY,		"ANY" },
	{ DNS_TYPE_TA,			"TA" },
	{ DNS_TYPE_DLV,			"DLV" },
	{ 0,					"UNKNOWN" }
};

static const pair_array_t dns_array_qtype = {
	.count = sizeof(dns_array_qtype_data) / sizeof(pair_t),
	.data = (pair_t *)dns_array_qtype_data
};

static const pair_t dns_array_qclass_data[] = {
	{ DNS_CLASS_IN,		"IN" },
	{ DNS_CLASS_CH,		"CH" },
	{ DNS_CLASS_HS,		"HS" },
	{ DNS_QCLASS_NONE,	"NONE" },
	{ DNS_QCLASS_ANY,	"ANY" },
	{ 0,				"UNKNOWN" }
};

static const pair_array_t dns_array_qclass = {
	.count = sizeof(dns_array_qclass_data) / sizeof(pair_t),
	.data = dns_array_qclass_data
};

static const pair_t dnssec_array_algorithm_data[] = {
	{ DNSSEC_ALG_RSAMD5,		"RSA/MD5" },
	{ DNSSEC_ALG_DH,			"DH" },
	{ DNSSEC_ALG_DSA,			"DSA" },
	{ DNSSEC_ALG_ECC,			"ECC" },
	{ DNSSEC_ALG_RSASHA1,		"RSA/SHA-1" },
	{ DNSSEC_ALG_INDIRECT,		"Indirect" },
	{ DNSSEC_ALG_PRIVATEDNS,	"Private DNS" },
	{ DNSSEC_ALG_PRIVATEOID,	"Private OID" },
	{ 0,						"UNKNOWN" }
};

static const pair_array_t dnssec_array_algorithm = {
	.count = sizeof(dnssec_array_algorithm_data) / sizeof(pair_t),
	.data = dnssec_array_algorithm_data
};

static const pair_array_t *select_array(dns_array_e type) {
	switch (type) {
		case DNS_ARRAY_OPCODE: return &dns_array_opcode; break;
		case DNS_ARRAY_RCODE: return &dns_array_rcode; break;
		case DNS_ARRAY_QTYPE: return &dns_array_qtype; break;
		case DNS_ARRAY_QCLASS: return &dns_array_qclass; break;
		case DNSSEC_ARRAY_ALGORITHM: return &dnssec_array_algorithm; break;
	}
	return NULL;
}

static const char *totext(dns_array_e type, int key) {
	const pair_array_t *array = select_array(type);
	const pair_t *result = pair_array_lookup_key(array, key);
	return result == NULL ? pair_array_last(array)->value : result->value;
}

static int fromtext(dns_array_e type, const char *value) {
	const pair_array_t *array = select_array(type);
	const pair_t *result = pair_array_lookup_value(array, value);
	return result == NULL ? pair_array_last(array)->key : result->key;
}

static const char *flags_totext(const dns_hdr_flags_t *value) {
	static char text[7 * 3]; // # of flags * length with separator
	char *ptr = text;
	int has_prev = 0;
	memset(text, 0, sizeof(text));
#define FLAGS_IF(txt) \
	if (value->txt) { \
		strcpy(ptr, has_prev ? " " # txt : "" # txt); \
		ptr += has_prev++ ? 3 : 2; \
	}
	FLAGS_IF(qr)
	FLAGS_IF(aa)
	FLAGS_IF(tc)
	FLAGS_IF(rd)
	FLAGS_IF(ra)
	FLAGS_IF(ad)
	FLAGS_IF(cd)
#undef FLAGS_IF
	return text;
}

static void free_txtdata(char *data) {
	if (data == NULL)
		return;
	free(data);
}

static char *parse_txtdata(buffer_t *buffer) {
	char *data = NULL;
	size_t length;

	length = buffer_read_uint8(buffer);
	if (buffer_has_error(buffer))
		goto error;
	if (length == 0)
		goto error;
	data = malloc(length+1);
	if (data == NULL)
		return NULL;
	buffer_strncpy(buffer, data, length);
	if (buffer_has_error(buffer))
		goto error;
	data[length] = 0;
	return data;
error:
	if (data != NULL) {
		LOG_WARN("Invalid data");
		free(data);
	}
	return NULL;
}

static void free_name(char *name) {
	if (name == NULL)
		return;
	free(name);
}

static size_t predict_name_length(buffer_t *buffer) {
	int label_count = 0;
	size_t orig_pos, label_len, total_len = 0;

	orig_pos = buffer_tell(buffer);
	// LOG_DEBUG("starting at %#x", orig_pos);
	for (;;) {
		label_len = buffer_read_uint8(buffer);
		// LOG_DEBUG("label_len = %zd", label_len);
		if (buffer_has_error(buffer))
			goto error;
		if (label_len == 0) // null label?
			break;
		if (label_len & DNS_LABEL_COMPRESS_MASK) { // compressed label?
			// get the new offset
			uint32_t new_off = buffer_read_uint8(buffer);
			// LOG_DEBUG("new offset is %#zx", new_off);
			if (buffer_has_error(buffer))
				goto error;
			buffer_seek(buffer, new_off);
			if (buffer_has_error(buffer))
				goto error;
			continue;
		} else if (label_len > DNS_LABEL_MAXLEN) { // invalid size?
			goto error;
		}
		total_len += label_len;
		if (total_len > DNS_NAME_MAXLEN) // overflow?
			goto error;
		// LOG_DEBUG("skiping from %#x", buffer_tell(buffer));
		buffer_skip(buffer, label_len);
		if (buffer_has_error(buffer))
			goto error;
		total_len += 1; // dot separator
		++label_count;
	}
	// move back to original position
	buffer_seek(buffer, orig_pos);
	// LOG_DEBUG("jumped back to %#zx", orig_pos);
	if (label_count > 0)
		return total_len;
error:
	LOG_WARN("DNS name is invalid");
	return 0;
}

static char *parse_name(buffer_t *buffer) {
	int label_count = 0;
	int compressed = 0;
	size_t total_len = 0, orig_pos = 0, label_len;

	char *name = malloc(DNS_NAME_MAXLEN+1);
	if (name == NULL)
		return NULL;

	for (;;) {
		label_len = buffer_read_uint8(buffer);
		// LOG_DEBUG("label_len is %zd", label_len);
		if (buffer_has_error(buffer))
			goto error;
		if (label_len == 0) { // null label?
			// A null label indicates the end of the name.
			// LOG_DEBUG("null label");
			break;
		}
		if (label_len & DNS_LABEL_COMPRESS_MASK) { // compressed label?
			uint32_t new_off;
			compressed++;
			// get the new offset
			new_off = buffer_read_uint8(buffer);
			// LOG_DEBUG("new_off is %#zx", new_off);
			if (buffer_has_error(buffer))
				goto error;
			// keep the original position
			if (compressed == 1) {
				orig_pos = buffer_tell(buffer);
				// LOG_DEBUG("orig_pos is %#zx", orig_pos);
			}
			// move to new offset
			buffer_seek(buffer, new_off);
			if (buffer_has_error(buffer))
				goto error;
			continue;
		} else if (label_len > DNS_LABEL_MAXLEN) { // invalid size?
			LOG_WARN("DNS name label size is invalid (exceeded max label size)");
			goto error;
		}
		total_len += label_len;
		if (total_len > DNS_NAME_MAXLEN) { // overflow?
			LOG_WARN("DNS name size is invalid (exceeded max name size)");
			goto error;
		}
		// LOG_DEBUG("copying from %#x", buffer_tell(buffer));
		buffer_strncpy(buffer, name + total_len - label_len, label_len);
		if (buffer_has_error(buffer))
			goto error;
		memset(name + total_len, '.', 1);
		total_len += 1;
		++label_count;
	}
	if (compressed != 0) {
		// move back to original position
		buffer_seek(buffer, orig_pos);
		// LOG_DEBUG("jumped back to %#zx", orig_pos);
	}
	if (label_count > 0) {
		name[total_len - 1] = 0;
		return name;
	} else {
		// LOG_WARN("DNS name has no labels");
		return NULL;
	}
error:
	LOG_WARN("DNS name is invalid");
	free(name);
	return NULL;
}

static char *parse_rrsig_signature(buffer_t *buffer) {
	//pd3IpdiZHH7ig7szxDcWSKtkmpK52w7hcCJs/6TL74AH2Wyd4N4pAYbpRuNSuuPHwH+fT8P9f+TqKTeTa2DSzD1bumgICnHhOi9yO0pAYdsyThFdiiJtg8vPMyyMagxhJkurienCAVA4nqF40cMwJgAfHS+Vc+EQSlbDVFjmI5s=
	//M+5jGt0Xd5+fnvfyCNG7v7quzJ6p5sABjWVz0L/kUyN0erX4eNzpzFiofiRFnYkwAaibP+GcW/kB/ibots9e4sPhHvPWZs/01kgVgust9VN7nOiPON8dMkCJPPOrsz1SfcDqBj3ES5wNT/C2bTle4QOgv9z9XKdcNtlyeWmBW0h9Co+SMutYHpHoiBCKhcgI
	// TODO(jweyrich): What's the real size? 128 or 144? Is it constant?
	const size_t input_size = 128; // RSA/SHA-1
	byte signature[input_size];
	int read = buffer_read(buffer, signature, input_size);
	if (read == 0)
		return NULL;
	// Base64
	const size_t encoded_size = base64_encoded_size(input_size);
	char *encoded = malloc(encoded_size + 1);
	if (encoded == NULL)
		return NULL;
	base64_encode(encoded, encoded_size, signature, input_size);
	printf("input_size = %zu, encoded_size = %zu, result_size = %zu\n", input_size, encoded_size, strlen(encoded));
	return encoded;
}

static void print_header(dns_hdr_t *header) {
	LOG_PRINTF_INDENT(2, "opcode: %s, status: %s, id: %u\n",
		totext(DNS_ARRAY_OPCODE, header->flags.expanded.opcode),
		totext(DNS_ARRAY_RCODE, header->flags.expanded.rcode),
		header->id);
	LOG_PRINTF_INDENT(2, "flags: %#x [%s]\n",
		header->flags.single,
		flags_totext(&header->flags.expanded));
	LOG_PRINTF_INDENT(2, "query: %u, answer: %u, authority: %u, additional: %u\n",
		header->qd_c,
		header->an_c,
		header->ns_c,
		header->ar_c);
}

static void free_header(dns_hdr_t *header) {
	if (header == NULL)
		return;
	free(header);
}

static dns_hdr_t *parse_header(buffer_t *buffer) {
	dns_hdr_t *header = malloc(sizeof(dns_hdr_t));
	if (header == NULL)
		return NULL;
	memset(header, 0, sizeof(dns_hdr_t));
	{
		header->id = buffer_read_uint16(buffer);
		header->flags.single = buffer_read_uint16(buffer);
		header->qd_c = buffer_read_uint16(buffer);
		header->an_c = buffer_read_uint16(buffer);
		header->ns_c = buffer_read_uint16(buffer);
		header->ar_c = buffer_read_uint16(buffer);
		if (buffer_has_error(buffer))
			goto error;
		header->id = ntohs(header->id);
		header->flags.single = ntohs(header->flags.single);
		header->an_c = ntohs(header->an_c);
		header->qd_c = ntohs(header->qd_c);
		header->ns_c = ntohs(header->ns_c);
		header->ar_c = ntohs(header->ar_c);
	}
	return header;
error:
	LOG_WARN("Invalid header");
	free_header(header);
	return NULL;
}

static void print_question(dns_question_t *question) {
	LOG_PRINTF_INDENT(4, "%s\t\t\t%s\t%s\n",
		question->name,
		totext(DNS_ARRAY_QCLASS, question->qclass),
		totext(DNS_ARRAY_QTYPE, question->qtype));
}

static void free_question(dns_question_t *question) {
	if (question == NULL)
		return;
	free_name(question->name);
	free(question);
}

static dns_question_t *parse_question(buffer_t *buffer) {
	dns_question_t *question = malloc(sizeof(dns_question_t));
	if (question == NULL)
		return NULL;
	memset(question, 0, sizeof(dns_question_t));
	{
		question->name = parse_name(buffer);
		if (question->name == NULL)
			goto error;
		question->qtype = buffer_read_uint16(buffer);
		question->qclass = buffer_read_uint16(buffer);
		if (buffer_has_error(buffer))
			goto error;
		question->qtype = ntohs(question->qtype);
		question->qclass = ntohs(question->qclass);
	}
	return question;
error:
	LOG_WARN("Invalid question");
	free_question(question);
	return NULL;
}

char *parse_timestamp(char *out, size_t out_size, time_t in) {
	struct tm tm;
	gmtime_r(&in, &tm);
	strftime(out, out_size, "%Y%m%d%H%M%S", &tm); // YYYYMMDDHHmmSS
	return out;
}

static void print_rr(dns_rr_t *rr) {
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
			LOG_PRINTF("%s %s %u %u %s (\n",
				totext(DNS_ARRAY_QTYPE, rr->rdata.rrsig.typec),
				totext(DNSSEC_ARRAY_ALGORITHM, rr->rdata.rrsig.algnum),
				rr->rdata.rrsig.labels,
				rr->rdata.rrsig.original_ttl,
				parse_timestamp(sig_expiration, sizeof(sig_expiration), rr->rdata.rrsig.signature_expiration)
			);
			LOG_PRINTF_INDENT_TAB(5, "   %s %u %s\n",
				parse_timestamp(sig_inception, sizeof(sig_inception), rr->rdata.rrsig.signature_inception),
				rr->rdata.rrsig.key_tag,
				rr->rdata.rrsig.signer_name
			);
			LOG_PRINTF_INDENT_TAB(5, "   %s )\n",
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

static void free_rr(dns_rr_t *rr) {
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

static dns_rr_t *parse_rr(buffer_t *buffer) {
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
			LOG_WARN("RR rdlen error");
			goto error;
		}
		rr->qtype = ntohs(rr->qtype);
		rr->qclass = ntohs(rr->qclass);
		rr->ttl = ntohl(rr->ttl);
		rr->rdlen = ntohs(rr->rdlen);
	}

	// LOG_DEBUG("name: %s, qtype: %u, qclass: %u, ttl: %u, rdlen: %u",
	// 	rr->name, rr->qtype, rr->qclass, rr->ttl, rr->rdlen);

	switch (rr->qtype) {
		case DNS_TYPE_A:
		{
			rr->rdata.a.address[0] = buffer_read_uint32(buffer);
			if (buffer_has_error(buffer)) {
				LOG_WARN("A address is NULL");
				goto error;
			}
			break;
		}
		case DNS_TYPE_AAAA:
		{
			for (size_t i=0; i<4; i++) {
				rr->rdata.aaaa.address[i] = buffer_read_uint32(buffer);
				if (buffer_has_error(buffer)) {
					LOG_WARN("AAAA address is NULL");
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
				LOG_WARN("SOA minimum error");
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
				LOG_WARN("MX preference is NULL");
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
			rr->rdata.rrsig.signer_name = parse_name(buffer);
			if (rr->rdata.rrsig.signer_name == NULL) {
				LOG_WARN("TXT data is NULL");
				goto error;
			}
			rr->rdata.rrsig.signature = parse_rrsig_signature(buffer);
			if (rr->rdata.rrsig.signature == NULL) {
				LOG_WARN("RRSIG signature is NULL");
				goto error;
			}
			if (buffer_has_error(buffer)) {
				LOG_WARN("RRSIG error");
				goto error;
			}
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

int sniff_dns_fromwire(const byte *packet, size_t length, const config_t *config) {
	int result = 0;
	buffer_t buffer = BUFFER_INITIALIZER;
	dns_hdr_t *header;
	int i;

	buffer_set_data(&buffer, (byte *)packet, length);

	if (config->filters_flag.dns) {
		LOG_PRINTF("-- DNS (%u bytes)\n", buffer_size(&buffer));
	}

	header = parse_header(&buffer);
	if (header == NULL) {
		result = -1;
	}
	else {
		if (config->filters_flag.dns) {
			print_header(header);
		}
	}

	if (config->filters_flag.dns) {
		LOG_PRINTF_INDENT(2, "QUESTION SECTION:\n");
		for (i=0; result == 0 && i < header->qd_c; i++) {
			dns_question_t *section = parse_question(&buffer);
			if (section == NULL) { result = -1; }
			else { print_question(section); free_question(section); }
		}
		LOG_PRINTF_INDENT(2, "ANSWER SECTION:\n");
		for (i=0; result == 0 && i < header->an_c; i++) {
			dns_rr_t *section = parse_rr(&buffer);
			if (section == NULL) { result = -1; }
			else { print_rr(section); free_rr(section); }
		}
		LOG_PRINTF_INDENT(2, "AUTHORITY SECTION:\n");
		for (i=0; result == 0 && i < header->ns_c; i++) {
			dns_rr_t *section = parse_rr(&buffer);
			if (section == NULL) { result = -1; }
			else { print_rr(section); free_rr(section); }
		}
		LOG_PRINTF_INDENT(2, "ADDITIONAL SECTION:\n");
		for (i=0; result == 0 && i < header->ar_c; i++) {
			dns_rr_t *section = parse_rr(&buffer);
			if (section == NULL) { result = -1; }
			else { print_rr(section); free_rr(section); }
		}
	}

	free_header(header);

//	packet = (byte *)PTR_ADD(packet, DNS_HDR_LEN);
//	length -= DNS_HDR_LEN;
	if (config->filters_flag.dns_data) {
		LOG_PRINTF("showing %lu bytes:\n", length);
		dump_hex(stdout, packet, length, 0);
	}
//	if (result == 0) {
//		packet = buffer_data_ptr(&buffer);
//		length = buffer_left(&buffer);
//		dump_hex(packet, length, 0);
//	}

	return result;
}

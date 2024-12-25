#include "arrays.h"

#include "proto/dns/dns.h"
#include "types/pair.h"

#include <stdlib.h>
#include <string.h>

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
	{ DNSSEC_ALG_DELETE, 				"DELETE" },
	{ DNSSEC_ALG_RSAMD5,				"RSAMD5" },
	{ DNSSEC_ALG_DH,					"DH" },
	{ DNSSEC_ALG_DSA, 		    		"DSA" },
	{ DNSSEC_ALG_ECC,					"ECC" },
	{ DNSSEC_ALG_RSASHA1,				"RSASHA1" },
	{ DNSSEC_ALG_DSA_NSEC3_SHA1, 		"DSA-NSEC3-SHA1" },
	{ DNSSEC_ALG_RSASHA1_NSEC3_SHA1,	"RSASHA1-NSEC3-SHA1" },
	{ DNSSEC_ALG_RSASHA256, 			"RSASHA256" },
	{ DNSSEC_ALG_RSASHA512, 			"RSASHA512" },
	{ DNSSEC_ALG_ECC_GOST,				"ECC-GOST" },
	{ DNSSEC_ALG_ECDSAP256SHA256,		"ECDSAP256SHA256" },
	{ DNSSEC_ALG_ECDSAP384SHA384,		"ECDSAP384SHA384" },
	{ DNSSEC_ALG_ED25519, 				"ED25519" },
	{ DNSSEC_ALG_ED448,					"ED448" },
	{ DNSSEC_ALG_INDIRECT,				"INDIRECT" },
	{ DNSSEC_ALG_SM2SM3,				"SM2SM3" },
	{ DNSSEC_ALG_ECC_GOST12,			"ECC-GOST12" },
	{ DNSSEC_ALG_PRIVATEDNS,			"PRIVATEDNS" },
	{ DNSSEC_ALG_PRIVATEOID,			"PRIVATEOID" },
};

static const pair_array_t dnssec_array_algorithm = {
	.count = sizeof(dnssec_array_algorithm_data) / sizeof(pair_t),
	.data = dnssec_array_algorithm_data
};

const pair_array_t *select_array(dns_array_e type) {
	switch (type) {
		case DNS_ARRAY_OPCODE: return &dns_array_opcode; break;
		case DNS_ARRAY_RCODE: return &dns_array_rcode; break;
		case DNS_ARRAY_QTYPE: return &dns_array_qtype; break;
		case DNS_ARRAY_QCLASS: return &dns_array_qclass; break;
		case DNSSEC_ARRAY_ALGORITHM: return &dnssec_array_algorithm; break;
	}
	return NULL;
}

const char *totext(dns_array_e type, int key) {
	const pair_array_t *array = select_array(type);
	const pair_t *result = pair_array_lookup_key(array, key);
	return result == NULL ? pair_array_last(array)->value : result->value;
}

int fromtext(dns_array_e type, const char *value) {
	const pair_array_t *array = select_array(type);
	const pair_t *result = pair_array_lookup_value(array, value);
	return result == NULL ? pair_array_last(array)->key : result->key;
}

const char *flags_totext(const dns_hdr_flags_t *value) {
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

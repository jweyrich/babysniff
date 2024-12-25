/**
 *	References:
 *		http://en.wikipedia.org/wiki/List_of_DNS_record_types
 *		http://www.bind9.net/dns-parameters
 *		http://www.iana.org/assignments/dns-parameters
 **/

#pragma once

typedef enum {
	DNS_FLAG_OFF	= 0,
	DNS_FLAG_ON		= 1
} dns_flag_e;

typedef enum {
	// RFC 1035
	DNS_OP_QUERY	= 0,
	DNS_OP_IQUERY_	= 1, // Inverse query (OBSOLETE: RFC 3425)
	DNS_OP_STATUS	= 2,
	// RFC 1996
	DNS_OP_NOTIFY	= 4,
	// RFC 2136
	DNS_OP_UPDATE	= 5
} dns_opcode_e;

typedef enum {
	// RFC 1035
	DNS_CLASS_IN	= 1, // Internet
	DNS_CLASS_CS	= 2, // CSNET (OBSOLETE)
	// Moon 1981
	DNS_CLASS_CH	= 3, // CHAOS
	// Dyer 1987
	DNS_CLASS_HS	= 4, // Hesiod
	// RFC 2136
	DNS_QCLASS_NONE	= 254,
	// RFC 1035
	DNS_QCLASS_ANY	= 255
} dns_qclass_e;

typedef enum {
	// RFC 1035
	DNS_RC_NOERROR	= 0,
	DNS_RC_FORMERR	= 1,
	DNS_RC_SERVFAIL	= 2,
	DNS_RC_NXDOMAIN	= 3,
	DNS_RC_NOTIMP	= 4,
	DNS_RC_REFUSED	= 5,
	// RFC 2136
	DNS_RC_YXDOMAIN	= 6,
	DNS_RC_YXRRSET	= 7,
	DNS_RC_NXRRSET	= 8,
	DNS_RC_NOTAUTH	= 9,
	DNS_RC_NOTZONE	= 10
} dns_rcode_e;

typedef enum {
	// RFC 2671
	DNS_RC_BADVERS	= 16,
	// RFC 2845
	DNS_RC_BADSIG	= 16,
	DNS_RC_BADKEY	= 17,
	DNS_RC_BADTIME	= 18,
	// RFC 2930
	DNS_RC_BADMODE	= 19,
	DNS_RC_BADNAME	= 20,
	DNS_RC_BADALG	= 21,
	// RFC 4635
	DNS_RC_BADTRUNC	= 22
} dns_rcode_ex_e;

typedef enum {
	// RFC 1035
	DNS_TYPE_A			= 1, // IPv4 address
	DNS_TYPE_NS			= 2, // Authoritative name server
	DNS_TYPE_MD_		= 3, // Mail destination (OBSOLETE: RFC 973, use MX instead)
	DNS_TYPE_MF_		= 4, // Mail forwarder (OBSOLETE: RFC 973, use MX instead)
	DNS_TYPE_CNAME		= 5, // Canonical name for an alias
	DNS_TYPE_SOA		= 6, // Marks the start of a zone of authorit
	DNS_TYPE_MB_		= 7, // Mailbox domain name (OBSOLETE: RFC 2505)
	DNS_TYPE_MG_		= 8, // Mail group member (OBSOLETE: RFC 2505)
	DNS_TYPE_MR_		= 9, // Mail rename domain name (OBSOLETE: RFC 2505)
	DNS_TYPE_NULL_		= 10, // Null RR (OBSOLETE: RFC 1035)
	DNS_TYPE_WKS_		= 11, // Well known service description (OBSOLETE: RFC 1123)
	DNS_TYPE_PTR		= 12, // Domain name pointer
	DNS_TYPE_HINFO_		= 13, // Host information (OBSOLETE: not in use)
	DNS_TYPE_MINFO_		= 14, // Mailbox or mail list information (OBSOLETE: RFC 2505)
	DNS_TYPE_MX			= 15, // Mail exchange
	DNS_TYPE_TXT		= 16, // Text strings
	// RFC 1183
	DNS_TYPE_RP_		= 17, // Responsible Person (OBSOLETE: not in use)
	DNS_TYPE_AFSDB		= 18, // AFS Data Base location
	DNS_TYPE_X25_		= 19, // X.25 PSDN address (OBSOLETE: not in use)
	DNS_TYPE_ISDN_		= 20, // ISDN address (OBSOLETE: not in use)
	DNS_TYPE_RT_		= 21, // Route Through (OBSOLETE: not in use)
	// RFC 1706
	DNS_TYPE_NSAP_		= 22, // NSAP address. NSAP style A record (OBSOLETE: not in use)
	// RFC 1348
	DNS_TYPE_NSAPPTR_	= 23, // (OBSOLETE: not in use)
	// RFC 2535
	DNS_TYPE_SIG		= 24, // Security signature used in SIG(0)
	// RFC 4034
	DNS_TYPE_KEY		= 25, // Security key
	// RFC 1664, RFC 2163
	DNS_TYPE_PX_		= 26, // X.400 mail mapping information (OBSOLETE: not in use)
	// RFC 1712
	DNS_TYPE_GPOS_		= 27, // Geographical Position (OBSOLETE: early limited version of LOC)
	// RFC 3596
	DNS_TYPE_AAAA		= 28, // IPv6 Address
	// RFC 1876
	DNS_TYPE_LOC		= 29, // Location Information
	// RFC 2535, RFC 2065
	DNS_TYPE_NXT_		= 30, // Next Domain (OBSOLETE: RFC 3755)
	// Patton
	DNS_TYPE_EID_		= 31, // Endpoint Identifier (OBSOLETE: not in use)
	// Patton
	DNS_TYPE_NIMLOC_	= 32, // Nimrod Locator (OBSOLETE: not in use)
	// RFC 2782
	DNS_TYPE_SRV		= 33, // Server Selection
	// ???
	DNS_TYPE_ATMA_		= 34, // ATM Address (OBSOLETE: not in use)
	// RFC 3403
	DNS_TYPE_NAPTR		= 35, // Naming Authority Pointer
	// RFC 2230
	DNS_TYPE_KX_		= 36, // Key Exchanger (OBSOLETE: part of the first version of DNSSEC)
	// RFC 4398
	DNS_TYPE_CERT		= 37,
	// RFC 2874, RFC 3226
	DNS_TYPE_A6_		= 38, // (OBSOLETE: RFC 3363 downgraded to experimental)
	// RFC 2672
	DNS_TYPE_DNAME		= 39,
	// ???
	DNS_TYPE_SINK_		= 40, // Eastlake (Kitchen Sink) (OBSOLETE: never made it to RFC status)
	// RFC 2671
	DNS_QTYPE_OPT		= 41, // EDNS OPT -- Extension mechanisms
	// RFC 3123
	DNS_TYPE_APL_		= 42, // (OBSOLETE: not in use)
	// RFC 4034
	DNS_TYPE_DS			= 43, // Desigated/Delegation Signer
	// RFC 4255
	DNS_TYPE_SSHFP		= 44, // SSH Public Key Fingerprint
	// RFC 4025
	DNS_TYPE_IPSECKEY	= 45, // IPSEC Key
	// RFC 4034
	DNS_TYPE_RRSIG		= 46,
	DNS_TYPE_NSEC		= 47, // Next-Secure record
	DNS_TYPE_DNSKEY		= 48,
	// RFC 4701
	DNS_TYPE_DHCID		= 49, // DHCP identifier
	// RFC 5155
	DNS_TYPE_NSEC3		= 50, // NSEC record version 3
	DNS_TYPE_NSEC3PARAM	= 51, // NSEC3 parameters
	// RFC 5205
	DNS_TYPE_HIP		= 55, // Host Identity Protocol
	// Reid
	DNS_TYPE_NINFO		= 56,
	DNS_TYPE_RKEY		= 57,
	// RFC 4408
	DNS_TYPE_SPF		= 99, // Sender Policy Framework
	// IANA Reserved
	DNS_TYPE_UINFO_		= 100, // (OBSOLETE: no RFC documentation)
	DNS_TYPE_UID_		= 101, // (OBSOLETE: no RFC documentation)
	DNS_TYPE_GID_		= 102, // (OBSOLETE: no RFC documentation)
	DNS_TYPE_UNSPEC_	= 103, // (OBSOLETE: no RFC documentation)
	// ???
	DNS_TYPE_ADDRS		= 248, // ???
	// RFC 2930
	DNS_QTYPE_TKEY		= 249,
	// RFC 2845, RFC 3645
	DNS_TYPE_TSIG		= 250, // Transaction Signature
	// RFC 1995
	DNS_QTYPE_IXFR		= 251, // Incremental transfer
	// RFC 1035
	DNS_QTYPE_AXFR		= 252, // Transfer of an entire zone
	DNS_QTYPE_MAILB_	= 253, // Mailbox-related RRs (MB, MG or MR) (OBSOLETE: RFC 2505)
	DNS_QTYPE_MAILA_	= 254, // Mail agent RRs (OBSOLETE: RFC 973)
	DNS_QTYPE_ANY		= 255, // All cached records
	// Weiler
	DNS_TYPE_TA			= 32768, // DNSSEC Trust Authorities
	// RFC 4431
	DNS_TYPE_DLV		= 32769 // DNSSEC Lookaside Validation
} dns_qtype_e;

typedef enum {
	DNS_SECTION_QUESTION	= 1,
	DNS_SECTION_ANSWER		= 2,
	DNS_SECTION_AUTHORITY	= 3,
	DNS_SECTION_ADDITIONAL	= 4
} dns_section_e;

// REFERENCE: https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
typedef enum {
	DNSSEC_ALG_DELETE				= 0, // RFC 4034, DELETE DS
	DNSSEC_ALG_RSAMD5				= 1, // RFC 3110, RSA/MD5 (DEPRECATED)
	DNSSEC_ALG_DH					= 2, // RFC 2539, Diffie-Hellman
	DNSSEC_ALG_DSA					= 3, // RFC 3755, DSA/SHA-1 (OPTIONAL)
	DNSSEC_ALG_ECC					= 4, // RFC ???, Elliptic Curve
	DNSSEC_ALG_RSASHA1				= 5, // RFC 3110, RSA/SHA-1 (MANDATORY)
	DNSSEC_ALG_DSA_NSEC3_SHA1		= 6, // RFC 5155, DSA/SHA-1 NSEC3
	DNSSEC_ALG_RSASHA1_NSEC3_SHA1	= 7, // RFC 5155, alias for DNSSEC_ALG_RSASHA1 - Don't break NSEC3-unaware resolvers
	DNSSEC_ALG_RSASHA256			= 8, // RFC 5702, RSA/SHA-256
	DNSSEC_ALG_RESERVED_9			= 9,
	DNSSEC_ALG_RSASHA512			= 10, // RFC 5702, RSA/SHA-512
	DNSSEC_ALG_RESERVED_11			= 11,
	DNSSEC_ALG_ECC_GOST			    = 12, // RFC 5933, GOST R 34.10-2001 as per https://datatracker.ietf.org/doc/rfc5933/
	DNSSEC_ALG_ECDSAP256SHA256		= 13, // RFC 6605, ECDSA Curve P-256 with SHA-256
	DNSSEC_ALG_ECDSAP384SHA384		= 14, // RFC 6605, ECDSA Curve P-384 with SHA-384
	DNSSEC_ALG_ED25519				= 15, // RFC 8080, Ed25519
	DNSSEC_ALG_ED448				= 16, // RFC 8080, Ed448
	DNSSEC_ALG_SM2SM3				= 17, // RFC 8997, SM2 with SM3
	DNSSEC_ALG_ECC_GOST12		 	= 23, // RFC 9558, GOST R 34.10-2012
	// ???
	DNSSEC_ALG_INDIRECT				= 252, // RFC 4034, Indirect
	DNSSEC_ALG_PRIVATEDNS			= 253, // RFC 4034, Private (OPTIONAL)
	DNSSEC_ALG_PRIVATEOID			= 254 // RFC 4034, Private (OPTIONAL)
} dnssec_algorithm_e;

// REFERENCE: http://rfc-ref.org/RFC-TEXTS/4034/chapter11.html#d4e448090
typedef enum {
	DNSSEC_DIG_SHA1 = 1 // SHA-1 (MANDATORY)
} dnssec_digest_e;

//http://rfc-ref.org/RFC-TEXTS/4034/chapter3.html
//http://www.dnspython.org/docs/1.7.1/html/

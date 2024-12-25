#pragma once

#include "proto/dns/types.h"
// #include "types/queue.h"
#include <stdint.h>

//
// Question
//
typedef struct dns_question {
	char *			name; // Domain name
	dns_qtype_e		qtype:16; // Type of the query
	dns_qclass_e	qclass:16; // Class of the query
} dns_question_t;

//
// A
//
typedef struct dns_rdata_a {
	uint32_t	address[1]; // Internet address
} dns_rdata_a_t;

//
// AAAA
//
typedef struct dns_rdata_aaaa {
	uint32_t	address[4]; // Internet address
} dns_rdata_aaaa_t;

//
// NS
//
typedef struct dns_rdata_ns {
	char *	name; // Host which should be authoritative for the specified class and domain
} dns_rdata_ns_t;

//
// CNAME
//
typedef struct dns_rdata_cname {
	char *	name; // Canonical or primary name for the owner. The owner name is an alias
} dns_rdata_cname_t;

//
// SOA
//
typedef struct dns_rdata_soa {
	char *  	mname; // Server that was the original or primary source of data for this zone
	char *  	rname; // Mailbox mailbox of the person responsible for this zone
	uint32_t	serial; // Version number of the original copy of the zone
	int32_t	 refresh; // Time interval before the zone should be refreshed
	int32_t 	retry; // Time interval that should elapse before a failed refresh should be retried
	int32_t	 expire; // Upper limit on the time interval that can elapse before the zone is no longer authoritative
	uint32_t	minimum; // Minimum TTL for any RR from this zone
} dns_rdata_soa_t;

//
// PTR
//
typedef struct dns_rdata_ptr {
	char *	name; // Domain name which points to some location in the domain name space
} dns_rdata_ptr_t;

//
// MX
//
typedef struct dns_rdata_mx {
	uint16_t	preference; // Preference given to this RR among others at the same owner
	char *	  exchange; // Host willing to act as a mail exchange for the owner name
} dns_rdata_mx_t;

//
// RRSIG
//
// REFERENCE: https://datatracker.ietf.org/doc/html/rfc4034#section-3.1
typedef struct dnssec_rrsig {
	uint16_t	typec;	// Type covered
	uint8_t		algnum; // Algorithm number
	uint8_t		labels;
	uint32_t	original_ttl;
	uint32_t	signature_expiration;
	uint32_t	signature_inception;
	uint16_t	key_tag;
	char *		signer_name;
	char *		signature;
} dnssec_rdata_rrsig_t;

//
// Section
//
//typedef struct dns_section {
//	dns_section_e	type;
//	union section {
//		dns_question_t	question;
//		dns_rr_t		rr;
//	} section;
//} dns_section_t;
//
//
// Auxiliar
//
//typedef struct dnsaux_label {
//	dns_label_t					data;
//	STAILQ_ENTRY(dnsaux_label)	next;
//} dnsaux_label_t;
//
//typedef struct dnsaux_rr {
//	STAILQ_HEAD( , dnsaux_label_t) rname;
//} dnsaux_rr_t;
//
//static void free_rr_labels(dnsaux_rr_t *rr) {
//	dnsaux_label_t *current, *next;
//	// Faster than STAILQ_REMOVE_HEAD
//	current = STAILQ_FIRST(&rr->rname);
//	while (current != NULL) {
//		next = STAILQ_NEXT(current, next);
//		if (current->data.domain != NULL)
//			free(current->data.domain);
//		free(current);
//		current = next;
//	}
//}
//	STAILQ_INIT(&rr.rname);
//	STAILQ_INSERT_TAIL(&rr->rname, label, next);
//	STAILQ_FOREACH(label, &rr.rname, next) {
//		DPRINT(DNS, "%d %s\n", label->length, label->domain);
//	}

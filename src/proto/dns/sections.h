#pragma once

#include "proto/dns/types.h"
#include "proto/dns/sections/question.h"
#include "proto/dns/sections/rr.h"
// #include "types/queue.h"
#include <stdint.h>

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

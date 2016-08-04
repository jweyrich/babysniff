#include "proto_ops.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "config.h"
#include "log.h"

int sniff_icmp_fromwire(const byte *packet, size_t length) {
	const struct icmp *header = (struct icmp *)packet;

	LOG_PRINTF(ICMP, "-- ICMP (%lu bytes)\n", length);
	if (length < ICMP_MINLEN || header->icmp_type > ICMP_MAXTYPE) {
		LOG_PRINTF_INDENT(ICMP, 2, "\tinvalid packet\n");
		return -1;
	}
	LOG_PRINTF_INDENT(ICMP, 2, "\ttype   : %u\n", header->icmp_type); // type of message
	LOG_PRINTF_INDENT(ICMP, 2, "\tcode   : %u\n", header->icmp_code); // type sub code
	LOG_PRINTF_INDENT(ICMP, 2, "\tcksum  : %u\n", ntohs(header->icmp_cksum)); // ones complement cksum of struct

	if (header->icmp_type == ICMP_ECHOREPLY || header->icmp_type == ICMP_ECHO) {
		LOG_PRINTF_INDENT(ICMP, 2, "\tid	: %u\n", ntohs(header->icmp_id));
		LOG_PRINTF_INDENT(ICMP, 2, "\tseq   : %u\n", ntohs(header->icmp_seq));
	} else if (header->icmp_type == ICMP_UNREACH) {
		if (header->icmp_code == ICMP_UNREACH_NEEDFRAG) {
			LOG_PRINTF_INDENT(ICMP, 2, "\tpmvoid : %u\n", ntohs(header->icmp_pmvoid));
			LOG_PRINTF_INDENT(ICMP, 2, "\tnextmtu: %u\n", ntohs(header->icmp_nextmtu));
		} else {
			LOG_PRINTF_INDENT(ICMP, 2, "\tvoid   : %u\n", ntohl(header->icmp_void));
		}
	} else if (header->icmp_type == ICMP_REDIRECT) {
		LOG_PRINTF_INDENT(ICMP, 2, "\tgwaddr : %s\n", inet_ntoa(*(struct in_addr *)&(header->icmp_gwaddr)));
	} else if (header->icmp_type == ICMP_TIMXCEED) {
		LOG_PRINTF_INDENT(ICMP, 2, "\tvoid   : %u\n", ntohl(header->icmp_void));
	}

	return 0;
}

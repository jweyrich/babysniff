#ifndef _DEFAULT_SOURCE
#   define _DEFAULT_SOURCE
#endif
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <stdio.h>

#include "config.h"
#include "log.h"
#include "proto_ops.h"
#include "utils.h"

int sniff_icmp_fromwire(const uint8_t *packet, size_t length, const config_t *config) {
	const struct icmp *header = (struct icmp *)packet;

	if (config->display_filters_flag.icmp) {
		LOG_PRINTF("-- ICMP (%lu bytes)\n", length);
	}

	if (length < ICMP_MINLEN || header->icmp_type > ICMP_MAXTYPE) {
		if (config->display_filters_flag.icmp) {
			LOG_PRINTF_INDENT(2, "\tinvalid packet\n");
		}
		return -1;
	}

	if (config->display_filters_flag.icmp) {
		LOG_PRINTF_INDENT(2, "\ttype   : %u\n", header->icmp_type); // type of message
		LOG_PRINTF_INDENT(2, "\tcode   : %u\n", header->icmp_code); // type sub code
		LOG_PRINTF_INDENT(2, "\tcksum  : %u\n", ntohs(header->icmp_cksum)); // ones complement cksum of struct

		if (header->icmp_type == ICMP_ECHOREPLY || header->icmp_type == ICMP_ECHO) {
				LOG_PRINTF_INDENT(2, "\tid	: %u\n", ntohs(header->icmp_id));
				LOG_PRINTF_INDENT(2, "\tseq   : %u\n", ntohs(header->icmp_seq));
		} else if (header->icmp_type == ICMP_UNREACH) {
			if (header->icmp_code == ICMP_UNREACH_NEEDFRAG) {
				LOG_PRINTF_INDENT(2, "\tpmvoid : %u\n", ntohs(header->icmp_pmvoid));
				LOG_PRINTF_INDENT(2, "\tnextmtu: %u\n", ntohs(header->icmp_nextmtu));
			} else {
				LOG_PRINTF_INDENT(2, "\tvoid   : %u\n", ntohl(header->icmp_void));
			}
		} else if (header->icmp_type == ICMP_REDIRECT) {
			char icmp_gwaddr_as_str[INET_ADDRSTRLEN];
			utils_in_addr_to_str(icmp_gwaddr_as_str, sizeof(icmp_gwaddr_as_str), &header->icmp_gwaddr);
			LOG_PRINTF_INDENT(2, "\tgwaddr : %s\n", icmp_gwaddr_as_str);
		} else if (header->icmp_type == ICMP_TIMXCEED) {
			LOG_PRINTF_INDENT(2, "\tvoid   : %u\n", ntohl(header->icmp_void));
		}
	}

	return 0;
}

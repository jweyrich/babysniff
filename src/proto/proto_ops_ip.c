#ifndef _DEFAULT_SOURCE
#   define _DEFAULT_SOURCE
#endif

#include "compat/network_compat.h"
#include "config.h"
#include "log.h"
#include "macros.h"
#include "proto_ops.h"
#include "system.h"
#include "utils.h"

#include <stdio.h>

#ifndef OS_WINDOWS
#	include <net/ethernet.h>
#	include <netinet/ip.h>
#	include <netdb.h>
#endif

int sniff_ip_fromwire(const uint8_t *packet, size_t length, const config_t *config) {
	int result = 0;

	// Basic bounds check before accessing any fields
	if (length < sizeof(struct ip)) {
		return -1;
	}

	const struct ip *header = (struct ip *)packet;
	uint16_t header_len = header->ip_hl << 2;
	uint16_t ip_len = ntohs(header->ip_len);
	uint16_t ip_id = ntohs(header->ip_id);
	uint16_t ip_off = ntohs(header->ip_off) & IP_OFFMASK; // fragment offset (lower 13 bits)
	uint16_t ip_sum = ntohs(header->ip_sum);

	if (config->display_filters_flag.ip) {
		LOG_PRINTF("-- IP (%lu bytes)\n", ip_len);
	}

	// Basic validation: check minimum packet length, IP version, and header length
	if (header->ip_v != 4 || header_len < sizeof(struct ip) || header_len > length) {
		if (config->display_filters_flag.ip) {
			LOG_PRINTF_INDENT(2, "\tinvalid packet (validation failed: length=%lu, ip_v=%u, ip_hl=%u, header_len=%u)\n",
				length, header->ip_v, header->ip_hl, header_len);
		}
		return -1;
	}

	// Allow packets larger than IP length (common with padding),
	// but reject truncated packets
	if (ip_len > length) {
		if (config->display_filters_flag.ip) {
			LOG_PRINTF_INDENT(2, "\tinvalid packet (truncated)\n");
		}
		return -1;
	}

	char ip_src_as_str[INET_ADDRSTRLEN];
	utils_in_addr_to_str(ip_src_as_str, sizeof(ip_src_as_str), &header->ip_src);

	char ip_dst_as_str[INET_ADDRSTRLEN];
	utils_in_addr_to_str(ip_dst_as_str, sizeof(ip_dst_as_str), &header->ip_dst);

	if (config->display_filters_flag.ip) {
		LOG_PRINTF_INDENT(2, "\tv  : %u\n", header->ip_v); // version
		LOG_PRINTF_INDENT(2, "\thl : %u\n", header_len); // header length
		LOG_PRINTF_INDENT(2, "\ttos: 0x%x\n", header->ip_tos); // type of service
		LOG_PRINTF_INDENT(2, "\tlen: %u\n", ip_len); // total length
		LOG_PRINTF_INDENT(2, "\tid : %u\n", ip_id); // identification
		LOG_PRINTF_INDENT(2, "\toff: %u\n", ip_off); // fragment offset (lower 13 bits)
		LOG_PRINTF_INDENT(2, "\tttl: %u\n", header->ip_ttl); // time to live
		struct protoent *proto = getprotobynumber(header->ip_p);
		LOG_PRINTF_INDENT(2, "\tp  : %u [%s]\n", header->ip_p, proto ? proto->p_name : "unknown");
		LOG_PRINTF_INDENT(2, "\tsum: %u\n", ip_sum); // checksum
		LOG_PRINTF_INDENT(2, "\tsrc: %s\n", ip_src_as_str); // source address
		LOG_PRINTF_INDENT(2, "\tdst: %s\n", ip_dst_as_str); // destination address
	}

	// fragmented? Check the More Fragments flag
	if ((ip_off & IP_MF) != 0) {
		if (config->display_filters_flag.ip) {
			LOG_PRINTF_INDENT(2, "\tfragmented\n");
		}
		return -1;
	}

	packet = (uint8_t *)PTR_ADD(header, header_len);
	// Use the IP packet's actual payload length, not the received buffer length
	size_t payload_length = ip_len - header_len;

	switch (header->ip_p) {
		case IPPROTO_TCP: result = sniff_tcp_fromwire(packet, payload_length, config); break;
		case IPPROTO_UDP: result = sniff_udp_fromwire(packet, payload_length, config); break;
		case IPPROTO_ICMP: result = sniff_icmp_fromwire(packet, payload_length, config); break;
		default: break;
	}

	return result;
}

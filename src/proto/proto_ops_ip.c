#include "config.h"
#include "log.h"
#include "macros.h"
#include "proto_ops.h"
#include "utils.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stdio.h>

// TODO(jweyrich): parse options
// http://64.233.163.132/search?q=cache:IxxD7kq2CAAJ:www.w00w00.org/files/sectools/fragrouter/print.c+IP_OFFMASK&cd=1&hl=en&ct=clnk
// TODO(jweyrich): linux uses struct iphdr

int sniff_ip_fromwire(const uint8_t *packet, size_t length, const config_t *config) {
	int result = 0;
	const struct ip *header = (struct ip *)packet;
	uint16_t header_len = header->ip_hl << 2;
	uint16_t ip_len = ntohs(header->ip_len);

	if (config->filters_flag.ip) {
		LOG_PRINTF("-- IP (%lu bytes)\n", length);
	}

	if (length != ip_len) {
		if (config->filters_flag.ip) {
			LOG_PRINTF_INDENT(2, "\tinvalid packet\n");
		}
		return -1;
	}

	char ip_src_as_str[INET_ADDRSTRLEN];
	utils_in_addr_to_str(ip_src_as_str, sizeof(ip_src_as_str), &header->ip_src);

	char ip_dst_as_str[INET_ADDRSTRLEN];
	utils_in_addr_to_str(ip_dst_as_str, sizeof(ip_dst_as_str), &header->ip_dst);

	if (config->filters_flag.ip) {
		LOG_PRINTF_INDENT(2, "\tv  : %u\n", header->ip_v); // version
		LOG_PRINTF_INDENT(2, "\thl : %u\n", header->ip_hl); // header length
		LOG_PRINTF_INDENT(2, "\ttos: 0x%x\n", header->ip_tos); // type of service
		LOG_PRINTF_INDENT(2, "\tlen: %u\n", ip_len); // total length
		LOG_PRINTF_INDENT(2, "\tid : %u\n", ntohs(header->ip_id)); // identification
		LOG_PRINTF_INDENT(2, "\toff: %u\n", ntohs(header->ip_off)); // fragment offset
		LOG_PRINTF_INDENT(2, "\tttl: %u\n", header->ip_ttl); // time to live
		LOG_PRINTF_INDENT(2, "\tp  : %u [%s]\n", header->ip_p, getprotobynumber(header->ip_p)->p_name); // protocol
		LOG_PRINTF_INDENT(2, "\tsum: %u\n", ntohs(header->ip_sum)); // checksum
		LOG_PRINTF_INDENT(2, "\tsrc: %s\n", ip_src_as_str); // source address
		LOG_PRINTF_INDENT(2, "\tdst: %s\n", ip_dst_as_str); // destination address
	}

	// fragmented?
	if ((header->ip_off & IP_MF) != 0) {
		if (config->filters_flag.ip) {
			LOG_PRINTF_INDENT(2, "\tfragmented\n");
		}
		return -1;
	}

	packet = (uint8_t *)PTR_ADD(header, header_len);
	length -= header_len;

	switch (header->ip_p) {
		case IPPROTO_TCP: result = sniff_tcp_fromwire(packet, length, config); break;
		case IPPROTO_UDP: result = sniff_udp_fromwire(packet, length, config); break;
		case IPPROTO_ICMP: result = sniff_icmp_fromwire(packet, length, config); break;
		default: break;
	}

	return result;
}

#include "config.h"
#include "dump.h"
#include "log.h"
#include "macros.h"
#include "proto_ops.h"
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <stdio.h>

#define UDP_HDR_LEN 8

int sniff_udp_fromwire(const uint8_t *packet, size_t length, const config_t *config) {
	const struct udphdr *header = (struct udphdr *)packet;
	uint16_t sport = ntohs(header->uh_sport);
	uint16_t dport = ntohs(header->uh_dport);

	if (config->filters_flag.udp) {
		LOG_PRINTF("-- UDP (%lu bytes)\n", length);
		LOG_PRINTF_INDENT(2,  "\tsport: %u\n", sport); // source port
		LOG_PRINTF_INDENT(2,  "\tdport: %u\n", dport); // destination port
		LOG_PRINTF_INDENT(2,  "\tulen : %u\n", ntohs(header->uh_ulen)); // udp length
		LOG_PRINTF_INDENT(2,  "\tsum  : %u\n", header->uh_sum); // udp checksum
	}

	packet = (uint8_t *)PTR_ADD(packet, UDP_HDR_LEN);
	length = ntohs(header->uh_ulen) - UDP_HDR_LEN;

	// If there is no data, we can return now
	if (length == 0) {
		return 0;
	}

	if (sport == 53 || dport == 53) {
		sniff_dns_fromwire(packet, length, config);
	}

	if (config->filters_flag.udp_data) {
		LOG_PRINTF("showing %lu bytes:\n", length);
		dump_hex(stdout, packet, length, 0);
	}

	return 0;
}

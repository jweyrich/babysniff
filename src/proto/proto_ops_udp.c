#include "proto_ops.h"
#include <stdio.h>

#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <arpa/inet.h>
#include <netinet/udp.h>

#include "config.h"
#include "dump.h"
#include "log.h"
#include "macros.h"

#define UDP_HDR_LEN 8

int sniff_udp_fromwire(const byte *packet, size_t length) {
	const struct udphdr *header = (struct udphdr *)packet;
	uint16_t sport = ntohs(header->uh_sport);
	uint16_t dport = ntohs(header->uh_dport);

	LOG_PRINTF(UDP, "-- UDP (%lu bytes)\n", length);
	LOG_PRINTF_INDENT(UDP, 2,  "\tsport: %u\n", sport); // source port
	LOG_PRINTF_INDENT(UDP, 2,  "\tdport: %u\n", dport); // destination port
	LOG_PRINTF_INDENT(UDP, 2,  "\tulen : %u\n", ntohs(header->uh_ulen)); // udp length
	LOG_PRINTF_INDENT(UDP, 2,  "\tsum  : %u\n", header->uh_sum); // udp checksum

	packet = (byte *)PTR_ADD(packet, UDP_HDR_LEN);
	length = ntohs(header->uh_ulen) - UDP_HDR_LEN;

	if (sport == 53 || dport == 53) {
		sniff_dns_fromwire(packet, length);
	}

#if LOG_ENABLED(UDP_DATA)
	LOG_PRINTF(UDP_DATA, "showing %lu bytes:\n", length);
	dump_hex(stdout, packet, length, 0);
#endif
	return 0;
}

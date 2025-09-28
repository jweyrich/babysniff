#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdio.h>

#include "system.h"
#ifdef OS_LINUX
#	include <netinet/ether.h> // for `ether_ntoa`
#endif

#include "config.h"
#include "log.h"
#include "macros.h"
#include "proto_ops.h"


// TODO(jweyrich): linux uses struct ethhdr
int sniff_eth_fromwire(const uint8_t *packet, size_t length, const config_t *config) {
	int result = 0;
	const struct ether_header *header = (struct ether_header *)packet;
	uint16_t type = ntohs(header->ether_type);
	uint16_t header_len = ETHER_HDR_LEN;

	if (config->display_filters_flag.eth) {
		LOG_PRINTF("-- ETH (%lu bytes)\n", length);
	}

	if (type < ETHER_MIN_LEN) {
		if (config->display_filters_flag.eth) {
			LOG_PRINTF_INDENT(2, "\tinvalid packet\n");
		}
		return -1;
	}

	if (config->display_filters_flag.eth) {
		if (type <= ETHERMTU)
			LOG_PRINTF_INDENT(2, "\tframe: IEEE 802.3\n");
		else
			LOG_PRINTF_INDENT(2, "\tframe: Ethernet\n");
		LOG_PRINTF_INDENT(2, "\tdhost: %s\n", ether_ntoa((struct ether_addr *)&header->ether_dhost));
		LOG_PRINTF_INDENT(2, "\tshost: %s\n", ether_ntoa((struct ether_addr *)&header->ether_shost));
		if (type < ETHERMTU)
			LOG_PRINTF_INDENT(2, "\tlen  : %u\n", type);
		else
			LOG_PRINTF_INDENT(2, "\ttype : 0x%x\n", type);
	}

	packet = (uint8_t *)PTR_ADD(header, header_len);
	length -= header_len;

	switch (type) {
		case ETHERTYPE_IP:
			result = sniff_ip_fromwire(packet, length, config);
			break;
		case ETHERTYPE_ARP:
			result = sniff_arp_fromwire(packet, length, config);
			break;
		default:
			break;
	}

	return result;
}

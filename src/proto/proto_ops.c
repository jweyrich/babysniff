#include "proto_ops.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <string.h>

int sniff_packet_fromwire(const uint8_t *packet, size_t length, int protocol, const config_t *config) {
	int result = 0;
	switch (protocol) {
		case 0:
			result = sniff_eth_fromwire(packet, length, config);
			break;
		case ETHERTYPE_IP:
			result = sniff_ip_fromwire(packet, length, config);
			break;
		default: break;
	}
	return result;
}

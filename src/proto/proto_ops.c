#include "proto_ops.h"
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

int sniff_packet_fromwire(const byte *packet, size_t length, int protocol) {
	int result = 0;
	switch (protocol) {
		case 0:
			result = sniff_eth_fromwire(packet, length);
			break;
		case ETHERTYPE_IP:
			result = sniff_ip_fromwire(packet, length);
			break;
		default: break;
	}
	return result;
}

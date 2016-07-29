#include "proto_ops.h"
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

//const char *mac_ntoa(const byte *mac) {
//	static char buffer[18];
//	sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
//		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
//	return buffer;
//}

int sniff_packet_fromwire(const byte *packet, size_t length, int protocol) {
	int result = 0;
	switch (protocol) {
		case 0: result = sniff_eth_fromwire(packet, length); break;
		case ETHERTYPE_IP: result = sniff_ip_fromwire(packet, length); break;
		default: break;
	}
	return result;
}

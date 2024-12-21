#include "proto_ops.h"
#include <stdio.h>
#include <arpa/inet.h>
#include "system.h"
#ifdef OS_LINUX
#	include <netinet/ether.h> // for `ether_ntoa`
#endif
#include <netinet/if_ether.h>
#include "config.h"
#include "log.h"
#include "types/pair.h"
#include "utils.h"

// TODO(jweyrich): request/responses: http://64.233.163.132/search?q=cache:fTLz8j_w-0YJ:www.few.vu.nl/~cn/arp.c+arp_hln&cd=1&hl=en&ct=clnk

typedef enum {
	ARP_ARRAY_HRD,
	ARP_ARRAY_PRO,
	ARP_ARRAY_OP,
} arp_array_e;

static pair_t arp_array_hrd_data[] = {
	{ ARPHRD_ETHER,				"Ethernet" },
#ifdef ARPHRD_IEEE802
	{ ARPHRD_IEEE802,			"IEEE802" },
#endif
#ifdef ARPHRD_FRELAY
	{ ARPHRD_FRELAY,			"FRELAY" },
#endif
#ifdef ARPHRD_IEEE1394
	{ ARPHRD_IEEE1394,			"IEEE1394" },
#endif
#ifdef ARPHRD_IEEE1394_EUI64
	{ ARPHRD_IEEE1394_EUI64,	"IEEE1394EUI64" },
#endif
	{ 0,						"Unknown" },
};

static const pair_array_t arp_array_hrd = {
	.count = sizeof(arp_array_hrd_data) / sizeof(pair_t),
	.data = arp_array_hrd_data
};

static pair_t arp_array_pro_data[] = {
	{ ETHERTYPE_PUP,		"PUP" },
	{ ETHERTYPE_IP,			"IP" },
	{ ETHERTYPE_ARP,		"ARP" },
	{ ETHERTYPE_REVARP,		"RARP" },
	{ ETHERTYPE_VLAN,		"VLAN" }, // IEEE 802.1Q VLAN tagging
	{ ETHERTYPE_IPV6,		"IP6" },
	{ ETHERTYPE_LOOPBACK,	"LO" }, // used to test interfaces
	{ ETHERTYPE_TRAIL,		"TRAIL" }, // trailer packet
	{ 0,					"Unknown" },
};

static const pair_array_t arp_array_pro = {
	.count = sizeof(arp_array_pro_data) / sizeof(pair_t),
	.data = arp_array_pro_data
};

#ifndef OS_LINUX
#	define ARPOP_RREQUEST	ARPOP_REVREQUEST
#	define ARPOP_RREPLY		ARPOP_REVREPLY
#	define ARPOP_InREQUEST	ARPOP_INVREQUEST
#	define ARPOP_InREPLY	ARPOP_INVREPLY
#	define ARPOP_NAK		10
#endif

static pair_t arp_array_op_data[] = {
	{ ARPOP_REQUEST,	"Request"  }, // request to resolve address
	{ ARPOP_REPLY,		"Reply"    }, // response to previous request
	{ ARPOP_RREQUEST,	"RRequest" }, // request protocol address given hardware
	{ ARPOP_RREPLY,		"RReply"   }, // response giving protocol address
	{ ARPOP_InREQUEST,	"IRequest" }, // request to identify peer
	{ ARPOP_InREPLY,	"IReply"   }, // response identifying peer
	{ ARPOP_NAK,		"NAK"      }, // (ATM)ARP NAK.
	{ 0,				"Unknown"  },
};

static const pair_array_t arp_array_op = {
	.count = sizeof(arp_array_op_data) / sizeof(pair_t),
	.data = arp_array_op_data
};

static const pair_array_t *select_array(arp_array_e type) {
	switch (type) {
		case ARP_ARRAY_HRD: return &arp_array_hrd; break;
		case ARP_ARRAY_PRO: return &arp_array_pro; break;
		case ARP_ARRAY_OP: return &arp_array_op; break;
	}
	return NULL;
}

static const char *totext(arp_array_e type, int key) {
	const pair_array_t *array = select_array(type);
	const pair_t *result = pair_array_lookup_key(array, key);
	return result == NULL ? pair_array_last(array)->value : result->value;
}

static int fromtext(arp_array_e type, const char *value) {
	const pair_array_t *array = select_array(type);
	const pair_t *result = pair_array_lookup_value(array, value);
	return result == NULL ? pair_array_last(array)->key : result->key;
}

int sniff_arp_fromwire(const byte *packet, size_t length) {
	const struct ether_arp *header = (struct ether_arp *)packet;
	uint16_t arphrd = ntohs(header->arp_hrd);
	uint16_t arppro = ntohs(header->arp_pro);
	uint16_t arpop = ntohs(header->arp_op);

	char arp_tha_as_str[INET_ADDRSTRLEN];
	utils_in_addr_to_str(arp_tha_as_str, sizeof(arp_tha_as_str), (struct in_addr *)&header->arp_spa);

	char arp_tpa_as_str[INET_ADDRSTRLEN];
	utils_in_addr_to_str(arp_tpa_as_str, sizeof(arp_tpa_as_str), (struct in_addr *)&header->arp_tpa);

	LOG_PRINTF(ARP, "-- ARP (%lu bytes)\n", length);
	LOG_PRINTF_INDENT(ARP, 2, "hrd: %u [%s]\n", arphrd, totext(ARP_ARRAY_HRD, arphrd)); // format of hardware address
	LOG_PRINTF_INDENT(ARP, 2, "pro: 0x%04x [%s]\n", arppro, totext(ARP_ARRAY_PRO, arppro)); // format of protocol address
	LOG_PRINTF_INDENT(ARP, 2, "hln: %u\n", header->arp_hln); // length of hardware address
	LOG_PRINTF_INDENT(ARP, 2, "pln: %u\n", header->arp_pln); // length of protocol address
	LOG_PRINTF_INDENT(ARP, 2, "op : %u [%s]\n", arpop, totext(ARP_ARRAY_OP, arpop));
	LOG_PRINTF_INDENT(ARP, 2, "sha: %s\n", ether_ntoa((struct ether_addr *)&header->arp_sha)); // sender hardware address
	LOG_PRINTF_INDENT(ARP, 2, "spa: %s\n", arp_tha_as_str); // sender protocol address
	LOG_PRINTF_INDENT(ARP, 2, "tha: %s\n", ether_ntoa((struct ether_addr *)&header->arp_tha)); // target hardware address
	LOG_PRINTF_INDENT(ARP, 2, "tpa: %s\n", arp_tpa_as_str); // target protocol address
	return 0;
}

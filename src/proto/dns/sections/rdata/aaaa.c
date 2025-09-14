#include "aaaa.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/sections/rr.h"
#include "utils.h" // for utils_in6_addr_to_str
#include <arpa/inet.h> // for INET6_ADDRSTRLEN

int parse_rdata_aaaa(dns_rr_t *rr, buffer_t *buffer) {
	for (size_t i=0; i<4; i++) {
		rr->rdata.aaaa.address[i] = buffer_read_uint32(buffer);
		if (buffer_has_error(buffer)) {
			LOG_WARN("detected an error in the buffer while reading RR of type AAAA");
			return -1;
		}
	}
	return 0;
}

void free_rdata_aaaa(dns_rr_t *rr) {
    // Nothing to do
}

void print_rdata_aaaa(dns_rr_t *rr) {
	char ip_as_str[INET6_ADDRSTRLEN];
	const char *ip_addr = utils_in6_addr_to_str(ip_as_str, sizeof(ip_as_str), (struct in6_addr *)rr->rdata.aaaa.address);
	LOG_PRINTF("%s\n", ip_addr);
}

#include "aaaa.h"

#include "compat/network_compat.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/sections/rdata.h"
#include "macros.h"
#include "utils.h" // for utils_in6_addr_to_str

int parse_rdata_aaaa(dns_rdata_t *rdata, buffer_t *buffer) {
	for (size_t i=0; i<4; i++) {
		rdata->aaaa.address[i] = buffer_read_uint32(buffer);
		if (buffer_has_error(buffer)) {
			LOG_WARN("detected an error in the buffer while reading RR of type AAAA");
			return -1;
		}
	}
	return 0;
}

void free_rdata_aaaa(dns_rdata_t *rdata) {
	UNUSED(rdata);
    // Nothing to do
}

void print_rdata_aaaa(dns_rdata_t *rdata) {
	char ip_as_str[INET6_ADDRSTRLEN];
	const char *ip_addr = utils_in6_addr_to_str(ip_as_str, sizeof(ip_as_str), (struct in6_addr *)rdata->aaaa.address);
	LOG_PRINTF("%s\n", ip_addr);
}

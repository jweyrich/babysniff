#include "a.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/sections/rdata.h"
#include "utils.h" // for utils_in_addr_to_str
#include <arpa/inet.h> // for INET_ADDRSTRLEN

int parse_rdata_a(dns_rdata_t *rdata, buffer_t *buffer) {
	rdata->a.address[0] = buffer_read_uint32(buffer);
	if (buffer_has_error(buffer)) {
		LOG_WARN("detected an error in the buffer while reading RR of type A");
		return -1;
	}
	return 0;
}

void free_rdata_a(dns_rdata_t *rdata) {
    // Nothing to do
}

void print_rdata_a(dns_rdata_t *rdata) {
	char ip_as_str[INET_ADDRSTRLEN];
	const char *ip_addr = utils_in_addr_to_str(ip_as_str, sizeof(ip_as_str), (struct in_addr *)rdata->a.address);
	LOG_PRINTF("%s\n", ip_addr);
}

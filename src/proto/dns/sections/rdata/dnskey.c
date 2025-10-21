#include "dnskey.h"

#include "compat/network_compat.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/sections/rdata.h"
#include "proto/dns/arrays.h"
#include "reader.h"

#include <stdlib.h>

char *read_public_key(buffer_t *from_buffer, int *error, size_t size) {
	return read_bytes_and_base64(from_buffer, error, size);
}

int parse_rdata_dnskey(dns_rdata_t *rdata, buffer_t *buffer) {
	rdata->dnskey.flags = buffer_read_uint16(buffer);
	rdata->dnskey.protocol = buffer_read_uint8(buffer);
	rdata->dnskey.algorithm = buffer_read_uint8(buffer);

	// TODO(jweyrich): Figure out sizes depending on algorithm
	size_t public_key_size = 64;
	int read_error = 0;
	rdata->dnskey.public_key = read_public_key(buffer, &read_error, public_key_size);
	if (read_error != 0) {
		LOG_WARN("error while reading DNSKEY public key: %d", read_error);
		return -1;
	}
	if (buffer_has_error(buffer)) {
		LOG_WARN("detected an error in the buffer while reading RR of type DNSKEY");
		return -1;
	}

	rdata->dnskey.flags = ntohs(rdata->dnskey.flags);
	return 0;
}

void free_rdata_dnskey(dns_rdata_t *rdata) {
    free(rdata->dnskey.public_key);
}

void print_rdata_dnskey(dns_rdata_t *rdata) {
	LOG_PRINTF("%s %s %s %u %s\n",
		// If bit 15 has value 1, then the DNSKEY record holds a
		// key intended for use as a secure entry point
		(rdata->dnskey.flags & 0x8000) ? "SEP" : "",
		// If bit 7 has value 1, then the DNSKEY record holds a DNS zone key
		// If bit 7 has value 0, then the DNSKEY record holds some other type of
		// DNS public key and MUST NOT be used to verify RRSIGs that cover RRsets.
		(rdata->dnskey.flags & 0x0100) ? "ZONE" : "",
		totext(DNSSEC_ARRAY_ALGORITHM, rdata->dnskey.algorithm),
		rdata->dnskey.flags,
		rdata->dnskey.public_key
	);
}

#include "rrsig.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rdata.h"
#include "proto/dns/arrays.h"
#include "reader.h"
#include <stdlib.h>
#include <netinet/in.h> // for ntohs and ntohl
#include <time.h> // for gmtime_r + strftime

char *read_signature(buffer_t *from_buffer, int *error, size_t size) {
	return read_bytes_and_base64(from_buffer, error, size);
}

int parse_rdata_rrsig(dns_rdata_t *rdata, buffer_t *buffer) {
	rdata->rrsig.typec = buffer_read_uint16(buffer);
	rdata->rrsig.algnum = buffer_read_uint8(buffer);
	rdata->rrsig.labels = buffer_read_uint8(buffer);
	rdata->rrsig.original_ttl = buffer_read_uint32(buffer);
	rdata->rrsig.signature_expiration = buffer_read_uint32(buffer);
	rdata->rrsig.signature_inception = buffer_read_uint32(buffer);
	rdata->rrsig.key_tag = buffer_read_uint16(buffer);
	if (buffer_has_error(buffer)) {
		LOG_WARN("detected an error in the buffer while reading RR of type RRSIG");
		return -1;
	}
	rdata->rrsig.signer_name = parse_name(buffer);
	if (rdata->rrsig.signer_name == NULL) {
		LOG_WARN("RRSIG signer name is NULL");
		return -1;
	}

	// TODO(jweyrich): Figure out sizes depending on algorithm
	size_t signature_size = 64;
	int read_error = 0;
	rdata->rrsig.signature = read_signature(buffer, &read_error, signature_size);
	if (read_error != 0) {
		LOG_WARN("error while reading RRSIG signature: %d", read_error);
		return -1;
	}
	if (buffer_has_error(buffer)) {
		LOG_WARN("detected an error in the buffer while reading RR of type RRSIG");
		return -1;
	}

	rdata->rrsig.typec = ntohs(rdata->rrsig.typec);
	rdata->rrsig.original_ttl = ntohl(rdata->rrsig.original_ttl);
	rdata->rrsig.signature_expiration = ntohl(rdata->rrsig.signature_expiration);
	rdata->rrsig.signature_inception = ntohl(rdata->rrsig.signature_inception);
	rdata->rrsig.key_tag = ntohs(rdata->rrsig.key_tag);
	return 0;
}

void free_rdata_rrsig(dns_rdata_t *rdata) {
    free(rdata->rrsig.signer_name);
	free(rdata->rrsig.signature);
}

static char *parse_timestamp(char *out, size_t out_size, time_t in) {
	struct tm tm;
	gmtime_r(&in, &tm);
	strftime(out, out_size, "%Y%m%d%H%M%S", &tm); // YYYYMMDDHHmmSS
	return out;
}

void print_rdata_rrsig(dns_rdata_t *rdata) {
	char sig_expiration[15];
	char sig_inception[15];
	LOG_PRINTF("%s %s %u %u %s %s %u %s %s\n",
		totext(DNS_ARRAY_QTYPE, rdata->rrsig.typec),
		totext(DNSSEC_ARRAY_ALGORITHM, rdata->rrsig.algnum),
		rdata->rrsig.labels,
		rdata->rrsig.original_ttl,
		parse_timestamp(sig_expiration, sizeof(sig_expiration), rdata->rrsig.signature_expiration),
		parse_timestamp(sig_inception, sizeof(sig_inception), rdata->rrsig.signature_inception),
		rdata->rrsig.key_tag,
		rdata->rrsig.signer_name,
		rdata->rrsig.signature
	);
}

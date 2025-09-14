#include "rrsig.h"
#include "log.h"
#include "types/buffer.h"
#include "proto/dns/name.h"
#include "proto/dns/sections/rr.h"
#include "proto/dns/arrays.h"
#include "base64.h"
#include <stdlib.h> // for malloc
#include <string.h> // for strlen
#include <netinet/in.h> // for ntohs and ntohl
#include <time.h> // for gmtime_r + strftime

static char *parse_signature(buffer_t *buffer) {
	//pd3IpdiZHH7ig7szxDcWSKtkmpK52w7hcCJs/6TL74AH2Wyd4N4pAYbpRuNSuuPHwH+fT8P9f+TqKTeTa2DSzD1bumgICnHhOi9yO0pAYdsyThFdiiJtg8vPMyyMagxhJkurienCAVA4nqF40cMwJgAfHS+Vc+EQSlbDVFjmI5s=
	//M+5jGt0Xd5+fnvfyCNG7v7quzJ6p5sABjWVz0L/kUyN0erX4eNzpzFiofiRFnYkwAaibP+GcW/kB/ibots9e4sPhHvPWZs/01kgVgust9VN7nOiPON8dMkCJPPOrsz1SfcDqBj3ES5wNT/C2bTle4QOgv9z9XKdcNtlyeWmBW0h9Co+SMutYHpHoiBCKhcgI
	// TODO(jweyrich): What's the real size? 128 or 144? Is it constant?
	const size_t input_size = 128; // RSA/SHA-1
	uint8_t signature[input_size];
	int read = buffer_read(buffer, signature, input_size);
	if (read == 0)
		return NULL;
	// Base64
	const size_t encoded_size = base64_encoded_size(input_size);
	char *encoded = malloc(encoded_size + 1);
	if (encoded == NULL)
		return NULL;
	base64_encode(encoded, encoded_size, signature, input_size);
	LOG_DEBUG("input_size = %zu, encoded_size = %zu, result_size = %zu\n", input_size, encoded_size, strlen(encoded));
	return encoded;
}

int parse_rdata_rrsig(dns_rr_t *rr, buffer_t *buffer) {
	rr->rdata.rrsig.typec = buffer_read_uint16(buffer);
	rr->rdata.rrsig.algnum = buffer_read_uint8(buffer);
	rr->rdata.rrsig.labels = buffer_read_uint8(buffer);
	rr->rdata.rrsig.original_ttl = buffer_read_uint32(buffer);
	rr->rdata.rrsig.signature_expiration = buffer_read_uint32(buffer);
	rr->rdata.rrsig.signature_inception = buffer_read_uint32(buffer);
	rr->rdata.rrsig.key_tag = buffer_read_uint16(buffer);
	if (buffer_has_error(buffer)) {
		LOG_WARN("detected an error in the buffer while reading RR of type RRSIG");
		return -1;
	}
	rr->rdata.rrsig.signer_name = parse_name(buffer);
	if (rr->rdata.rrsig.signer_name == NULL) {
		LOG_WARN("RRSIG signer name is NULL");
		return -1;
	}
	// FIXME(jweyrich): parse_signature is not working properly.
	// rr->rdata.rrsig.signature = parse_signature(buffer);
	// if (rr->rdata.rrsig.signature == NULL) {
	// 	LOG_WARN("RRSIG signature is NULL");
	// 	return -1;
	// }
	rr->rdata.rrsig.typec = ntohs(rr->rdata.rrsig.typec);
	rr->rdata.rrsig.original_ttl = ntohl(rr->rdata.rrsig.original_ttl);
	rr->rdata.rrsig.signature_expiration = ntohl(rr->rdata.rrsig.signature_expiration);
	rr->rdata.rrsig.signature_inception = ntohl(rr->rdata.rrsig.signature_inception);
	rr->rdata.rrsig.key_tag = ntohs(rr->rdata.rrsig.key_tag);
	return 0;
}

void free_rdata_rrsig(dns_rr_t *rr) {
    free(rr->rdata.rrsig.signer_name);
	free(rr->rdata.rrsig.signature);
}

static char *parse_timestamp(char *out, size_t out_size, time_t in) {
	struct tm tm;
	gmtime_r(&in, &tm);
	strftime(out, out_size, "%Y%m%d%H%M%S", &tm); // YYYYMMDDHHmmSS
	return out;
}

void print_rdata_rrsig(dns_rr_t *rr) {
	char sig_expiration[15];
	char sig_inception[15];
	LOG_PRINTF("%s %s %u %u %s %s %u %s %s\n",
		totext(DNS_ARRAY_QTYPE, rr->rdata.rrsig.typec),
		totext(DNSSEC_ARRAY_ALGORITHM, rr->rdata.rrsig.algnum),
		rr->rdata.rrsig.labels,
		rr->rdata.rrsig.original_ttl,
		parse_timestamp(sig_expiration, sizeof(sig_expiration), rr->rdata.rrsig.signature_expiration),
		parse_timestamp(sig_inception, sizeof(sig_inception), rr->rdata.rrsig.signature_inception),
		rr->rdata.rrsig.key_tag,
		rr->rdata.rrsig.signer_name,
		rr->rdata.rrsig.signature
	);
}

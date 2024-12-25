#include "rrsig.h"
#include "base64.h"
#include "log.h"
#include "types/buffer.h"
#include <stdlib.h>
#include <string.h>

char *parse_rrsig_signature(buffer_t *buffer) {
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

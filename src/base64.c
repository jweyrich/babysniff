#include "base64.h"
#include <inttypes.h>
#include <string.h>

size_t base64_encoded_size(size_t input_size) {
	const size_t code_size = (input_size * 4) / 3;
	const size_t padding_size = input_size % 3
		? 3 - (input_size % 3)
		: 0;
	return code_size + padding_size + 1;
}

int base64_encode(char *result, size_t resultSize, const void *input, size_t inputSize) {
	static const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const uint8_t *data = (const uint8_t *)input;
	size_t resultIndex = 0;

	// Increment over the length of the string, three characters at a time
	for (size_t x = 0; x < inputSize; x += 3) {
		// these three 8-bit (ASCII) characters become one 24-bit number
		uint32_t n = data[x] << 16;

		if ((x+1) < inputSize)
			n += data[x+1] << 8;

		if ((x+2) < inputSize)
			n += data[x+2];

		// This 24-bit number gets separated into four 6-bit numbers
		uint8_t n0 = (uint8_t)(n >> 18) & 63;
		uint8_t n1 = (uint8_t)(n >> 12) & 63;
		uint8_t n2 = (uint8_t)(n >> 6) & 63;
		uint8_t n3 = (uint8_t)n & 63;

		/*
		* if we have one byte available, then its encoding is spread
		* out over two characters
		*/
		if (resultIndex >= resultSize)
			return 0; // failure: buffer too small
		result[resultIndex++] = base64chars[n0];
		if (resultIndex >= resultSize)
			return 0; // failure: buffer too smal
		result[resultIndex++] = base64chars[n1];

		/*
		* if we have only two bytes available, then their encoding is
		* spread out over three chars
		*/
		if ((x+1) < inputSize) {
			if (resultIndex >= resultSize)
				return 0; // failure: buffer too small
			result[resultIndex++] = base64chars[n2];
		}

		/*
		* if we have all three bytes available, then their encoding is spread
		* out over four characters
		*/
		if ((x+2) < inputSize) {
			if (resultIndex >= resultSize)
				return 0; // failure: buffer too small
			result[resultIndex++] = base64chars[n3];
		}
	}

	/*
	* create and add padding that is required if we did not have a multiple of 3
	* number of characters available
	*/
	int padCount = inputSize % 3;
	if (padCount > 0) {
		for (; padCount < 3; padCount++) {
			if (resultIndex >= resultSize)
				return 0; // failure: buffer too small
			result[resultIndex++] = '=';
		}
	}
	if (resultIndex >= resultSize)
		return 0; // failure: buffer too small
	result[resultIndex] = 0;
	return 1; // success
}

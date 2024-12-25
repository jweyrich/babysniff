#include "header.h"
#include "log.h"
#include "proto/dns/arrays.h"
#include "proto/dns/dns.h"
#include "types/buffer.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

dns_hdr_t *parse_header(buffer_t *buffer) {
	dns_hdr_t *header = malloc(sizeof(dns_hdr_t));
	if (header == NULL)
		return NULL;
	memset(header, 0, sizeof(dns_hdr_t));
	{
		header->id = buffer_read_uint16(buffer);
		header->flags.single = buffer_read_uint16(buffer);
		header->qd_c = buffer_read_uint16(buffer);
		header->an_c = buffer_read_uint16(buffer);
		header->ns_c = buffer_read_uint16(buffer);
		header->ar_c = buffer_read_uint16(buffer);
		if (buffer_has_error(buffer))
			goto error;
		header->id = ntohs(header->id);
		header->flags.single = ntohs(header->flags.single);
		header->an_c = ntohs(header->an_c);
		header->qd_c = ntohs(header->qd_c);
		header->ns_c = ntohs(header->ns_c);
		header->ar_c = ntohs(header->ar_c);
	}
	return header;
error:
	LOG_WARN("Invalid header");
	free_header(header);
	return NULL;
}

void free_header(dns_hdr_t *header) {
	if (header == NULL)
		return;
	free(header);
}

void print_header(dns_hdr_t *header) {
	LOG_PRINTF_INDENT(2, "opcode: %s, status: %s, id: %u\n",
		totext(DNS_ARRAY_OPCODE, header->flags.expanded.opcode),
		totext(DNS_ARRAY_RCODE, header->flags.expanded.rcode),
		header->id);
	LOG_PRINTF_INDENT(2, "flags: %#x [%s]\n",
		header->flags.single,
		flags_totext(&header->flags.expanded));
	LOG_PRINTF_INDENT(2, "query: %u, answer: %u, authority: %u, additional: %u\n",
		header->qd_c,
		header->an_c,
		header->ns_c,
		header->ar_c);
}

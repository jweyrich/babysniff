#include "config.h"
#include "dump.h"
#include "log.h"
#include "proto_ops.h"
#include "proto/dns/dns.h"
#include "proto/dns/header.h"
#include "proto/dns/sections/question.h"
#include "proto/dns/sections/rr.h"
#include "types/buffer.h"

int sniff_dns_fromwire(const uint8_t *packet, size_t length, const config_t *config) {
	int result = 0;
	buffer_t buffer = BUFFER_INITIALIZER;
	buffer_set_data(&buffer, (uint8_t *)packet, length);

	if (config->display_filters_flag.dns) {
		LOG_PRINTF("-- DNS (%u bytes)\n", buffer_size(&buffer));
	}

	dns_hdr_t *header = parse_header(&buffer);
	if (header == NULL) {
		result = -1;
	} else {
		if (config->display_filters_flag.dns) {
			print_header(header);
		}
	}

	if (config->display_filters_flag.dns) {
		LOG_PRINTF_INDENT(2, "QUESTION SECTION:\n");
		for (uint16_t i=0; result == 0 && i < header->qd_c; i++) {
			dns_question_t *section = parse_question(&buffer);
			if (section == NULL) { result = -1; }
			else { print_question(section); free_question(section); }
		}
		LOG_PRINTF_INDENT(2, "ANSWER SECTION:\n");
		for (uint16_t i=0; result == 0 && i < header->an_c; i++) {
			dns_rr_t *section = parse_rr(&buffer);
			if (section == NULL) { result = -1; }
			else { print_rr(section); free_rr(section); }
		}
		LOG_PRINTF_INDENT(2, "AUTHORITY SECTION:\n");
		for (uint16_t i=0; result == 0 && i < header->ns_c; i++) {
			dns_rr_t *section = parse_rr(&buffer);
			if (section == NULL) { result = -1; }
			else { print_rr(section); free_rr(section); }
		}
		LOG_PRINTF_INDENT(2, "ADDITIONAL SECTION:\n");
		for (uint16_t i=0; result == 0 && i < header->ar_c; i++) {
			dns_rr_t *section = parse_rr(&buffer);
			if (section == NULL) { result = -1; }
			else { print_rr(section); free_rr(section); }
		}
	}

	free_header(header);

//	packet = (uint8_t *)PTR_ADD(packet, DNS_HDR_LEN);
//	length -= DNS_HDR_LEN;
	if (config->display_filters_flag.dns_data) {
		LOG_PRINTF("showing %lu bytes:\n", length);
		dump_hex(stdout, packet, length, 0);
	}
//	if (result == 0) {
//		packet = buffer_data_ptr(&buffer);
//		length = buffer_left(&buffer);
//		dump_hex(packet, length, 0);
//	}

	return result;
}

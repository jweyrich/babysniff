#include "question.h"
#include "log.h"
#include "proto/dns/arrays.h"
#include "proto/dns/dns.h"
#include "proto/dns/name.h"
#include "types/buffer.h"
#include <stdlib.h>
#include <string.h>

dns_question_t *parse_question(buffer_t *buffer) {
	dns_question_t *question = malloc(sizeof(dns_question_t));
	if (question == NULL)
		return NULL;
	memset(question, 0, sizeof(dns_question_t));
	{
		question->name = parse_name(buffer);
		if (question->name == NULL)
			goto error;
		question->qtype = buffer_read_uint16(buffer);
		question->qclass = buffer_read_uint16(buffer);
		if (buffer_has_error(buffer))
			goto error;
		question->qtype = ntohs(question->qtype);
		question->qclass = ntohs(question->qclass);
	}
	return question;
error:
	LOG_WARN("Invalid question");
	free_question(question);
	return NULL;
}

void free_question(dns_question_t *question) {
	if (question == NULL)
		return;
	free_name(question->name);
	free(question);
}

void print_question(dns_question_t *question) {
	LOG_PRINTF_INDENT(4, "%s\t\t\t%s\t%s\n",
		question->name,
		totext(DNS_ARRAY_QCLASS, question->qclass),
		totext(DNS_ARRAY_QTYPE, question->qtype));
}

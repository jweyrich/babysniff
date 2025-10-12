#include "channel_ops.h"
#include "system.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef OS_WINDOWS
#	include <winsock2.h>
#else
#	include <errno.h>
#	include <fcntl.h>
#	include <sys/ioctl.h>
#endif

#include "bpf/bpf_filter.h"
#include "bpf/bpf_vm.h"
#include "bpf/bpf_types.h"

int sniff_channel_set_error_msg(channel_t *channel, const char *format, ...) {
	int ret;
	va_list ap;
	va_start(ap, format);
	ret = vsnprintf(channel->errmsg, SNIFF_ERR_BUFSIZE, format, ap);
	va_end(ap);
	return ret;
}

const char *sniff_channel_get_error_msg(channel_t *channel) {
	return channel->errmsg;
}

// BPF filter functions
int sniff_channel_set_bpf_filter(channel_t *channel, bpf_mode_t bpf_mode, const char *filter_expression) {
	if (!channel) {
		return -1;
	}

	if (!filter_expression) {
		sniff_channel_set_error_msg(channel, "Filter expression is NULL");
		return -1;
	}

	// Clear any existing filter
	sniff_channel_clear_bpf_filter(channel);

	// Allocate new filter
	channel->bpf_filter = malloc(sizeof(channel_bpf_filter_t));
	if (!channel->bpf_filter) {
		sniff_channel_set_error_msg(channel, "Failed to allocate memory for BPF filter");
		return -1;
	}
	memset(channel->bpf_filter, 0, sizeof(channel_bpf_filter_t));

	// Compile the new filter
	if (bpf_compile_filter(filter_expression, &channel->bpf_filter->program) < 0) {
		sniff_channel_set_error_msg(channel, "Failed to compile BPF filter: %s", filter_expression);
		return -1;
	}

	channel->bpf_filter->mode = bpf_mode;
	return 0;
}

void sniff_channel_clear_bpf_filter(channel_t *channel) {
	if (!channel || !channel->bpf_filter) {
		return;
	}
	bpf_free_program(&channel->bpf_filter->program);
	channel->bpf_filter = NULL;
}

int sniff_channel_apply_bpf_filter(channel_t *channel, const uint8_t *packet, uint32_t packet_len) {
	if (!channel || !packet) {
		return 0; // Reject invalid input
	}

	if (!channel->bpf_filter) {
		return 1; // Accept all packets if no filter is set
	}

	if (channel->bpf_filter->mode == NATIVE_BPF) {
		// Native BPF filtering is done in the kernel, so we accept all packets here
		return 1;
	}

	return bpf_execute_filter(&channel->bpf_filter->program, packet, packet_len);
}

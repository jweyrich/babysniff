#include "channel_ops.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/ioctl.h>

int sniff_setnonblock(channel_t *channel, int nonblock) {
#ifdef WIN32
	unsigned long nonblocking = nonblock;
	ioctlsocket(channel->fd, FIONBIO, &nonblocking);
#else
	long flags;
	if ((flags = fcntl(channel->fd, F_GETFL)) < 0) {
		sniff_channel_set_error_msg(channel, "fcntl(F_GETFL): %s", sniff_strerror(errno));
		return -1;
	}
	if (nonblock)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;
	if (fcntl(channel->fd, F_SETFL, flags) == -1) {
		sniff_channel_set_error_msg(channel, "fcntl(F_SETFL): %s", sniff_strerror(errno));
		return -1;
	}
#endif
	return 0;
}

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
int sniff_channel_set_bpf_filter(channel_t *channel, const char *filter_expression) {
	if (!channel || !filter_expression) {
		return -1;
	}

	// Clear any existing filter
	sniff_channel_clear_bpf_filter(channel);

	// Compile the new filter
	if (bpf_compile_filter(filter_expression, &channel->bpf_filter) < 0) {
		sniff_channel_set_error_msg(channel, "Failed to compile BPF filter: %s", filter_expression);
		return -1;
	}

	channel->has_bpf_filter = true;
	return 0;
}

void sniff_channel_clear_bpf_filter(channel_t *channel) {
	if (channel && channel->has_bpf_filter) {
		bpf_free_program(&channel->bpf_filter);
		channel->has_bpf_filter = false;
	}
}

int sniff_channel_apply_bpf_filter(channel_t *channel, const uint8_t *packet, uint32_t packet_len) {
	if (!channel || !packet) {
		return 0; // Reject invalid input
	}

	if (!channel->has_bpf_filter) {
		return 1; // Accept all packets if no filter is set
	}

	return bpf_execute_filter(&channel->bpf_filter, packet, packet_len);
}

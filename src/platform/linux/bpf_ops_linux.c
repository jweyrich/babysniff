#ifndef _GNU_SOURCE
#	define _GNU_SOURCE
#endif
#include <stdio.h>
#include <errno.h>
#include <linux/filter.h>
#include <net/if.h>
#include "../../channel.h"
#include "../../channel_ops.h"

int linux_bpf_attach_filter(channel_t *channel) {
	const void *program = &channel->bpf_filter->program;
	const size_t program_size = sizeof(channel->bpf_filter->program);

	// TODO(jweyrich): We should drain packets that arrived before the filter was set! See https://natanyellin.com/posts/ebpf-filtering-done-right/
	if (setsockopt(channel->fd, SOL_SOCKET, SO_ATTACH_FILTER, program, program_size) == -1) {
		snprintf(channel->errmsg, SNIFF_ERR_BUFSIZE, "setsockopt(SO_ATTACH_FILTER): %s", sniff_strerror(errno));
		return -1;
	}
	return 0;
}

int sniff_channel_attach_filter(channel_t *channel) {
	if (!channel || !channel->bpf_filter) {
		sniff_channel_set_error_msg(channel, "No BPF filter set on channel");
		return -1;
	}

	switch (channel->bpf_filter->mode) {
		case NATIVE_BPF:
			return linux_bpf_attach_filter(channel);
		case EMULATED_BPF:
			// Nothing to do for emulated BPF
			return 0;
		default:
			sniff_channel_set_error_msg(channel, "Unknown BPF mode");
			return -1;
	}
}

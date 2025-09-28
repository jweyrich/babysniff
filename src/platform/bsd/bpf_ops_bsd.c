#ifndef _GNU_SOURCE
#	define _GNU_SOURCE
#endif
#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <errno.h>
#include "../../channel.h"
#include "../../channel_ops.h"

int bsd_bpf_attach_filter(channel_t *channel) {
	// TODO(jweyrich): Drain packets that arrived before the filter was set! See https://natanyellin.com/posts/ebpf-filtering-done-right/
	if (ioctl(bpf_fd, BIOCSETF, &channel->bpf_filter->program) < 0) {
		snprintf(channel->errmsg, SNIFF_ERR_BUFSIZE, "BIOCSETF: %s", sniff_strerror(errno));
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
			return bsd_bpf_attach_filter(channel);
		case EMULATED_BPF:
			// Nothing to do for emulated BPF
			return 0;
		default:
			sniff_channel_set_error_msg(channel, "Unknown BPF mode");
			return -1;
	}
}

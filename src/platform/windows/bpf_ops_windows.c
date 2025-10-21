#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#	define NOMINMAX
#endif

#include <winsock2.h>
#include <stdio.h>
#include <sys/types.h>
#include "channel.h"
#include "channel_ops.h"

int windows_bpf_attach_filter(channel_t *channel) {
	// Windows doesn't support native BPF filtering through socket options like Linux
	// SO_ATTACH_FILTER is not available on Windows Winsock2
	// All BPF filtering on Windows must be done through emulated BPF in user space

	// TODO(jweyrich): We should drain packets that arrived before the filter was set! See https://natanyellin.com/posts/ebpf-filtering-done-right/

	// On Windows, native BPF is not supported, so we cannot attach a filter to the socket
	// The filtering will be done in user space using the emulated BPF implementation
	sniff_channel_set_error_msg(channel, "Native BPF filtering is not supported on Windows. Use emulated BPF instead.");
	return -1;
}

int sniff_channel_attach_filter(channel_t *channel) {
	if (!channel || !channel->bpf_filter) {
		sniff_channel_set_error_msg(channel, "No BPF filter set on channel");
		return -1;
	}

	switch (channel->bpf_filter->mode) {
		case NATIVE_BPF:
			return windows_bpf_attach_filter(channel);
		case EMULATED_BPF:
			// Nothing to do for emulated BPF
			return 0;
		default:
			sniff_channel_set_error_msg(channel, "Unknown BPF mode");
			return -1;
	}
}

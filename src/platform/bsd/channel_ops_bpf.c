#include "channel_ops.h"
#include "proto_ops.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/bpf.h>
#include <time.h>
#include "log.h"
#include "macros.h"
#include "config.h"

// TODO(jweyrich): parse options
// http://bpf.4.man.smakd.potaroo.net
// http://fuse4bsd.creo.hu/localcgi/man-cgi.cgi?bpf+4
// http://docs.google.com/viewer?a=v&q=cache:GcRvf_ssap4J:www.seccuris.com/documents/whitepapers/20070517-devsummit-zerocopybpf.pdf+zero-copy+BPF&hl=en&sig=AHIEtbQNRzBZinc7zNhdzMfNxWYJfNxgOw&pli=1
// http://www.tcpdump.org

// TODO(jweyrich): Write bpf_set_timeout
//to.tv_sec = 1;
//to.tv_usec = 0;
//if (ioctl(fd, BIOCSRTIMEOUT, &to) == -1) {
//	perror("BIOCSRTIMEOUT");
//	exit(-1);
//}

static int bpf_ensure_version(channel_t *channel) {
	struct bpf_version bpfv;
	if (ioctl(channel->fd, BIOCVERSION, &bpfv) < 0) {
		sniff_channel_set_error_msg(channel, "ioctl(BIOCVERSION): %s", sniff_strerror(errno));
		return -1;
	}
	if (bpfv.bv_major != BPF_MAJOR_VERSION || bpfv.bv_minor < BPF_MINOR_VERSION)
		return -1;
	return 0;
}

static int bpf_set_interface(channel_t *channel, const char *ifname, uint16_t protocol) {
	struct ifreq ifr;
	UNUSED(protocol);

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(channel->fd, BIOCSETIF, &ifr) < 0) {
		sniff_channel_set_error_msg(channel, "ioctl(BIOCSETIF): %s", sniff_strerror(errno));
		return -1;
	}

	free(channel->ifname);
	channel->ifname = strdup(ifname);
	if (channel->ifname == NULL)
		return -1;

	return 0;
}

static int bpf_set_immediate(channel_t *channel, int on) {
	// IO operations must return even if the buffer is not full
	int value = on == 0 ? 0 : 1;
	if (ioctl(channel->fd, BIOCIMMEDIATE, &value) < 0) {
		sniff_channel_set_error_msg(channel, "ioctl(BIOCIMMEDIATE): %s", sniff_strerror(errno));
		return -1;
	}
	return 0;
}

static int bpf_set_promisc(channel_t *channel, const char *ifname, int on) {
	int value = on == 0 ? 0 : 1;
	if (ioctl(channel->fd, BIOCPROMISC, &value) < 0) {
		sniff_channel_set_error_msg(channel, "ioctl(BIOCPROMISC): %s", sniff_strerror(errno));
		return -1;
	}
	channel->opts.promisc = value;
	return 0;
}

static int bpf_set_nonblock(channel_t *channel, int on) {
	int value = on == 0 ? 0 : 1;
	if (ioctl(channel->fd, FIONBIO, &value) < 0) {
		sniff_channel_set_error_msg(channel, "ioctl(FIONBIO): %s", sniff_strerror(errno));
		return -1;
	}
	return 0;
}

static int bpf_set_buffersize(channel_t *channel, size_t size) {
	if (size < BPF_MINBUFSIZE || size > BPF_MAXBUFSIZE)
		size = 0;
	if (size == 0) {
		if (ioctl(channel->fd, BIOCGBLEN, &channel->buffer_size) < 0) {
			sniff_channel_set_error_msg(channel, "ioctl(BIOCGBLEN): %s", sniff_strerror(errno));
			channel->buffer_size = SNIFF_DEFAULT_BUFSIZE;
		}
	} else {
		channel->buffer_size = size;
		uint test = size;
		if (ioctl(channel->fd, BIOCSBLEN, (caddr_t)&test) < 0) {
			sniff_channel_set_error_msg(channel, "ioctl(BIOCSBLEN): %s", sniff_strerror(errno));
			return -1;
		}
	}
	// TODO(jweyrich): better to use realloc?
	free(channel->buffer);
	channel->buffer = calloc(channel->buffer_size, sizeof(uint8_t));
	if (channel->buffer == NULL) {
		sniff_channel_set_error_msg(channel, "calloc(): %s", sniff_strerror(errno));
		return -1;
	}
	return 0;
}

channel_t *sniff_open(const char *ifname, int promisc, size_t buffer_size) {
	char device[20];
	int bpfn = 0;
	channel_t *channel;

	channel = sniff_alloc_channel();
	if (channel == NULL)
		return NULL;

	do {
		snprintf(device, sizeof(device), "/dev/bpf%d", bpfn++);
		channel->fd = open(device, O_RDWR);
		if (channel->fd == -1 && errno == EACCES)
			channel->fd = open(device, O_RDONLY);
	} while (channel->fd < 0 && errno == EBUSY);

	if (channel->fd < 0) {
		sniff_channel_set_error_msg(channel, "No devices found: %s", sniff_strerror(errno));
		goto error;
	}

	if (bpf_ensure_version(channel) < 0)
		goto error;

	if (bpf_set_interface(channel, ifname, 0) < 0)
		goto error;

	// Keep going if it fails
	bpf_set_buffersize(channel, buffer_size);

	if (bpf_set_immediate(channel, 1) < 0)
		goto error;

	// Keep going if it fails
	bpf_set_promisc(channel, ifname, promisc);

	return channel;

error:
	LOG_ERROR("%s", channel->errmsg);
	sniff_free_channel(channel);
	return NULL;
}

void sniff_close(channel_t *channel) {
//	if (ioctl(BpfFd, SIOCDELMULTI, (caddr_t)&ifr) < 0)
//		bpf_set_promisc(channel, 0);
//	}
	sniff_free_channel(channel);
}

int sniff_readloop(channel_t *channel, long timeout, const config_t *config) {
	uint8_t *begin, *end, *current;
	struct bpf_hdr *header;
	ssize_t bytes_read;
	time_t time_start, time_elapsed;

	time_start = time(NULL);

	while (1) {
		bytes_read = read(channel->fd, channel->buffer, channel->buffer_size);
		if (bytes_read < 0) {
			if (errno != EAGAIN)
				fprintf(stderr, "errno = %d\n", errno);
		} else if (bytes_read > 0) {
			//printf("bytes_read = %lu\n", bytes_read);
			begin = channel->buffer;
			end = channel->buffer + bytes_read;

			// loop through each snapshot in the chunk
			while (begin < end) {
				header = (struct bpf_hdr *)begin;
				current = begin + header->bh_hdrlen;
				sniff_packet_fromwire(current, header->bh_caplen, 0, config);
				begin += BPF_WORDALIGN(header->bh_caplen + header->bh_hdrlen);
			}
		}
		time_elapsed = time(NULL) - time_start;
		if (time_elapsed >= timeout) {
			//printf("expired @ %lus\n", time_elapsed);
			return 0;
		}
		usleep(50000);
	}
	//printf("error = %s\n", sniff_strerror(errno));
	return -1;
}

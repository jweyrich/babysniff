#include "channel_ops.h"
#include "proto_ops.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>
//#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
//#include <netinet/in_systm.h>
//#include <netinet/if_ether.h>
//#include <arpa/inet.h>
//#include <net/ethernet.h>
//#include <netinet/in_systm.h>
//#include <netinet/in.h>
//#include <netinet/ip.h>
//#include <netinet/tcp.h>
//#include <netinet/udp.h>
//#include <netinet/ip_icmp.h>
#include <time.h>
#include <unistd.h>
#include "log.h"
#include "types.h"
#include "config.h"

static int linux_ensure_version(channel_t *channel) {
	return 0;
}

static int linux_set_interface(channel_t *channel, const char *ifname, uint16_t protocol) {
	struct sockaddr_ll sll;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(channel->fd, SIOCGIFINDEX, &ifr) == -1) {
		snprintf(channel->errmsg, SNIFF_ERR_BUFSIZE, "ioctl(BIOCSETIF): %s",
			sniff_strerror(errno));
		return -1;
	}

	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = protocol; // must already be network short
	if (bind(channel->fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
		snprintf(channel->errmsg, SNIFF_ERR_BUFSIZE, "bind(): %s",
			sniff_strerror(errno));
		return -1;
	}

	if (channel->ifname != NULL)
		free(channel->ifname);
	channel->ifname = strdup(ifname);
	if (channel->ifname == NULL)
		return -1;

	return 0;
}

static int linux_set_immediate(channel_t *channel, int on) {
	return 0;
}

static int linux_set_promisc(channel_t *channel, const char *ifname, int on) {
	int value = on == 0 ? 0 : 1;
	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(channel->fd, SIOCGIFFLAGS, &ifr) == -1) {
		snprintf(channel->errmsg, SNIFF_ERR_BUFSIZE, "ioctl(SIOCGIFFLAGS): %s",
			sniff_strerror(errno));
		return -1;
	}
	if (value)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~IFF_PROMISC;
	if (ioctl(channel->fd, SIOCSIFFLAGS, &ifr) == -1) {
		snprintf(channel->errmsg, SNIFF_ERR_BUFSIZE, "ioctl(SIOCSIFFLAGS): %s",
			sniff_strerror(errno));
		return -1;
	}
	channel->opts.promisc = value;
	return 0;
}

static int linux_set_nonblock(channel_t *channel, int on) {
	return sniff_setnonblock(channel, on);
}

static int linux_set_buffersize(channel_t *channel, size_t size) {
	// TODO(jweyrich): rewrite this
	if (size == 0) {
		channel->buffer_size = SNIFF_DEFAULT_BUFSIZE;
	} else {
		channel->buffer_size = size;
	}
	// TODO(jweyrich): better use realloc?
	if (channel->buffer != NULL)
		free(channel->buffer);
	channel->buffer = calloc(channel->buffer_size, sizeof(byte));
	if (channel->buffer == NULL) {
		snprintf(channel->errmsg, SNIFF_ERR_BUFSIZE, "calloc(): %s",
			sniff_strerror(errno));
		return -1;
	}
	return 0;
}

channel_t *sniff_open(const char *ifname, int promisc, size_t buffer_size) {
	const uint16_t protocol = htons(ETH_P_ALL); // ETH_P_IP
	channel_t *channel;

	channel = sniff_alloc_channel();
	if (channel == NULL)
		return NULL;

	channel->fd = socket(PF_PACKET, SOCK_RAW, protocol);
	if (channel->fd == -1) {
		//snprintf(channel->errmsg, SNIFF_ERR_BUFSIZE, "socket(SOCK_RAW): %s",
		//	sniff_strerror(errno));
		goto error;
	}

	if (linux_ensure_version(channel) < 0)
		goto error;

	if (linux_set_interface(channel, ifname, protocol) < 0)
		goto error;

	// Keep going if it fails
	linux_set_buffersize(channel, buffer_size);

	if (linux_set_immediate(channel, 1) < 0)
		goto error;

	// Keep going if it fails
	linux_set_promisc(channel, ifname, promisc);

	return channel;

error:
	LOG_ERROR("%s", channel->errmsg);
	sniff_free_channel(channel);
	return NULL;
}

void sniff_close(channel_t *channel) {
	sniff_free_channel(channel);
}

int sniff_readloop(channel_t *channel, long timeout, const config_t *config) {
	byte *begin, *end, *current;
	struct sockaddr packet_info;
	size_t packet_info_size = sizeof(struct sockaddr_ll);
	//struct eth_hdr *header;
	ssize_t bytes_read;
	time_t time_start, time_elapsed;

	time_start = time(NULL);

	while (1) {
		bytes_read = recvfrom(channel->fd, channel->buffer, channel->buffer_size, 0,
			&packet_info, (socklen_t *)&packet_info_size);
		//bytes_read = read(channel->fd, channel->buffer, channel->buffer_size);
		if (bytes_read < 0) {
			if (errno != EAGAIN)
				fprintf(stderr, "errno = %d\n", errno);
		} else if (bytes_read > 0) {
			//printf("bytes_read = %lu\n", bytes_read);
			begin = channel->buffer;
			end = channel->buffer + bytes_read;

			// loop through each snapshot in the chunk
			while (begin < end) {
				//header = (struct eth_hdr *)begin;
				current = begin; // Point to the start of the received buffer because it's not encapsulated.
				sniff_packet_fromwire(current, bytes_read, 0, config);
				begin += bytes_read;
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

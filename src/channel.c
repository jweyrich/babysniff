#include "channel.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

channel_t *sniff_alloc_channel(void) {
	channel_t *channel = malloc(sizeof(channel_t));
	if (channel == NULL)
		return NULL;
	CHANNEL_INIT(channel);
	return channel;
}

void sniff_free_channel(channel_t *channel) {
	if (channel == NULL)
		return;

	if (channel->fd != -1)
		close(channel->fd);

	free(channel->ifname);
	free(channel->buffer);
	free(channel);
}

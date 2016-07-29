#include "channel_ops.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
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

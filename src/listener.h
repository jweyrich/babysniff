#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "arguments.h"

int listener_udp_create(cli_args_t *args) {
	struct sockaddr_in sa;
	int sock;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1)
		goto _error;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons (args->port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) != 0)
		goto _error_close;

	return sock;

_error_close:
	close(sock);
_error:
	return -1;
}

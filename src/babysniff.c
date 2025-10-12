#include "babysniff.h"

#ifndef __USE_POSIX
#	define __USE_POSIX
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arguments.h"
#include "config.h"
#include "daemon.h"
#include "security.h"
#include "signal_handler.h"
#include "stdio_utils.h"
#include "system.h"

int main(int argc, char **argv) {
	cli_args_t args;
	config_t config;

	if (parse_arguments(&args, argc, argv) < 0) {
		return EXIT_FAILURE;
	}

	if (config_initialize(&config, &args) < 0) {
		return EXIT_FAILURE;
	}

	if (!is_running_as_superuser()) {
#ifdef OS_WINDOWS
		fprintf(stderr, "Requires administrator privileges\n");
#else
		fprintf(stderr, "Requires superuser privileges\n");
#endif
		return EXIT_FAILURE;
	}

	if (args.interface_name == NULL || args.interface_name[0] == '\0') {
		fprintf(stderr, "Missing interface name argument: --interface=foo\n");
		return EXIT_FAILURE;
	}

	if (args.background)
		daemonize(&args);

	if (signal_handler_init() < 0) {
		fprintf(stderr, "Failed to initialize signal handlers\n");
		return EXIT_FAILURE;
	}

	if (args.background) {
		if (stdio_redirect_to_null() < 0) {
			fprintf(stderr, "Warning: Failed to redirect stdio to null device\n");
			// Continue anyway - this is not a fatal error for daemon mode
		}
	}

	channel_t *channel = sniff_open(args.interface_name, 0, 0);
	if (channel == NULL)
		return EXIT_FAILURE;
	
	if (sniff_setnonblock(channel, 1) < 0) {
		fprintf(stderr, "Error setting non-blocking mode: %s\n", sniff_channel_get_error_msg(channel));
		goto error;
	}

	// Set BPF filter
	// If not provided, a default is set in parse_arguments()
	if (sniff_channel_set_bpf_filter(channel, args.bpf_mode, args.bpf_filter_expr) < 0) {
		fprintf(stderr, "Error setting BPF filter: %s\n", sniff_channel_get_error_msg(channel));
		goto error;
	}

	int attach_ret = sniff_channel_attach_filter(channel);
	if (attach_ret < 0) {
		fprintf(stderr, "Failed to attach filter to channel: %s\n", sniff_channel_get_error_msg(channel));
		goto error;
	}

	printf("Applied BPF filter: %s\n", args.bpf_filter_expr);

	if (args.chrootdir != NULL) {
		if (security_force_chroot(args.chrootdir) < 0)
			goto error;
	}
	if (args.username != NULL) {
		if (security_force_uid(args.username) < 0)
			goto error;
	}

	while (!signal_handler_is_interrupted()) {
		sniff_readloop(channel, 1, &config);
	}

	signal_handler_cleanup();
	sniff_close(channel);

	printf("Terminating...\n");

	return EXIT_SUCCESS;

error:
	sniff_close(channel);

	return EXIT_FAILURE;
}

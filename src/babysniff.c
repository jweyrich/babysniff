#include "babysniff.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "arguments.h"
#include "daemon.h"
#include "security.h"
#include "config.h"
#include "log.h"

// #ifndef _GNU_SOURCE
// #define _POSIX_C_SOURCE 2 // POSIX.1, POSIX.2
// #define _SVID_SOURCE // SVID, ISO C, POSIX.1, POSIX.2, X/Open
// #define _BSD_SOURCE 1 // 4.3 BSD Unix, ISO C, POSIX.1, POSIX.2
// #endif

// #if _POSIX_C_SOURCE >= 1 || defined(_XOPEN_SOURCE) || defined(_POSIX_SOURCE)
// #define HAVE_SIGACTION // sigaction is part of POSIX.1
// #endif

// #ifndef HAVE_SIGACTION
// #error sigaction is not supported
// #endif

// sig_atomic_t is defined by C99
static volatile sig_atomic_t g_done = 0;

static void cleanup(int signal) {
	printf("Received signal %d\n", signal);
	if (signal == SIGINT)
		g_done = 1;
}

static void install_sighandlers(void) {
	struct sigaction sa;
	sa.sa_handler = &cleanup;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
}

int main(int argc, char **argv) {
	cli_args_t args;
	config_t config;

	if (parse_arguments(&args, argc, argv) < 0) {
		return EXIT_FAILURE;
	}

	if (config_initialize(&config, &args) < 0) {
		return EXIT_FAILURE;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "Requires superuser privileges\n");
		return EXIT_FAILURE;
	}

	if (args.interface_name == NULL || args.interface_name[0] == '\0') {
		fprintf(stderr, "Missing interface name argument: --interface=foo\n");
		return EXIT_FAILURE;
	}

	if (!args.foreground)
		daemonize(&args);

	install_sighandlers();

	if (!args.foreground) {
		// Redirect std{in|err|out} to /dev/null
		int nullfd = open("/dev/null", O_RDWR);
		dup2(nullfd, STDOUT_FILENO);
		dup2(nullfd, STDERR_FILENO);
		dup2(nullfd, STDIN_FILENO);
		close(nullfd);
	}

	channel_t *channel = sniff_open(args.interface_name, 0, 0);
	if (channel == NULL)
		return EXIT_FAILURE;
	if (sniff_setnonblock(channel, 1) < 0)
		return EXIT_FAILURE;

	if (args.chrootdir != NULL) {
		if (security_force_chroot(args.chrootdir) < 0)
			return EXIT_FAILURE;
	}
	if (args.username != NULL) {
		if (security_force_uid(args.username) < 0)
			return EXIT_FAILURE;
	}

	while (!g_done) {
		sniff_readloop(channel, 1, &config);
	}
	sniff_close(channel);

	printf("Terminating...\n");

	return EXIT_SUCCESS;
}

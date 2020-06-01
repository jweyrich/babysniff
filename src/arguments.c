#include "arguments.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "version.h"

void usage(const cli_args_t *args) {
	// TODO(jweyrich): Use ANSI escape sequences only when stdout is guaranteed to be a TTY.
#define BOLD(text)	"\033[1m" text "\033[0m"
#define UNDER(text)	"\033[4m" text "\033[0m"
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"  -d #, --debug=#             Set the daemon's debug level.\n"
		"                              Debugging is more verbose with a higher debug level.\n"
		"  -f, --foreground            Run the server in the foreground (do not daemonize).\n"
		"  -i, --interface             Specify which interface to inspect.\n"
		"  -t, --chrootdir="UNDER("directory")"   Chroot to "UNDER("directory")" after processing the command line arguments.\n"
		"  -u, --user="UNDER("name")"             Change the user to "UNDER("name")" after completing privileged operations, \n"
		"                              such as creating sockets that listen on privileged ports.\n"
		"  -v, --version               Output version information and exit.\n"
		"  -h, --help                  Display this help and exit.\n",
		args->exename
	);
#undef UNDER
#undef BOLD
}

void showversion() {
	fprintf(stdout, "%s %s - %s\n", PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_BUGREPORT);
}

// NOTE: Not thread-safe/reentrant!
const char *get_opt_string(const struct option *options) {
	static char buffer[128];
	int i;
	char *ptr = buffer;
	memset(buffer, 0, sizeof(buffer));
	for (i=0; options[i].name != NULL; ++i) {
		switch (options[i].has_arg) {
			case no_argument:
				*ptr++ = options[i].val;
				break;
			case required_argument:
			case optional_argument:
				*ptr++ = options[i].val;
				*ptr++ = ':';
				break;
		}
	}
	return buffer;
}

int parse_arguments(cli_args_t *args, int argc, char **argv) {
	static const struct option options[] = {
		{ "debug",		required_argument,	NULL, 'd' },
		{ "foreground",	no_argument,		NULL, 'f' },
		{ "interface",  required_argument,  NULL, 'i' },
		{ "chrootdir",	required_argument,	NULL, 't' },
		{ "username",	required_argument,	NULL, 'u' },
		{ "version",	no_argument,		NULL, 'v' },
		{ "help",		no_argument,		NULL, 'h' },
		{ NULL, no_argument, NULL, 0 }
	};
	memset(args, 0, sizeof(struct cli_args));
	args->argc = argc;
	args->argv = argv;
	args->exename = strrchr(argv[0], '/');
	args->exename = (args->exename != NULL) ? args->exename+1 : argv[0];
	while (1) {
		int opt_index = 0;
		int opt = getopt_long(argc, argv, get_opt_string(options), options, &opt_index);
		if (opt == -1)
			break;
		switch (opt) {
			case 'd': args->debuglevel = atoi(optarg); break;
			case 'f': args->foreground = true; break;
			case 'i': args->interface_name = optarg; break;
			case 't': args->chrootdir = optarg; break;
			case 'u': args->username = optarg; break;
			case 'v': showversion(); exit(EXIT_SUCCESS);
			case 'h': usage(args); exit(EXIT_SUCCESS);
			case '?': usage(args); exit(EXIT_FAILURE);
		}
	}
	return 0;
}

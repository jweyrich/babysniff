#include "arguments.h"
#include "log_level.h"
#include "version.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage(const cli_args_t *args) {
	// TODO(jweyrich): Use ANSI escape sequences only when stdout is guaranteed to be a TTY.
#define BOLD(text) "\033[1m" text "\033[0m"
#define UNDER(text) "\033[4m" text "\033[0m"
	const char *usage_format = "Usage: %s [OPTIONS] " UNDER("expression") "\n"
		"\n"
		"Arguments:\n"
		"  " UNDER("expression") "                   BPF filter expression (tcpdump-style).\n"
		"                              Examples: 'host 192.168.1.1', 'port 80', 'tcp'\n"
		"\n"
		"Options:\n"
		"  -l #, --loglevel=#          Set the daemon's log level.\n"
		"                              Debugging is more verbose with a higher debug level.\n"
		"  -b, --background            Run in background (daemonize).\n"
		"  -d, --display-filters=" UNDER("filters") " Specify a list of display filters separated by comma. Example: udp,dns\n"
		"                              The supported filters are:\n"
		"                                arp\n"
		"                                dns | dns-data\n"
		"                                eth\n"
		"                                icmp\n"
		"                                ip\n"
		"                                tcp | tcp-data\n"
		"                                udp | udp-data\n"
		"                              If not provided, protocols are auto-enabled based on BPF filter.\n"
		"  -E, --bpf-emulator          Use emulated BPF instead of the native BPF.\n"
		"  -i, --interface=" UNDER("name") "        Specify which interface to inspect.\n"
		"  -t, --chrootdir=" UNDER("directory") "   Chroot to " UNDER("directory") " after processing the command line arguments.\n"
		"  -u, --user=" UNDER("name") "             Change the user to " UNDER("name") " after completing privileged operations, \n"
		"                              such as creating sockets that listen on privileged ports.\n"
		"  -v, --version               Output version information and exit.\n"
		"  -h, --help                  Display this help and exit.\n";
	fprintf(stderr, usage_format, args->exename);
#undef UNDER
#undef BOLD
}

static void showversion(void) {
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
		{ "loglevel",			required_argument,	NULL, 'l' },
		{ "background",			no_argument,		NULL, 'b' },
		{ "display-filters",	required_argument,	NULL, 'd' },
		{ "bpf-emulator", 		no_argument,		NULL, 'E' },
		{ "interface",  		required_argument,  NULL, 'i' },
		{ "chrootdir",			required_argument,	NULL, 't' },
		{ "username",			required_argument,	NULL, 'u' },
		{ "version",			no_argument,		NULL, 'v' },
		{ "help",				no_argument,		NULL, 'h' },
		{ NULL, 				no_argument, 		NULL,  0  },
	};

	memset(args, 0, sizeof(struct cli_args));
	args->argc = argc;
	args->argv = argv;
	args->exename = strrchr(argv[0], '/');
	args->exename = (args->exename != NULL) ? args->exename+1 : argv[0];
	args->bpf_mode = NATIVE_BPF; // Default to native BPF

	while (1) {
		int opt_index = 0;
		int opt = getopt_long(argc, argv, get_opt_string(options), options, &opt_index);
		if (opt == -1)
			break;
		switch (opt) {
			case 'l':
				args->loglevel = atoi(optarg);
				log_level_set(args->loglevel);
				break;
			case 'b': args->background = true; break;
			case 'd': args->display_filters = optarg; break;
			case 'E': args->bpf_mode = EMULATED_BPF; break;
			case 'i': args->interface_name = optarg; break;
			case 't': args->chrootdir = optarg; break;
			case 'u': args->username = optarg; break;
			case 'v': showversion(); exit(EXIT_SUCCESS);
			case 'h': usage(args); exit(EXIT_SUCCESS);
			case '?': usage(args); exit(EXIT_FAILURE);
		}
	}
	
	// Check for required positional argument (BPF expression)
	if (optind >= argc) {
		fprintf(stderr, "Error: BPF filter expression is required.\n\n");
		usage(args);
		return -1;
	}
	
	// The first non-option argument is the BPF filter expression
	args->bpf_filter_expr = argv[optind];
	
	// Check for extra arguments
	if (optind + 1 < argc) {
		fprintf(stderr, "Error: Too many arguments. Only one BPF filter expression is allowed.\n\n");
		usage(args);
		return -1;
	}
	
	return 0;
}

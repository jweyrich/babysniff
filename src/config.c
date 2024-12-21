#include "config.h"
#include "arguments.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief Parse the filters flag from the command line arguments.
 * The `args->filters` member has the following format:
 *   arp,dns,dns-data,eth,icmp,ip,tcp,tcp-data,udp,upd-data
 *
 * @param config  The configuration structure
 * @param args    The command line arguments
 * @return int    0 on success, <0 on error
 */
static int config_parse_filters_flag(config_t *config, const cli_args_t *args) {
	// If no filters are provided, the default is "tcp"
	if (args->filters == NULL) {
		config->filters_flag.tcp = true;
		return 0;
	}

	if (args->filters != NULL) {
		char *token = strtok(args->filters, ",");
		while (token != NULL) {
			if (strcmp(token, "arp") == 0) {
				config->filters_flag.arp = true;
			} else if (strcmp(token, "dns") == 0) {
				config->filters_flag.dns = true;
			} else if (strcmp(token, "dns-data") == 0) {
				config->filters_flag.dns = true;
				config->filters_flag.dns_data = true;
			} else if (strcmp(token, "eth") == 0) {
				config->filters_flag.eth = true;
			} else if (strcmp(token, "icmp") == 0) {
				config->filters_flag.icmp = true;
			} else if (strcmp(token, "ip") == 0) {
				config->filters_flag.ip = true;
			} else if (strcmp(token, "tcp") == 0) {
				config->filters_flag.tcp = true;
			} else if (strcmp(token, "tcp-data") == 0) {
				config->filters_flag.tcp = true;
				config->filters_flag.tcp_data = true;
			} else if (strcmp(token, "udp") == 0) {
				config->filters_flag.udp = true;
			} else if (strcmp(token, "udp-data") == 0) {
				config->filters_flag.udp = true;
				config->filters_flag.udp_data = true;
			} else {
				fprintf(stderr, "Invalid filter flag: %s\n", token);
				return -1;
			}
			token = strtok(NULL, ",");
		}
	}
	return 0;
}

/**
 * @brief Initialize the configuration structure.
 * It will parse the filter flags from the command line arguments.
 *
 * @param config  The configuration structure
 * @param args    The command line arguments
 * @return int    0 on success, <0 on error
 */
int config_initialize(config_t *config, const cli_args_t *args) {
    memset(config, 0, sizeof(config_t));
    if (config_parse_filters_flag(config, args) < 0) {
        return -1;
    }
    return 0;
}

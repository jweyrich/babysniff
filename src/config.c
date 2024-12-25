#include "config.h"
#include "arguments.h"
#include <stdio.h>
#include <string.h>

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

	struct filter_flag {
		const char *name;
		bool *flag1;
		bool *flag2;
	};

	struct filter_flag filters_table[] = {
		{ "arp"		, &config->filters_flag.arp, NULL },
		{ "dns"		, &config->filters_flag.dns, NULL },
		{ "dns-data", &config->filters_flag.dns, &config->filters_flag.dns_data },
		{ "eth"		, &config->filters_flag.eth, NULL },
		{ "icmp"	, &config->filters_flag.icmp, NULL },
		{ "ip"		, &config->filters_flag.ip, NULL },
		{ "tcp"		, &config->filters_flag.tcp, NULL },
		{ "tcp-data", &config->filters_flag.tcp, &config->filters_flag.tcp_data },
		{ "udp"		, &config->filters_flag.udp, NULL },
		{ "udp-data", &config->filters_flag.udp, &config->filters_flag.udp_data },
	};


	if (args->filters != NULL) {
		char *token = strtok(args->filters, ",");
		while (token != NULL) {
			bool is_valid = false;
			// Find the filter flag in the table and set it to true
			// If the filter flag is not found, print an error message
			for (size_t i = 0; i < sizeof(filters_table) / sizeof(filters_table[0]); i++) {
				if (strcmp(token, filters_table[i].name) == 0) {
					is_valid = true;
					if (filters_table[i].flag1 != NULL) {
						*(filters_table[i].flag1) = true;
					}
					if (filters_table[i].flag2 != NULL) {
						*(filters_table[i].flag2) = true;
					}
					break;
				}
			}
			if (!is_valid) {
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

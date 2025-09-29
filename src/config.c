#include "config.h"
#include "arguments.h"
#include <stdio.h>
#include <string.h>

/**
 * @brief Parse the display filters flag from the command line arguments.
 * The `args->display_filters` member has the following format:
 *   arp,dns,dns-data,eth,icmp,ip,tcp,tcp-data,udp,upd-data
 *
 * @param config  The configuration structure
 * @param args    The command line arguments
 * @return int    0 on success, <0 on error
 */
static int config_parse_display_filters_flag(config_t *config, const cli_args_t *args) {
	// If no filters are provided, the default is "tcp"
	if (args->display_filters == NULL) {
		config->display_filters_flag.tcp = true;
		return 0;
	}

	struct filter_flag {
		const char *name;
		bool *flag1;
		bool *flag2;
	};

	struct filter_flag filters_table[] = {
		{ "arp"		, &config->display_filters_flag.arp, NULL },
		{ "dns"		, &config->display_filters_flag.dns, NULL },
		{ "dns-data", &config->display_filters_flag.dns, &config->display_filters_flag.dns_data },
		{ "eth"		, &config->display_filters_flag.eth, NULL },
		{ "icmp"	, &config->display_filters_flag.icmp, NULL },
		{ "ip"		, &config->display_filters_flag.ip, NULL },
		{ "tcp"		, &config->display_filters_flag.tcp, NULL },
		{ "tcp-data", &config->display_filters_flag.tcp, &config->display_filters_flag.tcp_data },
		{ "udp"		, &config->display_filters_flag.udp, NULL },
		{ "udp-data", &config->display_filters_flag.udp, &config->display_filters_flag.udp_data },
	};


	if (args->display_filters != NULL) {
		char *token = strtok(args->display_filters, ",");
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
				fprintf(stderr, "Invalid display filter flag: %s\n", token);
				return -1;
			}
			token = strtok(NULL, ",");
		}
	}
	return 0;
}

/**
 * @brief Automatically enable protocol display filters based on BPF filter
 * This makes BPF filters more user-friendly by automatically showing relevant protocols
 *
 * @param config  The configuration structure
 * @param args    The command line arguments
 */
static void config_auto_enable_protocol_filters(config_t *config, const cli_args_t *args) {
	if (args->bpf_filter_expr == NULL) {
		return; // No BPF filter, nothing to do
	}

    // Simple string matching to auto-enable protocol display filters
    // This makes BPF usage more intuitive for users
	if (strstr(args->bpf_filter_expr, "arp") != NULL) {
		config->display_filters_flag.arp = true;
	}
	if (strstr(args->bpf_filter_expr, "ip") != NULL) {
		config->display_filters_flag.ip = true;
	}
    if (strstr(args->bpf_filter_expr, "tcp") != NULL) {
        config->display_filters_flag.tcp = true;
    }
    if (strstr(args->bpf_filter_expr, "udp") != NULL) {
        config->display_filters_flag.udp = true;
    }
    if (strstr(args->bpf_filter_expr, "icmp") != NULL) {
        config->display_filters_flag.icmp = true;
    }
	if (strstr(args->bpf_filter_expr, "dns") != NULL || strstr(args->bpf_filter_expr, "port 53") != NULL) {
		config->display_filters_flag.udp = true;
		config->display_filters_flag.tcp = true;
		config->display_filters_flag.dns = true;
	}
    if (strstr(args->bpf_filter_expr, "port 80") != NULL || strstr(args->bpf_filter_expr, "port 443") != NULL) {
        config->display_filters_flag.tcp = true;
    }

	// Always enable IP and Ethernet for context
	config->display_filters_flag.ip = true;
	config->display_filters_flag.eth = true;
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
    if (config_parse_display_filters_flag(config, args) < 0) {
        return -1;
    }

    // Auto-enable protocol display filters based on BPF filter
    config_auto_enable_protocol_filters(config, args);

    return 0;
}

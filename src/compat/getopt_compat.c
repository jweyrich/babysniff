#include "getopt_compat.h"

#ifdef OS_WINDOWS

// Global variables for getopt state
char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = 0;

// Internal state
static char *nextchar = NULL;
static int first_nonopt = 1;
static int last_nonopt = 1;

int getopt(int argc, char * const argv[], const char *optstring) {
    if (optind >= argc) {
        return -1;
    }

    if (nextchar == NULL || *nextchar == '\0') {
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') {
            return -1;
        }

        if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }

        nextchar = argv[optind] + 1;
    }

    char c = *nextchar++;
    char *cp = strchr(optstring, c);

    if (cp == NULL || c == ':') {
        if (opterr) {
            fprintf(stderr, "Unknown option: -%c\n", c);
        }
        optopt = c;
        if (*nextchar == '\0') {
            optind++;
        }
        return '?';
    }

    if (cp[1] == ':') {
        // Option requires an argument
        if (*nextchar != '\0') {
            optarg = nextchar;
            optind++;
            nextchar = NULL;
        } else if (++optind >= argc) {
            if (opterr) {
                fprintf(stderr, "Option -%c requires an argument\n", c);
            }
            optopt = c;
            return '?';
        } else {
            optarg = argv[optind++];
        }
    } else {
        optarg = NULL;
        if (*nextchar == '\0') {
            optind++;
        }
    }

    return c;
}

int getopt_long(int argc, char * const argv[], const char *optstring, const struct option *longopts, int *longindex) {
    if (optind >= argc) {
        return -1;
    }

    char *arg = argv[optind];

    // Check for long option (starts with --)
    if (arg[0] == '-' && arg[1] == '-') {
        arg += 2;

        char *name_end = strchr(arg, '=');
        const int name_len = name_end ? (int)(name_end - arg) : (int)strlen(arg);

        // Find matching long option
        for (const struct option *opt = longopts; opt->name; opt++) {
            if (strncmp(opt->name, arg, name_len) == 0 && strlen(opt->name) == name_len) {
                if (longindex) {
                    *longindex = (int)(opt - longopts);
                }

                optind++;

                if (opt->has_arg == required_argument) {
                    if (name_end) {
                        optarg = name_end + 1;
                    } else if (optind < argc) {
                        optarg = argv[optind++];
                    } else {
                        if (opterr) {
                            fprintf(stderr, "Option --%s requires an argument\n", opt->name);
                        }
                        return '?';
                    }
                } else if (opt->has_arg == optional_argument) {
                    optarg = name_end ? name_end + 1 : NULL;
                } else {
                    if (name_end) {
                        if (opterr) {
                            fprintf(stderr, "Option --%s doesn't take an argument\n", opt->name);
                        }
                        return '?';
                    }
                    optarg = NULL;
                }

                if (opt->flag) {
                    *opt->flag = opt->val;
                    return 0;
                } else {
                    return opt->val;
                }
            }
        }

        if (opterr) {
            fprintf(stderr, "Unknown option: --%s\n", arg);
        }
        return '?';
    }

    // Fallback to short option processing
    return getopt(argc, argv, optstring);
}

#endif // OS_WINDOWS

#pragma once

// Windows getopt implementation
// Minimal implementation of getopt_long for Windows compatibility

#include "system.h"

#ifndef OS_WINDOWS
// On non-Windows systems, use the system's getopt.h
#   include <getopt.h>
#else // Windows
#   include <stdio.h>
#   include <string.h>
#   include <stdlib.h>

// getopt constants
#define no_argument       0
#define required_argument 1
#define optional_argument 2

// Option structure for getopt_long
struct option {
    const char *name;   // Long option name
    int has_arg;        // Argument requirement flag
    int *flag;          // Flag to set (or NULL)
    int val;            // Value to return (or to set *flag to)
};

// Global variables for getopt state
extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

// Function declarations
int getopt(int argc, char * const argv[], const char *optstring);
int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex);

#endif // OS_WINDOWS

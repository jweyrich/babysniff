#include "log.h"
#include "utils.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h> // for exit

void log_printf_narg_1(const char *format) {
	printf("%s", format);
}

void log_printf_narg_2(const char *format, ...) {
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

void log_printf_indent_narg_3(int indent, const char *indentstr, const char *format) {
	printf("%*s%s", indent, indentstr, format);
}

void log_printf_indent_narg_4(int indent, const char *indentstr, const char *format, ...) {
	va_list args;
	va_start(args, format);
	printf("%*s", indent, indentstr);
	vprintf(format, args);
	va_end(args);
}

void log_printf_level_narg_4(const char *file, int line, log_level_e level, const char *format) {
	log_level_e current_level = log_level_get();
	if (level > current_level) {
		return;
	}
	const char *level_name = log_level_name(level);

	char relative_path[1024];
	int ret = utils_relative_path(relative_path, sizeof(relative_path), file);
	if (ret != 0) {
		fprintf(stderr, "Failed to get relative path for %s\n", file);
		exit(1);
	}

    printf("%s %s:%d %s\n", level_name, relative_path, line, format);
}

void log_printf_level_narg_5(const char *file, int line, log_level_e level, const char *format, ...) {
	log_level_e current_level = log_level_get();
	if (level > current_level) {
		return;
	}
	const char *level_name = log_level_name(level);

	char relative_path[1024];
	int ret = utils_relative_path(relative_path, sizeof(relative_path), file);
	if (ret != 0) {
		fprintf(stderr, "Failed to get relative path for %s\n", file);
		exit(1);
	}

	va_list args;
	va_start(args, format);
	printf("%s %s:%d ", level_name, relative_path, line);
	vprintf(format, args);
	printf("\n");
	va_end(args);
}

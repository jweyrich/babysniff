//
//  Usage:
//
//	LOG_TRACE();
//	LOG_DEBUG(format, ...)
//	LOG_INFO(format, ...)
//	LOG_WARN(format, ...)
//	LOG_ERROR(format, ...)
//	LOG_FATAL(format, ...)
//
//	LOG_PRINTF(format, ...)
//	LOG_PRINTF_INDENT(indent, format, ...)
//	LOG_PRINTF_INDENT_TAB(indent, format, ...)
//

#pragma once

#include "variadic.h"
#include <stdbool.h>

typedef enum {
	LOGLEVEL_FATAL = 0,
	LOGLEVEL_ERROR, // default log level
	LOGLEVEL_WARN,
	LOGLEVEL_INFO,
	LOGLEVEL_DEBUG,
	LOGLEVEL_TRACE,
} loglevel_e;

bool log_level_is_valid(int level);
void log_level_set(int level);
const char *log_level_name(loglevel_e level);

#define LOG_PASTE2(_0,_1)					_0 ## _1
#define LOG_ARG16(_0,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,...)	_15
#define LOG_ARG_0_1_2_RSEQ()				2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,0
#define LOG_ARG_0_2_3_RSEQ()				3,3,3,3,3,3,3,3,3,3,3,3,3,3,2,0
#define LOG_ARG_0_3_4_RSEQ()				4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,0
#define LOG_ARG_0_4_5_RSEQ()				5,5,5,5,5,5,5,5,5,5,5,5,5,5,4,0
#define LOG_NARG(RSEQ,...)					LOG_NARG_IMP(__VA_ARGS__, RSEQ())
#define LOG_NARG_IMP(...)					LOG_ARG16(__VA_ARGS__)
#define LOG_SELECT_FUNC(FUNCNAME,ARGSN,...) LOG_RUN_FUNC(LOG_PASTE2(FUNCNAME, ARGSN), __VA_ARGS__)
#define LOG_RUN_FUNC(FUNCNAME,...)			FUNCNAME(__VA_ARGS__)

#define LOG_FATAL(...) \
	LOG_SELECT_FUNC(log_level_, LOG_NARG(LOG_ARG_0_4_5_RSEQ,__VA_ARGS__), \
		__FILE__, __LINE__, LOGLEVEL_FATAL, __VA_ARGS__)
#define LOG_ERROR(...) \
	LOG_SELECT_FUNC(log_level_, LOG_NARG(LOG_ARG_0_4_5_RSEQ,__VA_ARGS__), \
		__FILE__, __LINE__, LOGLEVEL_ERROR, __VA_ARGS__)
#define LOG_WARN(...) \
	LOG_SELECT_FUNC(log_level_, LOG_NARG(LOG_ARG_0_4_5_RSEQ,__VA_ARGS__), \
		__FILE__, __LINE__, LOGLEVEL_WARN, __VA_ARGS__)
#define LOG_INFO(...) \
	LOG_SELECT_FUNC(log_level_, LOG_NARG(LOG_ARG_0_4_5_RSEQ,__VA_ARGS__), \
		__FILE__, __LINE__, LOGLEVEL_INFO, __VA_ARGS__)
#define LOG_DEBUG(...) \
	LOG_SELECT_FUNC(log_level_, LOG_NARG(LOG_ARG_0_4_5_RSEQ,__VA_ARGS__), \
		__FILE__, __LINE__, LOGLEVEL_DEBUG, __VA_ARGS__)
#define LOG_TRACE \
	log_level_5(__FILE__, __LINE__, LOGLEVEL_TRACE, "%s called", __func__) //__PRETTY_FUNCTION__

#define LOG_PRINTF(...) \
	do { \
		LOG_SELECT_FUNC(log_printf_, LOG_NARG(LOG_ARG_0_1_2_RSEQ,__VA_ARGS__), \
			__VA_ARGS__); \
	} while (0)

#define LOG_PRINTF_INDENT(indent, ...) \
	do { \
		LOG_SELECT_FUNC(log_printf_indent_, LOG_NARG(LOG_ARG_0_3_4_RSEQ,__VA_ARGS__), \
			indent, " ", __VA_ARGS__); \
	} while (0)

#define LOG_PRINTF_INDENT_TAB(indent, ...) \
	do { \
		LOG_SELECT_FUNC(log_printf_indent_, LOG_NARG(LOG_ARG_0_3_4_RSEQ,__VA_ARGS__), \
			indent * 8, "\t", __VA_ARGS__); \
	} while (0)

void log_level_4(const char *file, int line, loglevel_e level, const char *format);
void log_level_5(const char *file, int line, loglevel_e level, const char *format, ...);
void log_printf_1(const char *format);
void log_printf_2(const char *format, ...);
void log_printf_indent_3(int indent, const char *indentstr, const char *format);
void log_printf_indent_4(int indent, const char *indentstr, const char *format, ...);

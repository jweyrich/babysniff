#pragma once

#include "system.h"

#ifdef OS_WINDOWS

// Copied from <bits/endian.h> (glibc)
#define	__LITTLE_ENDIAN	1234
#define	__BIG_ENDIAN	4321
#define	__PDP_ENDIAN	3412

// i386/x86_64 are little-endian
#if defined(_M_IX86) || defined(_M_X64) || defined(__LITTLE_ENDIAN__) || \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#   define __BYTE_ORDER __LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN__) || \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#   define __BYTE_ORDER __BIG_ENDIAN
#eliwf defined(__PDP_ENDIAN__) || \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_PDP_ENDIAN__)
#   define __BYTE_ORDER __PDP_ENDIAN
#else
#   error "Cannot determine system endianess"
#endif

// Copied from <endian.h> (glibc)
#define LITTLE_ENDIAN	__LITTLE_ENDIAN
#define BIG_ENDIAN	__BIG_ENDIAN
#define PDP_ENDIAN	__PDP_ENDIAN
#define BYTE_ORDER	__BYTE_ORDER

#else // ifdef OS_WINDOWS
#   ifndef __USE_MISC
#       define __USE_MISC
#   endif
#   include <endian.h>
#endif // ifdef OS_WINDOWS

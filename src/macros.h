#pragma once

#include <stddef.h> // for ptrdiff_t
#include <stdint.h> // for uintptr_t

// The void() here guarantees the global comma operator will be
// invoked instead of a possible overload defined by X's type.
// This is valid only in C++
//#define BASE_UNUSED(x)	(void)(true ? 0 : ((x), void(), 0))
// This is valid in either C and C++
#define BASE_UNUSED(x)      (void)(sizeof((x)))

#if defined(__GNUC__X) || defined(__INTEL_COMPILER)
#	define BASE_NOTREACHED	__builtin_unreachable()
#else
#	define BASE_NOTREACHED	((void)0)
#endif

//
// Use these
//
#define UNUSED(x)			BASE_UNUSED(x)
#define NOTREACHED			BASE_NOTREACHED
#define PTR_ADD(p1, p2)		((uintptr_t)(p1) + (uintptr_t)(p2))
#define PTR_SUB(p1, p2)		((ptrdiff_t)((uintptr_t)(p1) - (uintptr_t)(p2)))

#define member_size(type, member)	sizeof(((type *)0)->member)

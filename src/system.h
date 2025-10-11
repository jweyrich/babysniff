#pragma once

/*
 * Systems:
 * 		OS_MAC
 * 		OS_LINUX
 * 		OS_FREEBSD
 * 		OS_NETBSD
 * 		OS_OPENBSD
 * 		OS_MINT
 * 		OS_SOLARIS
 * 		OS_HPUX
 * 		OS_RISC_OS
 * 		OS_OS2
 * 		OS_IRIX
 * 		OS_AIX
 * 		OS_BEOS
 * 		OS_LYNX_OS
 * 		OS_CYGWIN
 * 		OS_OPENVMS
 * 		OS_OSF
 * 		OS_QNXNTO
 *      OS_TRU64
 * 		OS_WINDOWS
 *      OS_UNIXWARE
 * 		OS_DREAMCAST
 * Special cases:
 * 		OS_BSD_BASED
 * 		OS_MOSTLY_POSIX_COMPLIANT
 * 		OS_FULLY_POSIX_COMPLIANT
 */

#if defined(__APPLE__) || \
    defined(MAC_OS_CLASSIC) || \
    defined(MAC_OS_X) || \
    defined(macintosh)
#	define OS_MAC
#elif defined(linux) || \
    defined(__linux) || \
    defined(__linux__)
#	define OS_LINUX
#elif defined(__FreeBSD__) || \
    defined(__DragonFly__)
#	define OS_FREEBSD
#elif defined(__NetBSD__)
#	define OS_NETBSD
#elif defined(__OpenBSD__)
#	define OS_OPENBSD
#elif defined(__MINT__)
#	define OS_MINT
#elif defined(sun) || \
    defined(__sun) || \
    defined(__SVR4)
#	define OS_SOLARIS
#elif defined(hpux) || \
    defined(__hpux) || \
    defined(__hpux__)
#	define OS_HPUX
#elif defined(riscos) || \
    defined(__riscos) || \
    defined(__riscos__)
#	define OS_RISC_OS
#elif defined(__OS2__) || \
    defined(__EMX__)
#	define OS_OS2
#elif defined(osf) || \
    defined(__osf) || \
    defined(__osf__) || \
    defined(_OSF_SOURCE)
#	define OS_OSF
#elif defined(sgi) || \
    defined(__sgi) || \
    defined(__sgi__) || \
    defined(_SGI_SOURCE)
#	define OS_IRIX
#elif defined(_AIX)
#	define OS_AIX
#elif defined(BEOS) || \
    defined(__BEOS__)
#	define OS_BEOS
#elif defined(__lynxOS__)
#   define OS_LYNX_OS
#elif defined(__CYGWIN__)
#	define OS_CYGWIN
#elif defined(__VMS)
#	define OS_OPENVMS
#elif defined(__QNXNTO__)
#	define OS_QNXNTO
#elif defined(_arch_dreamcast)
#	define OS_DREAMCAST
#elif defined(Tru64)
#   define OS_TRU64
#elif defined(WINDOWS) || \
    defined(WIN32) || \
    defined(_WIN32) || \
    defined(_WIN64) || \
    defined(__WIN32__) || \
    defined(__WINDOWS__)
#	define OS_WINDOWS
#elif defined(UNIXWARE)
#   define OS_UNIXWARE
#else
#	error system not supported
#endif

#if defined(OS_MAC) || \
    defined(OS_FREEBSD) || \
    defined(OS_NETBSD) || \
    defined(OS_OPENBSD)
#   define OS_BSD_BASED
#endif

#if defined(OS_BEOS) || \
    defined(OS_FREEBSD) || \
    defined(OS_LINUX) || \
    defined(OS_NETBSD) || \
    defined(OS_OPENBSD) || \
    defined(OS_CYGWIN)
#   define OS_MOSTLY_POSIX_COMPLIANT
#endif

#if defined(OS_AIX) || \
    defined(OS_HPUX) || \
    defined(OS_IRIX) || \
    defined(OS_MAC) || \
    defined(OS_QNXNTO) || \
    defined(OS_SOLARIS) || \
    defined(OS_LYNX_OS) || \
    defined(OS_UNIXWARE) || \
    defined(OS_TRU64)
#   define OS_FULLY_POSIX_COMPLIANT
#endif

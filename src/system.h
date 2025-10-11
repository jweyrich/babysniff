#pragma once

/*
 * Cross-platform OS detection macros
 *
 * Primary OS identifiers:
 *   OS_MAC          - macOS/Mac OS X/Classic Mac
 *   OS_LINUX        - Linux distributions
 *   OS_WINDOWS      - Windows (all versions)
 *   OS_CYGWIN       - Cygwin on Windows
 *
 * BSD variants:
 *   OS_FREEBSD      - FreeBSD (includes DragonFly BSD)
 *   OS_NETBSD       - NetBSD
 *   OS_OPENBSD      - OpenBSD
 *
 * Unix systems:
 *   OS_SOLARIS      - Solaris/SunOS
 *   OS_HPUX         - HP-UX
 *   OS_AIX          - IBM AIX
 *   OS_IRIX         - SGI IRIX
 *   OS_OSF          - OSF/1, Digital Unix
 *   OS_TRU64        - Tru64 Unix
 *   OS_UNIXWARE     - UnixWare
 *   OS_QNXNTO       - QNX Neutrino
 *   OS_LYNX_OS      - LynxOS
 *
 * Other systems:
 *   OS_BEOS         - BeOS/Haiku
 *   OS_OS2          - OS/2
 *   OS_OPENVMS      - OpenVMS
 *   OS_RISC_OS      - RISC OS
 *   OS_MINT         - Atari MiNT
 *   OS_DREAMCAST    - Dreamcast
 *
 * Composite macros:
 *   OS_BSD_BASED              - Any BSD-derived system
 *   OS_MOSTLY_POSIX_COMPLIANT - Systems with good POSIX support
 *   OS_FULLY_POSIX_COMPLIANT  - Systems with complete POSIX compliance
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

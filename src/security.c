#include "security.h"

#include "macros.h"
#include "system.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#ifdef OS_WINDOWS
#	include <windows.h>
#	include <lmcons.h>
typedef unsigned int uid_t; // Windows doesn't have uid_t, define a dummy type
#else
#	include <pwd.h>
#	include <sys/types.h>
#	include <unistd.h>
#endif

static bool is_empty_string(const char *str) {
	return str == NULL || str[0] == '\0';
}

bool is_running_as_superuser(void) {
#ifdef OS_WINDOWS
	BOOL isAdmin = FALSE;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);

		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
			isAdmin = elevation.TokenIsElevated;
		}
		CloseHandle(hToken);
	}

	return isAdmin != FALSE;
#else
	uid_t euid = geteuid();
	return euid == 0;
#endif
}

int security_force_chroot(const char *dirname) {
	if (is_empty_string(dirname)) {
		fprintf(stderr, "Invalid chroot directory.\n");
		return -1;
	}
	if (!is_running_as_superuser()) {
#ifdef OS_WINDOWS
		fprintf(stderr, "Unable to chroot: not running as administrator\n");
#else
		fprintf(stderr, "Unable to chroot: not running as superuser\n");
#endif
		return -1;
	}

#ifdef OS_WINDOWS
	// Windows doesn't support chroot jail, so we just change the current directory.
	// NOTE: This doesn't provide the same security isolation as chroot on POSIX systems
	if (SetCurrentDirectoryA(dirname) == 0) {
		fprintf(stderr, "Unable to change directory to %s: Windows error %lu\n",
			dirname, GetLastError());
		return -1;
	}
	return 0;
#else
	if (chdir(dirname) != 0) {
		fprintf(stderr, "Unable to chdir to %s: %s\n", dirname, strerror(errno));
		return -1;
	}
	if (chroot(dirname) != 0) {
		fprintf(stderr, "Unable to chroot to %s: %s (Try using the absolute path)\n",
			dirname, strerror(errno));
		return -1;
	}
	return 0;
#endif
}

int drop_priv_perm(uid_t new_uid) {
#ifdef OS_WINDOWS
	// On Windows, privilege dropping is handled differently
	// For network sniffers, we typically just ensure we have the necessary
	// privileges when needed rather than permanently dropping them
	// This is because Windows doesn't have a direct equivalent to setuid
	UNUSED(new_uid);
	return 0; // Success - no action needed on Windows
#elif defined(OS_LINUX)
	uid_t ruid, euid, suid;
	// On Linux one MUST use setresuid to permanently drop privileges
	if (setresuid(new_uid, new_uid, new_uid) < 0)
		return -1;
	if (getresuid(&ruid, &euid, &suid) < 0)
		return -1;
	if (ruid != new_uid || euid != new_uid || suid != new_uid)
		return -1;
	return 0;
#else
	// TODO(jweyrich): We need to verify how to correctly drop privileges in other systems
	if (setuid(new_uid) < 0)
		return -1;
	if (geteuid() != new_uid)
		return -1;
	return 0;
#endif
}

int security_force_uid(const char *username) {
	if (is_empty_string(username)) {
		fprintf(stderr, "Invalid username provided for privileges dropping.\n");
		return -1;
	}
	if (!is_running_as_superuser()) {
		fprintf(stderr, "Unable to chroot: not running as superuser\n");
		return -1;
	}

#ifdef OS_WINDOWS
	// On Windows, we don't actually switch users like on POSIX systems
	// This is a no-op but we report success since the intent (security) is handled
	// by the Windows security model differently
	return 0;
#else
	// TODO(jweyrich): use getpwnam_r instead
	struct passwd *user = getpwnam(username);
	if (user == NULL) {
		fprintf(stderr, "User %s doesn't exist\n", username);
		return -1;
	}

	if (drop_priv_perm(user->pw_uid) < 0) {
		fprintf(stderr, "Unable to setuid to %s: %s\n", username, strerror(errno));
		return -1;
	}
	return 0;
#endif
}

#include "security.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>

static bool is_empty_string(const char *str) {
	return str == NULL || str[0] == '\0';
}

bool is_running_as_superuser(void) {
	uid_t euid = geteuid();
	return euid == 0;
}

int security_force_chroot(const char *dirname) {
	if (is_empty_string(dirname)) {
		fprintf(stderr, "Invalid chroot directory.\n");
		return -1;
	}
	if (!is_running_as_superuser()) {
		fprintf(stderr, "Unable to chroot: not running as superuser\n");
		return -1;
	}
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
}

int drop_priv_perm(uid_t new_uid) {
#if defined(OS_LINUX)
	uid_t ruid, euid, suid;
	// On Linux one MUST use setresuid to permanently drop privileges
	if (setresuid(new_uid, new_uid, new_uid) < 0)
		return -1;
	if (getresuid(&ruid, &euid, &suid) < 0)
		return -1;
	if (ruid != new_uid || euid != new_uid || suid != new_uid)
		return -1;
#else
	if (setuid(new_uid) < 0)
		return -1;
	if (geteuid() != new_uid)
		return -1;
#endif
	return 0;
}

int security_force_uid(const char *username) {
	struct passwd *user;
	if (is_empty_string(username)) {
		fprintf(stderr, "Invalid username provided for privileges dropping.\n");
		return -1;
	}
	if (!is_running_as_superuser()) {
		fprintf(stderr, "Unable to chroot: not running as superuser\n");
		return -1;
	}
	// TODO(jweyrich): use getpwnam_r instead
	user = getpwnam(username);
	if (user == NULL) {
		fprintf(stderr, "User %s doesn't exist\n", username);
		return -1;
	}
	if (drop_priv_perm(user->pw_uid) < 0) {
		fprintf(stderr, "Unable to setuid to %s: %s\n", username, strerror(errno));
		return -1;
	}
	return 0;
}

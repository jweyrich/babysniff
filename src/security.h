#pragma once

#include <stdbool.h>

bool is_running_as_superuser(void);
int security_force_chroot(const char *dirname);
int security_force_uid(const char *username);

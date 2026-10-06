/*
 * No-op stand-ins for unveil(2) and pledge(2), so that an unveil-backend
 * test build links on a host without them.  Drivers that assert the
 * enforcement sequence define recording versions themselves instead of
 * including this file.  On OpenBSD the definitions here take precedence
 * over libc's for the test binary, which keeps the tests kernel-free there
 * as well.
 */
#ifndef DASHLOCK_TEST_UNVEIL_STUBS_H
#define DASHLOCK_TEST_UNVEIL_STUBS_H

int
unveil(const char *path, const char *permissions)
{
	(void)path;
	(void)permissions;
	return 0;
}

int
pledge(const char *promises, const char *execpromises)
{
	(void)promises;
	(void)execpromises;
	return 0;
}

#endif

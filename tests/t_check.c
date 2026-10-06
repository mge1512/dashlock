/*
 * dashlock-check built against the test fixture directories, for the
 * policy-file trust tests (tests/t_trust.sh).  The fixture root is a
 * compile-time constant like the real directories, so the trust checks,
 * including the ownership walk from "/", run unchanged against it.  The
 * script reads the directories back from "t_check -V".
 */
#ifndef DASHLOCK_TEST_FIXTURE_ROOT
#define DASHLOCK_TEST_FIXTURE_ROOT "/var/lib/dashlock-test"
#endif
#undef DASHLOCK_ETCDIR
#undef DASHLOCK_LIBDIR
#define DASHLOCK_ETCDIR DASHLOCK_TEST_FIXTURE_ROOT "/etc"
#define DASHLOCK_LIBDIR DASHLOCK_TEST_FIXTURE_ROOT "/lib"

#include "dashlock-check.c"

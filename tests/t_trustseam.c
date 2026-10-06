/*
 * Layer 3, the two trust cases that must not be written as a race, driven
 * through the DL_FSTAT seam against the fixture directories:
 *
 *   grow  the policy file reports a larger size after the read than
 *         before it: refused as "changed while it was being read"
 *         (review finding 4: a truncated or extended read is never
 *         treated as a narrower policy)
 *   eio   fstat on the opened policy file fails with EIO: the refusal
 *         carries that errno, which it only does if errno is captured
 *         before the descriptor is closed (review finding 3)
 *
 * Run by tests/t_trust.sh as root with a fixture file for key "seam".
 */
#include <stdio.h>
#include <sys/stat.h>

#ifndef DASHLOCK_TEST_FIXTURE_ROOT
#define DASHLOCK_TEST_FIXTURE_ROOT "/var/dashlock-test"
#endif
#undef DASHLOCK_ETCDIR
#undef DASHLOCK_LIBDIR
#define DASHLOCK_ETCDIR DASHLOCK_TEST_FIXTURE_ROOT "/etc"
#define DASHLOCK_LIBDIR DASHLOCK_TEST_FIXTURE_ROOT "/lib"

static int test_fstat(int fd, struct stat *st);
#define DL_FSTAT test_fstat

#include "dashlock.c"

static int seam_grow, seam_eio, regular_calls;

static int
test_fstat(int fd, struct stat *st)
{
	int rc = fstat(fd, st);

	if (rc != 0 || !S_ISREG(st->st_mode))
		return rc;
	regular_calls++;
	/* 1: the verified open; 2: after the read-to-EOF. */
	if (seam_eio && regular_calls == 1) {
		errno = EIO;
		return -1;
	}
	if (seam_grow && regular_calls == 2)
		st->st_size += 1;
	return rc;
}

int
main(int argc, char **argv)
{
	static struct dl_policy pol;

	if (argc != 2)
		return 2;
	if (strcmp(argv[1], "grow") == 0)
		seam_grow = 1;
	else if (strcmp(argv[1], "eio") == 0)
		seam_eio = 1;
	else if (strcmp(argv[1], "plain") != 0)
		return 2;
	dl_load(&pol, "seam", 0);
	printf("loaded %s\n", pol.source);
	return 0;
}

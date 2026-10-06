/*
 * Forking fuzz driver over the parse path (dashlock.spec.md, DELIVERABLES:
 * fuzz-driver).  Reads one policy file, runs dl_parse and the backend's
 * pre-kernel checks on it, and exits: a refusal exits 78, which a forking
 * fuzzer (AFL++) treats as a normal result, so the refusal paths need no
 * change for fuzzing.  Only crashes and sanitizer reports are findings.
 *
 *   make fuzz_parse CC=afl-clang-fast
 *   afl-fuzz -i ../policy/users -o findings -- ./fuzz_parse @@
 */
#include <stdio.h>

#include "dashlock.c"

#ifdef DASHLOCK_BACKEND_UNVEIL
#include "unveil_stubs.h"
#endif

int
main(int argc, char **argv)
{
	static struct dl_policy pol;
	FILE *f;
	size_t n;

	if (argc != 2)
		return 2;
	f = fopen(argv[1], "rb");
	if (f == NULL)
		return 2;
	pol.content = malloc((size_t)DL_FILE_MAX + 1);
	if (pol.content == NULL)
		return 2;
	n = fread(pol.content, 1, (size_t)DL_FILE_MAX, f);
	fclose(f);
	pol.content[n] = '\0';
	pol.abi_floor = 1;
	strcpy(pol.source, "fuzz");
	dl_parse(&pol);
#ifdef DASHLOCK_BACKEND_LANDLOCK
	dl_landlock_check(&pol, NULL);
	(void)dl_required_abi(&pol);
#else
	dl_unveil_check(&pol);
#endif
	free(pol.content);
	return 0;
}

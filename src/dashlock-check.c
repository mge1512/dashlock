/*
 * dashlock-check: the policy checker.
 *
 * Implements BEHAVIOR validate-policy of dashlock.spec.md.  This is a
 * second translation unit that includes dashlock.c the way the unit drivers
 * in the hints file do, so it links the shell's own user-key resolution,
 * lookup, trust checks, parser, required-ABI derivation, backend pre-kernel
 * checks, and refusal.  It stops before enforcement: no ruleset is created,
 * no unveil or pledge call is made, no_new_privs is not set, and the
 * invoking process is never confined.
 *
 * Refusals are the shell's own: dl_refuse writes the session's exact line
 * and exits 78.  The checker adds nothing to that path, which is the point;
 * an administrator who runs the checker gets the report the session would
 * have produced.  Exit 2 is reserved for usage errors, so that a wrong
 * command line is never mistaken for a policy refusal.
 *
 * Unlike the shell, the checker may use stdio: it is not the confining
 * binary, has no output layer to stay out of, and prints reports.
 */

#include <stdio.h>
#include <pwd.h>

#include "dashlock.c"

#define CHECK_EXIT_USAGE 2

static const char *check_prog = "dashlock-check";

static void
check_usage(void)
{
	fprintf(stderr,
		"usage: %s [-k | -d] [-l] [-q] [-n narrow] [user]\n"
		"       %s -V\n"
		"  default  validate: would the policy apply? exit 0 or 78\n"
		"  -k       kernel mode: also check against the running kernel\n"
		"  -d       dump mode: print the normalized policy\n"
		"  -l       advisory lints on stderr (never change the exit code)\n"
		"  -q       quiet: one finding per line, no success line\n"
		"  -n NAME  also check the narrowing policy NAME\n"
		"  user     account whose policy to check (default: the caller)\n",
		check_prog, check_prog);
	exit(CHECK_EXIT_USAGE);
}

static const char *
check_backend(void)
{
#ifdef DASHLOCK_BACKEND_LANDLOCK
	return "landlock";
#else
	return "unveil";
#endif
}

/*
 * Derive the key for a named account the way resolve-user-key does for the
 * caller: the account name when it is a usable key, else the decimal uid.
 * A name that is not a local account is accepted verbatim when it is a
 * usable key, so that a policy file can be checked before the account
 * exists; the report says which case applied.
 */
static void
check_key_for(const char *arg, char *out, size_t outlen, int *is_account,
	      char **home)
{
	struct passwd pwd, *res = NULL;
	char buf[16384];
	int rc;

	rc = getpwnam_r(arg, &pwd, buf, sizeof(buf), &res);
	if (rc == 0 && res != NULL) {
		*is_account = 1;
		if (res->pw_dir != NULL)
			*home = strdup(res->pw_dir);
		if (res->pw_name != NULL && dl_valid_user_key(res->pw_name) &&
		    strlen(res->pw_name) < outlen) {
			memcpy(out, res->pw_name, strlen(res->pw_name) + 1);
			return;
		}
		dl_utoa((unsigned long)res->pw_uid, out, outlen);
		return;
	}
	*is_account = 0;
	if (!dl_valid_user_key(arg) || strlen(arg) >= outlen) {
		fprintf(stderr, "%s: '%s' is neither a local account nor a "
			"usable policy key\n", check_prog, arg);
		exit(CHECK_EXIT_USAGE);
	}
	memcpy(out, arg, strlen(arg) + 1);
}

/* Comma-separated names of the set bits in a table, in table order. */
static void
check_print_names(const struct dl_name_bit *table, uint64_t bits)
{
	const struct dl_name_bit *e;
	int first = 1;

	for (e = table; e->name != NULL; e++) {
		if ((bits & e->bit) == 0)
			continue;
		printf("%s%s", first ? "" : ",", e->name);
		first = 0;
	}
	if (first)
		printf("none");
}

/*
 * Dump mode: the normalized policy, one fact per line, names in table
 * order, rules in policy order (the order is semantically relevant on the
 * unveil backend).  Deterministic, so two dumps can be diffed.
 */
static void
check_dump(const struct dl_policy *pol, const char *label)
{
	int i;

	printf("%s %s\n", label, pol->source);
	printf("backend %s\n", check_backend());
	printf("abi-min %d\n", pol->abi_floor);
	if (pol->abi_max != 0)
		printf("abi-max %d\n", pol->abi_max);
	else
		printf("abi-max none\n");
	if (pol->want_all_fs)
		printf("access fs all\n");
	else if (pol->handled_fs != 0) {
		printf("access fs ");
		check_print_names(dl_fs_names, pol->handled_fs);
		printf("\n");
	} else
		printf("access fs none\n");
	if (pol->want_all_net)
		printf("access net-tcp all\n");
	else if (pol->handled_net != 0) {
		printf("access net-tcp ");
		check_print_names(dl_net_names, pol->handled_net);
		printf("\n");
	} else
		printf("access net-tcp none\n");
	printf("scope ");
	check_print_names(dl_scope_names, pol->scoped);
	printf("\n");
	if (pol->have_pledge) {
		int first = 1;

		printf("pledge ");
		for (i = 0; dl_pledge_names[i] != NULL; i++) {
			if ((pol->pledge_bits & ((uint64_t)1 << i)) == 0)
				continue;
			printf("%s%s", first ? "" : " ", dl_pledge_names[i]);
			first = 0;
		}
		printf("\n");
	} else
		printf("pledge default\n");
	for (i = 0; i < pol->npath; i++) {
		printf("rule path-beneath ");
		check_print_names(dl_fs_names, pol->path_rules[i].access);
		printf(" %s\n", pol->path_rules[i].path);
	}
	for (i = 0; i < pol->nnet; i++) {
		printf("rule net-port ");
		check_print_names(dl_net_names, pol->net_rules[i].access);
		printf(" %u\n", pol->net_rules[i].port);
	}
#ifdef DASHLOCK_BACKEND_LANDLOCK
	printf("required-abi %d\n", dl_required_abi(pol));
#endif
}

/* Does a rule path cover a given path: equal, or an ancestor directory. */
static int
check_rule_covers(const char *rule, const char *path)
{
	size_t n = strlen(rule);

	if (strcmp(rule, "/") == 0)
		return 1;
	if (strncmp(rule, path, n) != 0)
		return 0;
	return path[n] == '\0' || path[n] == '/';
}

/* Union of the rights every rule covering path grants. */
static uint64_t
check_rights_on(const struct dl_policy *pol, const char *path)
{
	uint64_t r = 0;
	int i;

	for (i = 0; i < pol->npath; i++)
		if (check_rule_covers(pol->path_rules[i].path, path))
			r |= pol->path_rules[i].access;
	return r;
}

static void
check_advise(const char *msg)
{
	fprintf(stderr, "%s: advisory: %s\n", check_prog, msg);
}

/*
 * Advisory lints.  Recommendations, never rules: they do not change the
 * exit code, and the set is backend-appropriate (hints file, "The policy
 * checker").  Each one names an omission that reads like a permission bug
 * in a session.
 */
static void
check_lint(const struct dl_policy *pol, const char *home, int is_account)
{
#ifdef DASHLOCK_BACKEND_LANDLOCK
	static const char *const libdirs[] = {
		"/usr/lib", "/usr/lib64", "/lib", "/lib64", NULL
	};
	int covered = 0;
	int i;

	for (i = 0; libdirs[i] != NULL; i++) {
		uint64_t r = check_rights_on(pol, libdirs[i]);

		if ((r & DL_FS_READ_FILE) != 0 && (r & DL_FS_EXECUTE) != 0)
			covered = 1;
	}
	if (!covered)
		check_advise("no rule grants read-file and execute on a "
			     "library directory (/usr/lib, /lib); dynamically "
			     "linked programs will not start");
	if ((check_rights_on(pol, "/etc/ld.so.cache") & DL_FS_READ_FILE) == 0)
		check_advise("/etc/ld.so.cache is not readable; the loader "
			     "falls back to a slower library search or fails");
	{
		uint64_t tty = check_rights_on(pol, "/dev/tty");
		uint64_t pts = check_rights_on(pol, "/dev/pts");

		if (((tty | pts) & (DL_FS_READ_FILE | DL_FS_WRITE_FILE)) != 0 &&
		    ((tty | pts) & DL_FS_IOCTL_DEV) == 0)
			check_advise("terminal devices are granted without "
				     "ioctl-dev; interactive programs that "
				     "query the terminal will fail");
	}
#endif
	if ((pol->want_all_fs || pol->handled_fs != 0) && pol->npath == 0)
		check_advise("the filesystem category is handled but no "
			     "path rule grants anything; the session can "
			     "reach no file at all");
	if ((pol->want_all_net || pol->handled_net != 0) && pol->nnet == 0)
		check_advise("the network category is handled but no port "
			     "rule grants anything; every TCP bind and "
			     "connect is denied");
	if (is_account && home != NULL && home[0] == '/' &&
	    check_rights_on(pol, home) == 0)
		check_advise("the account's home directory is not covered "
			     "by any rule; an interactive login lands in a "
			     "directory it cannot read");
}

int
main(int argc, char **argv)
{
	static struct dl_policy base;
	static struct dl_policy narrow;
	char key[DL_KEY_MAX];
	const char *narrow_name = NULL;
	const char *user_arg = NULL;
	char *home = NULL;
	int mode_kernel = 0, mode_dump = 0, lints = 0, quiet = 0;
	int is_account = 1;
	int i;

	if (argc > 0 && argv[0] != NULL && argv[0][0] != '\0')
		check_prog = argv[0];

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (a[0] != '-' || strcmp(a, "-") == 0) {
			if (user_arg != NULL)
				check_usage();
			user_arg = a;
			continue;
		}
		if (strcmp(a, "-k") == 0)
			mode_kernel = 1;
		else if (strcmp(a, "-d") == 0)
			mode_dump = 1;
		else if (strcmp(a, "-l") == 0)
			lints = 1;
		else if (strcmp(a, "-q") == 0)
			quiet = 1;
		else if (strcmp(a, "-n") == 0) {
			if (i + 1 >= argc || narrow_name != NULL)
				check_usage();
			narrow_name = argv[++i];
		} else if (strcmp(a, "-V") == 0) {
			printf("%s: backend %s, policy directories %s and %s\n",
			       check_prog, check_backend(), DASHLOCK_ETCDIR,
			       DASHLOCK_LIBDIR);
			return 0;
		} else
			check_usage();
	}
	if (mode_kernel && mode_dump)
		check_usage();

	/*
	 * Spec, validate-policy step 1: the key the session would use, for
	 * the caller by default.  The trust checks that follow run as the
	 * invoking identity; the success line states it.
	 */
	if (user_arg != NULL) {
		check_key_for(user_arg, key, sizeof(key), &is_account, &home);
	} else {
		struct passwd pwd, *res = NULL;
		char buf[16384];

		dl_user_key(key, sizeof(key));
		if (getpwuid_r(getuid(), &pwd, buf, sizeof(buf), &res) == 0 &&
		    res != NULL && res->pw_dir != NULL)
			home = strdup(res->pw_dir);
	}

	/* Steps 2 and 3: lookup, trust checks, parse, as the session does. */
	dl_load(&base, key, 0);

	/* Step 4: the narrowing policy, exactly as the session handles it. */
	if (narrow_name != NULL) {
#ifdef DASHLOCK_BACKEND_UNVEIL
		dl_refuse("narrowing is not supported by this backend",
			  NULL, NULL);
#else
		if (!dl_valid_narrow_name(narrow_name))
			dl_refuse("invalid narrow policy name", NULL, NULL);
		dl_load(&narrow, narrow_name, 1);
#endif
	}

	/* Step 5: every pre-kernel cross-check of the selected backend. */
#ifdef DASHLOCK_BACKEND_LANDLOCK
	dl_landlock_check(&base, narrow_name != NULL ? &narrow : NULL);
#else
	dl_unveil_check(&base);
#endif

	/* Step 6: kernel mode, the running kernel's judgment. */
	if (mode_kernel) {
#ifdef DASHLOCK_BACKEND_LANDLOCK
		int abi = dl_abi();

		printf("kernel landlock ABI %d\n", abi);
		printf("%s: required ABI %d, abi-min %d, abi-max %s%d\n",
		       base.source, dl_required_abi(&base), base.abi_floor,
		       base.abi_max != 0 ? "" : "none", base.abi_max);
		if (narrow_name != NULL)
			printf("%s: required ABI %d, abi-min %d, abi-max "
			       "%s%d\n", narrow.source,
			       dl_required_abi(&narrow), narrow.abi_floor,
			       narrow.abi_max != 0 ? "" : "none",
			       narrow.abi_max);
		fflush(stdout);
		dl_landlock_ceiling_check(&base, abi);
		if (narrow_name != NULL)
			dl_landlock_ceiling_check(&narrow, abi);
		dl_landlock_required_check(&base, abi);
		if (narrow_name != NULL)
			dl_landlock_required_check(&narrow, abi);
		printf("the judgment holds for this kernel only\n");
#else
		printf("backend unveil: no kernel version gate; abi-min and "
		       "abi-max are read without effect\n");
#endif
	}

	/* Step 7: dump mode, both policies as separate normalized blocks. */
	if (mode_dump) {
		check_dump(&base, "policy");
		if (narrow_name != NULL) {
			printf("\n");
			check_dump(&narrow, "narrow");
		}
	}

	/* Step 8: advisory lints, stderr only. */
	if (lints) {
		check_lint(&base, home, is_account);
		if (narrow_name != NULL)
			check_lint(&narrow, home, is_account);
	}

	/* Step 9: it would apply. */
	if (!quiet && !mode_dump)
		printf("%s would apply (checked as uid %lu, backend %s%s)\n",
		       base.source, (unsigned long)getuid(), check_backend(),
		       is_account ? "" : ", key not a local account");
	free(home);
	free(base.content);
	free(narrow.content);
	return 0;
}

/*
 * Layer 1: parse-policy, its cross-checks, the backend contract, and
 * compute-required-abi, without a kernel and without a filesystem.
 *
 * One table row per negative example of the specification: the row runs
 * dl_parse (and the backend's pre-kernel checks) on an in-memory policy in
 * a forked child, and the parent asserts the exit status 78 and the exact
 * refusal message the specification names.  Positive rows assert exit 0
 * and, on the Landlock backend, the required ABI the policy derives.
 *
 * Built once per backend by tests/Makefile.am; rows carry the backend they
 * apply to.  Output is TAP; the exit status is what the automake test
 * driver reads.
 */

#include <stdio.h>
#include <sys/wait.h>

#include "dashlock.c"

#ifdef DASHLOCK_BACKEND_UNVEIL
#include "unveil_stubs.h"
#endif

#define BE_ANY      0
#define BE_LANDLOCK 1
#define BE_UNVEIL   2

#ifdef DASHLOCK_BACKEND_LANDLOCK
#define BE_THIS BE_LANDLOCK
#else
#define BE_THIS BE_UNVEIL
#endif

struct row {
	const char *name;
	int backend;		/* BE_ANY, BE_LANDLOCK, BE_UNVEIL */
	const char *content;	/* the policy text */
	int exit_code;		/* 0 or 78 */
	const char *message;	/* substring of stderr, or NULL */
	int required_abi;	/* landlock, positive rows: expected value, 0 = skip */
};

static const struct row rows[] = {
	/* Positive rows, one per grammar element. */
	{ "wildcard fs with rules", BE_ANY,
	  "access fs\nrule path-beneath:read-file,read-dir:/etc\n", 0, NULL, 1 },
	{ "abi-min raises the requirement", BE_LANDLOCK,
	  "abi-min 3\naccess fs\nrule path-beneath:read-file:/etc\n", 0, NULL, 3 },
	{ "truncate needs ABI 3", BE_LANDLOCK,
	  "access fs:truncate\nrule path-beneath:truncate:/tmp\n", 0, NULL, 3 },
	{ "ioctl-dev needs ABI 5", BE_LANDLOCK,
	  "access fs:ioctl-dev\nrule path-beneath:ioctl-dev:/dev/tty\n", 0, NULL, 5 },
	{ "scope needs ABI 6", BE_LANDLOCK,
	  "access fs\nscope signal\n", 0, NULL, 6 },
	/* Review finding 1: the network wildcard must raise the requirement
	 * to 4, so a kernel below 4 refuses instead of applying with the
	 * network portion dropped. */
	{ "regression: network wildcard requires ABI 4", BE_LANDLOCK,
	  "access fs\naccess net-tcp\n", 0, NULL, 4 },
	{ "net-port rule within handled set", BE_LANDLOCK,
	  "access net-tcp:bind-tcp\nrule net-port:bind-tcp:8080\n", 0, NULL, 4 },
	{ "bind-tcp port 0 is valid", BE_LANDLOCK,
	  "access net-tcp:bind-tcp\nrule net-port:bind-tcp:0\n", 0, NULL, 4 },
	{ "pledge union across lines parses", BE_UNVEIL,
	  "access fs\npledge stdio rpath\npledge exec\n", 0, NULL, 0 },
	{ "comments and blank lines", BE_ANY,
	  "# comment\n\n  # indented comment\naccess fs\nrule path-beneath:execute:/usr\n",
	  0, NULL, 1 },
	{ "unveil: mixed ioctl-dev rule ports as rw", BE_UNVEIL,
	  "access fs\nrule path-beneath:read-file,write-file,ioctl-dev:/dev/tty\n",
	  0, NULL, 0 },

	/* Negative rows: parse-policy ERRORS, in the specification's order. */
	{ "invalid abi-min", BE_ANY, "abi-min x\naccess fs\n", 78,
	  "invalid abi-min in test", 0 },
	{ "invalid abi-max", BE_ANY, "abi-max 0\naccess fs\n", 78,
	  "invalid abi-max in test", 0 },
	{ "abi-max below abi-min", BE_ANY, "abi-min 6\nabi-max 5\naccess fs\n", 78,
	  "abi-max below abi-min in test", 0 },
	{ "unknown access name", BE_ANY, "access fs:read-everything\n", 78,
	  "unknown access name read-everything in test", 0 },
	{ "unknown scope name", BE_ANY, "access fs\nscope ptrace\n", 78,
	  "unknown scope name ptrace in test", 0 },
	{ "pledge without promises", BE_ANY, "access fs\npledge\n", 78,
	  "pledge without promises in test", 0 },
	{ "unknown promise name", BE_ANY, "access fs\npledge stdio tmppath\n", 78,
	  "unknown promise name tmppath in test", 0 },
	{ "unknown rule type", BE_ANY, "access fs\nrule path-above:read-file:/etc\n", 78,
	  "unknown rule type path-above in test", 0 },
	{ "unknown directive", BE_ANY, "allow fs\n", 78,
	  "unknown directive allow in test", 0 },
	{ "malformed rule: missing path", BE_ANY, "access fs\nrule path-beneath:read-file\n", 78,
	  "malformed rule in test", 0 },
	{ "rule path must be absolute", BE_ANY, "access fs\nrule path-beneath:read-file:etc\n", 78,
	  "rule path must be absolute in test", 0 },
	{ "invalid port", BE_ANY, "access net-tcp\nrule net-port:bind-tcp:70000\n", 78,
	  "invalid port in test", 0 },
	{ "port 0 only for bind-tcp", BE_ANY, "access net-tcp\nrule net-port:connect-tcp:0\n", 78,
	  "port 0 is only valid for bind-tcp in test", 0 },
	{ "handles no access", BE_ANY, "# nothing\n", 78,
	  "test handles no access", 0 },
	{ "pledge-only handles no access", BE_ANY, "pledge stdio\n", 78,
	  "test handles no access", 0 },
	{ "rule uses access not handled", BE_ANY,
	  "access fs:read-file\nrule path-beneath:write-file:/tmp\n", 78,
	  "rule for /tmp uses access not handled in test", 0 },
	{ "net rule uses access not handled", BE_ANY,
	  "access net-tcp:bind-tcp\nrule net-port:connect-tcp:443\n", 78,
	  "rule for port 443 uses access not handled in test", 0 },

	/* The backend contract (enforce-policy), pre-kernel part. */
	{ "landlock refuses the pledge directive", BE_LANDLOCK,
	  "access fs\nrule path-beneath:read-file:/etc\npledge stdio\n", 78,
	  "backend cannot enforce pledge in test", 0 },
	{ "unveil refuses the network category", BE_UNVEIL,
	  "access net-tcp\n", 78,
	  "backend cannot enforce access net-tcp in test", 0 },
	{ "unveil refuses scope", BE_UNVEIL,
	  "access fs\nscope signal\n", 78,
	  "backend cannot enforce scope in test", 0 },
	{ "unveil refuses a partial fs category", BE_UNVEIL,
	  "access fs:read-file\nrule path-beneath:read-file:/tmp\n", 78,
	  "backend cannot enforce access fs:read-file in test", 0 },
	{ "unveil refuses a rule mapping to nothing", BE_UNVEIL,
	  "access fs\nrule path-beneath:ioctl-dev:/dev/tty\n", 78,
	  "rule for /dev/tty grants nothing this backend mediates", 0 },
	{ NULL, 0, NULL, 0, NULL, 0 }
};

/*
 * Run one row in a child: parse, then the backend's pre-kernel checks.
 * The child writes the derived ABI on fd 3 for positive landlock rows.
 */
static void
run_child(const struct row *r, int errfd, int abifd)
{
	static struct dl_policy pol;

	dup2(errfd, 2);
	memset(&pol, 0, sizeof(pol));
	pol.abi_floor = 1;
	strcpy(pol.source, "test");
	pol.content = strdup(r->content);
	dl_parse(&pol);
#ifdef DASHLOCK_BACKEND_LANDLOCK
	dl_landlock_check(&pol, NULL);
	{
		char num[16];

		dl_utoa((unsigned long)dl_required_abi(&pol), num, sizeof(num));
		if (write(abifd, num, strlen(num)) < 0)
			_exit(99);
	}
#else
	(void)abifd;
	dl_unveil_check(&pol);
#endif
	_exit(0);
}

/* Read a descriptor to EOF; the refusal line arrives in several writes. */
static void
read_all(int fd, char *buf, size_t len)
{
	size_t n = 0;
	ssize_t got;

	while (n < len - 1 && (got = read(fd, buf + n, len - 1 - n)) > 0)
		n += (size_t)got;
	buf[n] = '\0';
}

int
main(void)
{
	int n = 0, failed = 0, i;

	for (i = 0; rows[i].name != NULL; i++)
		n++;
	printf("1..%d\n", n);

	for (i = 0; rows[i].name != NULL; i++) {
		const struct row *r = &rows[i];
		int ep[2], ap[2], status, code;
		char err[1024], abi[16];
		pid_t pid;

		if (r->backend != BE_ANY && r->backend != BE_THIS) {
			printf("ok %d - %s # SKIP other backend\n", i + 1, r->name);
			continue;
		}
		if (pipe(ep) != 0 || pipe(ap) != 0) {
			printf("not ok %d - %s # pipe failed\n", i + 1, r->name);
			failed++;
			continue;
		}
		pid = fork();
		if (pid == 0) {
			close(ep[0]);
			close(ap[0]);
			run_child(r, ep[1], ap[1]);
		}
		close(ep[1]);
		close(ap[1]);
		read_all(ep[0], err, sizeof(err));
		read_all(ap[0], abi, sizeof(abi));
		close(ep[0]);
		close(ap[0]);
		waitpid(pid, &status, 0);
		code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

		if (code != r->exit_code) {
			printf("not ok %d - %s # exit %d, expected %d: %s",
			       i + 1, r->name, code, r->exit_code,
			       err[0] ? err : "(no message)\n");
			failed++;
			continue;
		}
		if (r->message != NULL && strstr(err, r->message) == NULL) {
			printf("not ok %d - %s # message '%s' not in: %s",
			       i + 1, r->name, r->message,
			       err[0] ? err : "(no message)\n");
			failed++;
			continue;
		}
		if (BE_THIS == BE_LANDLOCK && r->exit_code == 0 &&
		    r->required_abi != 0 && atoi(abi) != r->required_abi) {
			printf("not ok %d - %s # required ABI %s, expected %d\n",
			       i + 1, r->name, abi, r->required_abi);
			failed++;
			continue;
		}
		printf("ok %d - %s\n", i + 1, r->name);
	}
	return failed ? 1 : 0;
}

/*
 * Layer 2: the Landlock enforcement sequence, asserted through the test
 * seams of dashlock.c without privilege and without a Landlock kernel.
 *
 * DL_SYSCALL is routed to a recorder: the Landlock system calls are logged
 * and answered by a fake kernel whose ABI the scenario chooses, openat2 is
 * passed through to the real kernel so that rule paths are resolved for
 * real, and everything else passes through unchanged.  Each scenario runs
 * dl_apply (and dl_abi) in a forked child, which writes the log to a
 * pipe; the parent asserts the sequence, the attribute size per ABI
 * branch, the handled masks after wildcard expansion, and that no
 * restrict call follows a failed add.  Output is TAP.
 */

#include <stdio.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/syscall.h>

static long test_syscall(long nr, ...);
static int test_prctl(int option, ...);

#define DL_SYSCALL test_syscall
#define DL_PRCTL test_prctl

#include "dashlock.c"

/* Scenario knobs, set by the child before it runs the policy. */
static int test_abi = 6;		/* what the fake kernel reports */
static int fail_add_at = 0;		/* 1-based add_rule call to fail, 0 = none */
static int add_calls;
static int logfd = -1;

static void
rec(const char *fmt, ...)
{
	char line[256];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (n > 0 && logfd >= 0 && write(logfd, line, (size_t)n) < 0)
		_exit(99);
}

static long
test_syscall(long nr, ...)
{
	va_list ap;
	long a1, a2, a3, a4;

	va_start(ap, nr);
	a1 = va_arg(ap, long);
	a2 = va_arg(ap, long);
	a3 = va_arg(ap, long);
	a4 = va_arg(ap, long);
	va_end(ap);

	if (nr == __NR_landlock_create_ruleset) {
		const struct dl_ruleset_attr *attr = (const void *)a1;
		size_t size = (size_t)a2;
		uint32_t flags = (uint32_t)a3;

		if (attr == NULL && flags == DL_CREATE_RULESET_VERSION)
			return test_abi;
		rec("create size=%zu fs=%llx net=%llx scoped=%llx\n", size,
		    (unsigned long long)attr->handled_access_fs,
		    size >= offsetof(struct dl_ruleset_attr, scoped) ?
		    (unsigned long long)attr->handled_access_net : 0ULL,
		    size >= sizeof(*attr) ?
		    (unsigned long long)attr->scoped : 0ULL);
		return 100;	/* a fake ruleset descriptor */
	}
	if (nr == __NR_landlock_add_rule) {
		int type = (int)a2;

		add_calls++;
		if (fail_add_at == add_calls) {
			errno = EINVAL;
			return -1;
		}
		if (type == DL_RULE_PATH_BENEATH) {
			const struct dl_path_beneath_attr *pb = (const void *)a3;

			rec("add path access=%llx parent_fd=%d\n",
			    (unsigned long long)pb->allowed_access,
			    (int)pb->parent_fd);
		} else {
			const struct dl_net_port_attr *np = (const void *)a3;

			rec("add port access=%llx port=%llu\n",
			    (unsigned long long)np->allowed_access,
			    (unsigned long long)np->port);
		}
		return 0;
	}
	if (nr == __NR_landlock_restrict_self) {
		rec("restrict fd=%d\n", (int)a1);
		return 0;
	}
	return syscall(nr, a1, a2, a3, a4);
}

static int
test_prctl(int option, ...)
{
	rec("prctl option=%d\n", option);
	return 0;
}

struct scenario {
	const char *name;
	const char *content;	/* base policy */
	const char *narrow;	/* second layer, or NULL */
	int abi;
	int fail_add;
	int exit_code;
	const char *message;	/* expected in stderr when refusing */
	const char *log;	/* expected log, exactly, with parent fds masked */
};

/*
 * parent_fd values vary per run and are masked to "N" before comparison,
 * so the expected log writes them as N.
 */
static const struct scenario scenarios[] = {
	{ "ABI 6: 24-byte attribute, wildcard expands to all 16 rights, scope kept",
	  "access fs\nscope signal\n"
	  "rule path-beneath:execute,read-file,read-dir:/usr\n"
	  "rule path-beneath:read-file:/etc\n",
	  NULL, 6, 0, 0, NULL,
	  "create size=24 fs=ffff net=0 scoped=2\n"
	  "add path access=d parent_fd=N\n"
	  "add path access=4 parent_fd=N\n"
	  "restrict fd=100\n" },
	{ "ABI 4: 16-byte attribute, fs mask stops at ABI-4 rights, net handled",
	  "access fs\naccess net-tcp\nrule net-port:bind-tcp:8080\n",
	  NULL, 4, 0, 0, NULL,
	  "create size=16 fs=7fff net=3 scoped=0\n"
	  "add port access=1 port=8080\n"
	  "restrict fd=100\n" },
	{ "ABI 3: 8-byte attribute, refer and truncate within the mask",
	  "access fs\nrule path-beneath:read-file:/etc\n",
	  NULL, 3, 0, 0, NULL,
	  "create size=8 fs=7fff net=0 scoped=0\n"
	  "add path access=4 parent_fd=N\n"
	  "restrict fd=100\n" },
	{ "ABI 1: wildcard masks out refer and truncate",
	  "access fs\nrule path-beneath:read-file:/etc\n",
	  NULL, 1, 0, 0, NULL,
	  "create size=8 fs=1fff net=0 scoped=0\n"
	  "add path access=4 parent_fd=N\n"
	  "restrict fd=100\n" },
	{ "explicit subset is not widened by the ABI mask",
	  "access fs:read-file,write-file\nrule path-beneath:read-file:/etc\n",
	  NULL, 6, 0, 0, NULL,
	  "create size=24 fs=6 net=0 scoped=0\n"
	  "add path access=4 parent_fd=N\n"
	  "restrict fd=100\n" },
	{ "failed add_rule refuses and never restricts",
	  "access fs\nrule path-beneath:read-file:/etc\n"
	  "rule path-beneath:read-file:/usr\n",
	  NULL, 6, 2, 78, "cannot add rule for /usr",
	  "create size=24 fs=ffff net=0 scoped=0\n"
	  "add path access=4 parent_fd=N\n" },
	{ "a symbolic-link rule path refuses before any add",
	  "access fs\nrule path-beneath:read-file:/tmp/t_sequence_link\n",
	  NULL, 6, 0, 78, "cannot open rule path /tmp/t_sequence_link",
	  "create size=24 fs=ffff net=0 scoped=0\n" },
	{ "narrowing applies a second layer after the first",
	  "access fs\nrule path-beneath:read-file:/etc\n",
	  "access fs\nrule path-beneath:read-file:/etc/hosts\n",
	  6, 0, 0, NULL,
	  "create size=24 fs=ffff net=0 scoped=0\n"
	  "add path access=4 parent_fd=N\n"
	  "restrict fd=100\n"
	  "create size=24 fs=ffff net=0 scoped=0\n"
	  "add path access=4 parent_fd=N\n"
	  "restrict fd=100\n" },
	{ NULL, NULL, NULL, 0, 0, 0, NULL, NULL }
};

static void
load_mem(struct dl_policy *pol, const char *content, const char *source)
{
	memset(pol, 0, sizeof(*pol));
	pol->abi_floor = 1;
	strcpy(pol->source, source);
	pol->content = strdup(content);
	dl_parse(pol);
}

static void
run_child(const struct scenario *s, int errfd, int lfd)
{
	static struct dl_policy base, narrow;

	dup2(errfd, 2);
	logfd = lfd;
	test_abi = s->abi;
	fail_add_at = s->fail_add;
	load_mem(&base, s->content, "base");
	dl_apply(&base);
	if (s->narrow != NULL) {
		load_mem(&narrow, s->narrow, "narrow");
		dl_apply(&narrow);
	}
	_exit(0);
}

static void
read_all(int fd, char *buf, size_t len)
{
	size_t n = 0;
	ssize_t got;

	while (n < len - 1 && (got = read(fd, buf + n, len - 1 - n)) > 0)
		n += (size_t)got;
	buf[n] = '\0';
}

/* Replace every "parent_fd=<digits>" with "parent_fd=N" in place. */
static void
mask_fds(char *s)
{
	char *p;

	while ((p = strstr(s, "parent_fd=")) != NULL) {
		char *d = p + strlen("parent_fd=");
		char *e = d;

		while (*e >= '0' && *e <= '9')
			e++;
		*d = 'N';
		memmove(d + 1, e, strlen(e) + 1);
		s = d + 1;
	}
}

int
main(void)
{
	int n = 0, failed = 0, i;

	for (i = 0; scenarios[i].name != NULL; i++)
		n++;
	printf("1..%d\n", n);
	unlink("/tmp/t_sequence_link");
	if (symlink("/etc", "/tmp/t_sequence_link") != 0) {
		printf("Bail out! cannot create the symbolic-link fixture\n");
		return 99;
	}

	for (i = 0; scenarios[i].name != NULL; i++) {
		const struct scenario *s = &scenarios[i];
		int ep[2], lp[2], status, code;
		char err[1024], log[2048];
		pid_t pid;

		if (pipe(ep) != 0 || pipe(lp) != 0) {
			printf("not ok %d - %s # pipe failed\n", i + 1, s->name);
			failed++;
			continue;
		}
		pid = fork();
		if (pid == 0) {
			close(ep[0]);
			close(lp[0]);
			run_child(s, ep[1], lp[1]);
		}
		close(ep[1]);
		close(lp[1]);
		read_all(ep[0], err, sizeof(err));
		read_all(lp[0], log, sizeof(log));
		close(ep[0]);
		close(lp[0]);
		waitpid(pid, &status, 0);
		code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		mask_fds(log);

		if (code != s->exit_code) {
			printf("not ok %d - %s # exit %d, expected %d: %s",
			       i + 1, s->name, code, s->exit_code,
			       err[0] ? err : "(no message)\n");
			failed++;
		} else if (s->message != NULL && strstr(err, s->message) == NULL) {
			printf("not ok %d - %s # message '%s' not in: %s",
			       i + 1, s->name, s->message, err);
			failed++;
		} else if (strcmp(log, s->log) != 0) {
			printf("not ok %d - %s # sequence differs\n# got:\n%s# expected:\n%s",
			       i + 1, s->name, log, s->log);
			failed++;
		} else
			printf("ok %d - %s\n", i + 1, s->name);
	}
	unlink("/tmp/t_sequence_link");
	return failed ? 1 : 0;
}

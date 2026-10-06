/*
 * Layer 5: the unveil enforcement sequence, asserted with recording
 * stand-ins for unveil(2) and pledge(2).  Runs on any host: the sequence,
 * the class strings, the working directory each call is issued from (the
 * pinned parent), the lock, and the execpromises string are what this
 * checks; the kernel's own behavior is Layer 4 on OpenBSD.
 *
 * Builds the unveil backend regardless of the configured one.  Each
 * scenario runs dl_unveil_apply in a forked child against real paths;
 * the child's log goes to a pipe and the parent compares.  Output is TAP.
 */

#include <stdio.h>
#include <stdarg.h>
#include <sys/wait.h>

#undef DASHLOCK_BACKEND_LANDLOCK
#define DASHLOCK_BACKEND_UNVEIL 1

#include "dashlock.c"

static int logfd = -1;

static void
rec(const char *fmt, ...)
{
	char line[512];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (n > 0 && logfd >= 0 && write(logfd, line, (size_t)n) < 0)
		_exit(99);
}

int
unveil(const char *path, const char *permissions)
{
	char cwd[DL_PATH_MAX];

	if (path == NULL && permissions == NULL) {
		rec("lock\n");
		return 0;
	}
	if (getcwd(cwd, sizeof(cwd)) == NULL)
		strcpy(cwd, "?");
	rec("unveil %s %s cwd=%s\n", path, permissions, cwd);
	return 0;
}

int
pledge(const char *promises, const char *execpromises)
{
	rec("pledge %s | %s\n", promises != NULL ? promises : "NULL",
	    execpromises != NULL ? execpromises : "NULL");
	return 0;
}

struct scenario {
	const char *name;
	const char *content;
	int exit_code;
	const char *message;
	const char *log;	/* expected log prefix; "" means no call at all */
};

static const char all_promises[] =
	"audio bpf chown cpath disklabel dns dpath drm error exec fattr flock "
	"getpw id inet mcast pf proc prot_exec ps recvfd route rpath sendfd "
	"settime stdio tape tty unix unveil video vminfo vmm wpath wroute";

static const struct scenario scenarios[] = {
	{ "order, classes, pinned parents, lock, policy promises",
	  "access fs\n"
	  "rule path-beneath:execute,read-file,read-dir:/usr\n"
	  "rule path-beneath:read-file,write-file,truncate:/tmp\n"
	  "rule path-beneath:read-file,write-file,ioctl-dev:/dev/null\n"
	  "pledge stdio rpath exec\n",
	  0, NULL,
	  "unveil usr rx cwd=/\n"
	  "unveil tmp rw cwd=/\n"
	  "unveil null rw cwd=/dev\n"
	  "lock\n"
	  "pledge NULL | exec rpath stdio\n" },
	{ "default promises are every known promise, 35 names",
	  "access fs\nrule path-beneath:read-file,read-dir:/etc\n",
	  0, NULL,
	  "unveil etc r cwd=/\n"
	  "lock\n"
	  "pledge NULL | " },	/* prefix; the full string is checked below */
	{ "the root directory is unveiled as / with no directory change",
	  "access fs\nrule path-beneath:read-file,read-dir:/\n",
	  0, NULL,
	  "unveil / r cwd=" },	/* prefix; cwd is wherever the test runs */
	{ "all make, remove and refer rights map to c",
	  "access fs\nrule path-beneath:make-reg,make-dir,make-sock,make-fifo,"
	  "make-char,make-block,make-sym,remove-file,remove-dir,refer:/tmp\n",
	  0, NULL,
	  "unveil tmp c cwd=/\n"
	  "lock\n"
	  "pledge NULL | " },
	{ "a symbolic-link leaf refuses before any unveil",
	  "access fs\nrule path-beneath:read-file:/tmp/t_unveil_link\n",
	  78, "cannot open rule path /tmp/t_unveil_link (errno 40)", "" },
	{ "a missing path refuses before any unveil",
	  "access fs\nrule path-beneath:read-file:/no/such/dir\n",
	  78, "cannot open rule path /no/such/dir (errno 2)", "" },
	{ "every path is verified before the first unveil",
	  "access fs\nrule path-beneath:read-file,read-dir:/etc\n"
	  "rule path-beneath:read-file:/no/such/dir\n",
	  78, "cannot open rule path /no/such/dir", "" },
	{ NULL, NULL, 0, NULL, NULL }
};

static void
run_child(const struct scenario *s, int errfd, int lfd)
{
	static struct dl_policy pol;
	char cwd_before[DL_PATH_MAX], cwd_after[DL_PATH_MAX];

	dup2(errfd, 2);
	logfd = lfd;
	memset(&pol, 0, sizeof(pol));
	pol.abi_floor = 1;
	strcpy(pol.source, "test");
	pol.content = strdup(s->content);
	dl_parse(&pol);
	if (getcwd(cwd_before, sizeof(cwd_before)) == NULL)
		_exit(99);
	dl_unveil_apply(&pol);
	if (getcwd(cwd_after, sizeof(cwd_after)) == NULL)
		_exit(99);
	if (strcmp(cwd_before, cwd_after) != 0) {
		rec("CWD NOT RESTORED: %s -> %s\n", cwd_before, cwd_after);
		_exit(98);
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

int
main(void)
{
	int n = 0, failed = 0, i;

	for (i = 0; scenarios[i].name != NULL; i++)
		n++;
	printf("1..%d\n", n);
	unlink("/tmp/t_unveil_link");
	if (symlink("/etc", "/tmp/t_unveil_link") != 0) {
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

		if (code != s->exit_code) {
			printf("not ok %d - %s # exit %d, expected %d: %s%s",
			       i + 1, s->name, code, s->exit_code,
			       err[0] ? err : "(no message)\n", log);
			failed++;
		} else if (s->message != NULL && strstr(err, s->message) == NULL) {
			printf("not ok %d - %s # message '%s' not in: %s",
			       i + 1, s->name, s->message, err);
			failed++;
		} else if (s->log[0] == '\0' ? log[0] != '\0' :
		   strncmp(log, s->log, strlen(s->log)) != 0) {
			printf("not ok %d - %s # sequence differs\n# got:\n%s# expected:\n%s",
			       i + 1, s->name, log, s->log);
			failed++;
		} else if (i == 1 && strstr(log, all_promises) == NULL) {
			printf("not ok %d - %s # default promise string differs:\n%s",
			       i + 1, s->name, log);
			failed++;
		} else
			printf("ok %d - %s\n", i + 1, s->name);
	}
	unlink("/tmp/t_unveil_link");
	return failed ? 1 : 0;
}

/*
 * Run a command as another account: t_asuser UID GID command [args...]
 *
 * The on-kernel tests need to start the shell as an unprivileged account
 * from a root test run.  setpriv(1) is Linux-only, su(1) differs between
 * systems and refuses accounts whose shell is nologin, and doas may ask
 * for a password; this helper does the one thing needed, portably:
 * drop the supplementary groups, set the gid, set the uid, exec.
 */
#include <sys/types.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	uid_t uid;
	gid_t gid;

	if (argc < 4) {
		fprintf(stderr, "usage: t_asuser uid gid command [args...]\n");
		return 2;
	}
	uid = (uid_t)strtoul(argv[1], NULL, 10);
	gid = (gid_t)strtoul(argv[2], NULL, 10);
	if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0) {
		perror("t_asuser: cannot drop privileges");
		return 2;
	}
	if (getuid() != uid || geteuid() != uid) {
		fprintf(stderr, "t_asuser: privileges not dropped\n");
		return 2;
	}
	execvp(argv[3], argv + 3);
	perror(argv[3]);
	return 126;
}

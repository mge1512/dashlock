/*
 * dashlock.c - Landlock self-confinement for dash.
 *
 * Copyright (c) 2026 Matthias G. Eckermann.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Implements dashlock.spec.md, version 0.6.0.  The enforcement backend is
 * selected at build time: DASHLOCK_BACKEND_LANDLOCK (Linux) or
 * DASHLOCK_BACKEND_UNVEIL (OpenBSD), exactly one per build.
 *
 * Deliberate properties of this file, each of which is a requirement rather
 * than a style choice:
 *
 *   - It includes no shell header.  main.h redefines errno as (*dash_errno)
 *     and dash_errno is assigned inside main(), so shell headers are unusable
 *     on this code path.
 *   - It uses no stdio.  Diagnostics go to file descriptor 2 through write(2),
 *     because the shell output layer is not initialised yet.
 *   - The Landlock backend defines every constant, structure and system
 *     call number itself.  The uapi header on the build host may predate
 *     the constants used here, and the structure passed to the kernel is
 *     size-tagged, so relying on the header layout would be wrong in both
 *     directions.
 *   - Every failure path terminates.  There is no code path that applies part
 *     of a policy and continues.
 */

/*
 * Build contract: dash injects the generated configuration header into every
 * translation unit from src/Makefile.am,
 *
 *     AM_CPPFLAGS = -include $(top_builddir)/config.h $(COMMON_CPPFLAGS)
 *
 * so USE_DASHLOCK, DASHLOCK_NAME_GATE, DASHLOCK_NAME, DASHLOCK_ETCDIR and
 * DASHLOCK_LIBDIR are already defined here without this file including
 * config.h itself.  That matters because this file must not include a shell
 * header (see dashlock.h), and config.h is not a shell header, so including
 * it would also be correct; the -include is simply how dash already does it.
 *
 * The guard below fails the build loudly if that contract is ever broken by a
 * build-system change, rather than silently compiling an inert shell that
 * looks like dashlock and confines nothing.
 */
#if !defined(USE_DASHLOCK) && !defined(DASHLOCK_BUILD_CONTRACT_CHECKED)
#if defined(HAVE_CONFIG_H) || defined(PACKAGE_NAME)
/*
 * The configuration header reached us but USE_DASHLOCK is absent, so the
 * feature really is disabled: compile the inert translation unit.
 */
#else
#error "dashlock.c: no configuration macros visible. dash must inject config.h via AM_CPPFLAGS -include; without it this file would silently compile to nothing."
#endif
#endif

#ifdef USE_DASHLOCK

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_LINUX_LANDLOCK_H
#include <linux/landlock.h>
#endif

#include "dashlock.h"

/*
 * Configuration supplied by configure.  Defaults here only so that the file
 * can be compiled standalone for review.
 */
#ifndef DASHLOCK_NAME
#define DASHLOCK_NAME "dashlock"
#endif
#ifndef DASHLOCK_ETCDIR
#define DASHLOCK_ETCDIR "/etc/dashlock"
#endif
#ifndef DASHLOCK_LIBDIR
#define DASHLOCK_LIBDIR "/usr/lib/dashlock"
#endif

/*
 * Exactly one enforcement backend per build; configure defines it.  For a
 * standalone review compile without the configuration header, default to the
 * Landlock backend so that the historical behavior of such compiles is
 * unchanged.
 */
#if !defined(DASHLOCK_BACKEND_LANDLOCK) && !defined(DASHLOCK_BACKEND_UNVEIL)
#define DASHLOCK_BACKEND_LANDLOCK 1
#endif
#if defined(DASHLOCK_BACKEND_LANDLOCK) && defined(DASHLOCK_BACKEND_UNVEIL)
#error "dashlock.c: exactly one enforcement backend must be selected"
#endif

#ifdef DASHLOCK_BACKEND_LANDLOCK
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

/* ------------------------------------------------------------------ */
/* Access-right bit representation, common to every backend            */
/* ------------------------------------------------------------------ */

/*
 * The bit values equal the Landlock uapi constants and serve as the
 * internal representation of parsed access rights on every backend.  The
 * unveil backend projects them onto its four permission classes at
 * enforcement time (see the PortableClass mapping in the specification);
 * the Landlock backend passes them to the kernel as they are.
 */

#define DL_FS_EXECUTE     (1ULL << 0)
#define DL_FS_WRITE_FILE  (1ULL << 1)
#define DL_FS_READ_FILE   (1ULL << 2)
#define DL_FS_READ_DIR    (1ULL << 3)
#define DL_FS_REMOVE_DIR  (1ULL << 4)
#define DL_FS_REMOVE_FILE (1ULL << 5)
#define DL_FS_MAKE_CHAR   (1ULL << 6)
#define DL_FS_MAKE_DIR    (1ULL << 7)
#define DL_FS_MAKE_REG    (1ULL << 8)
#define DL_FS_MAKE_SOCK   (1ULL << 9)
#define DL_FS_MAKE_FIFO   (1ULL << 10)
#define DL_FS_MAKE_BLOCK  (1ULL << 11)
#define DL_FS_MAKE_SYM    (1ULL << 12)
#define DL_FS_REFER       (1ULL << 13)
#define DL_FS_TRUNCATE    (1ULL << 14)
#define DL_FS_IOCTL_DEV   (1ULL << 15)

#define DL_NET_BIND_TCP    (1ULL << 0)
#define DL_NET_CONNECT_TCP (1ULL << 1)

#define DL_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#define DL_SCOPE_SIGNAL               (1ULL << 1)

#ifndef O_DIRECTORY
#define O_DIRECTORY 0200000
#endif

/*
 * Directory-walk open flags for path verification.  The Landlock backend
 * opens with O_PATH, which needs no read permission on the directory.
 * OpenBSD has no O_PATH; the unveil backend opens the directories for
 * reading, which the policy-directory precondition (root-owned, mode 0755)
 * guarantees for policy paths and which is a documented limitation for
 * rule paths with search-only components.
 */
#ifdef DASHLOCK_BACKEND_LANDLOCK
#define DL_WALK_FLAGS (O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
#else
#define DL_WALK_FLAGS (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
#endif

#ifdef DASHLOCK_BACKEND_LANDLOCK

/* ------------------------------------------------------------------ */
/* Landlock uapi, defined locally.  See the note at the top.           */
/* ------------------------------------------------------------------ */

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif
#ifndef __NR_openat2
#define __NR_openat2 437
#endif

/*
 * openat2(2) with RESOLVE_NO_SYMLINKS is used to open rule paths so that no
 * symbolic-link component is followed during resolution.  A root-authored
 * policy commonly names a path whose leaf the confined account controls,
 * such as a home directory; without this, the account could pre-position a
 * symlink and have the rule attach to a different hierarchy than the
 * administrator reviewed.  The structure and flag are defined locally for
 * the same reason as the Landlock definitions: the build host header may
 * predate them.
 */
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS 0x04
#endif

struct dl_open_how {
	uint64_t flags;
	uint64_t mode;
	uint64_t resolve;
};

static long
dl_sys_openat2(int dirfd, const char *path, struct dl_open_how *how,
	       size_t size)
{
	return syscall(__NR_openat2, dirfd, path, how, size);
}

#ifndef O_PATH
#define O_PATH 010000000
#endif

#define DL_CREATE_RULESET_VERSION (1U << 0)

#define DL_RULE_PATH_BENEATH 1
#define DL_RULE_NET_PORT     2

struct dl_ruleset_attr {
	uint64_t handled_access_fs;	/* ABI 1 */
	uint64_t handled_access_net;	/* ABI 4 */
	uint64_t scoped;		/* ABI 6 */
};

struct dl_path_beneath_attr {
	uint64_t allowed_access;
	int32_t parent_fd;
} __attribute__((packed));

struct dl_net_port_attr {
	uint64_t allowed_access;
	uint64_t port;
};

static long
dl_sys_create(const void *attr, size_t size, uint32_t flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static long
dl_sys_add(int fd, int type, const void *attr, uint32_t flags)
{
	return syscall(__NR_landlock_add_rule, fd, type, attr, flags);
}

static long
dl_sys_restrict(int fd, uint32_t flags)
{
	return syscall(__NR_landlock_restrict_self, fd, flags);
}

#endif /* DASHLOCK_BACKEND_LANDLOCK */

/* ------------------------------------------------------------------ */
/* Limits                                                              */
/* ------------------------------------------------------------------ */

#define DL_FILE_MAX  65536	/* policy file size ceiling */
#define DL_PATH_MAX  4096
#define DL_KEY_MAX   256
#define DL_PATH_RULES_MAX 64
#define DL_NET_RULES_MAX  32
#define DL_PLEDGE_MAX 1024	/* built execpromises string (unveil backend) */

/* ------------------------------------------------------------------ */
/* Name tables.  Names match setpriv(1) from util-linux.               */
/* ------------------------------------------------------------------ */

struct dl_name_bit {
	const char *name;
	uint64_t bit;
	int abi;
};

static const struct dl_name_bit dl_fs_names[] = {
	{ "execute",     DL_FS_EXECUTE,     1 },
	{ "write-file",  DL_FS_WRITE_FILE,  1 },
	{ "read-file",   DL_FS_READ_FILE,   1 },
	{ "read-dir",    DL_FS_READ_DIR,    1 },
	{ "remove-dir",  DL_FS_REMOVE_DIR,  1 },
	{ "remove-file", DL_FS_REMOVE_FILE, 1 },
	{ "make-char",   DL_FS_MAKE_CHAR,   1 },
	{ "make-dir",    DL_FS_MAKE_DIR,    1 },
	{ "make-reg",    DL_FS_MAKE_REG,    1 },
	{ "make-sock",   DL_FS_MAKE_SOCK,   1 },
	{ "make-fifo",   DL_FS_MAKE_FIFO,   1 },
	{ "make-block",  DL_FS_MAKE_BLOCK,  1 },
	{ "make-sym",    DL_FS_MAKE_SYM,    1 },
	{ "refer",       DL_FS_REFER,       2 },
	{ "truncate",    DL_FS_TRUNCATE,    3 },
	{ "ioctl-dev",   DL_FS_IOCTL_DEV,   5 },
	{ NULL,          0,                 0 }
};

static const struct dl_name_bit dl_net_names[] = {
	{ "bind-tcp",    DL_NET_BIND_TCP,    4 },
	{ "connect-tcp", DL_NET_CONNECT_TCP, 4 },
	{ NULL,          0,                  0 }
};

static const struct dl_name_bit dl_scope_names[] = {
	{ "abstract-unix-socket", DL_SCOPE_ABSTRACT_UNIX_SOCKET, 6 },
	{ "signal",               DL_SCOPE_SIGNAL,               6 },
	{ NULL,                   0,                             0 }
};

/*
 * OpenBSD pledge promise names known to this implementation: the state of
 * pledgereq[] in sys/kern/kern_pledge.c, OpenBSD 7.9 and -current as of
 * 2026-09-09.  "tmppath" was removed upstream and is deliberately absent.
 * The table is compiled on every backend, because parse-policy validates
 * pledge directives everywhere; only the unveil backend enforces them.
 * The bit for a name is (1 << index), used in dl_policy.pledge_bits.
 */
static const char *const dl_pledge_names[] = {
	"audio", "bpf", "chown", "cpath", "disklabel", "dns", "dpath",
	"drm", "error", "exec", "fattr", "flock", "getpw", "id", "inet",
	"mcast", "pf", "proc", "prot_exec", "ps", "recvfd", "route",
	"rpath", "sendfd", "settime", "stdio", "tape", "tty", "unix",
	"unveil", "video", "vminfo", "vmm", "wpath", "wroute",
	NULL
};

/* ------------------------------------------------------------------ */
/* Policy representation                                               */
/* ------------------------------------------------------------------ */

struct dl_path_rule {
	uint64_t access;
	const char *path;	/* points into struct dl_policy.content */
};

struct dl_net_rule {
	uint64_t access;
	unsigned int port;
};

struct dl_policy {
	uint64_t handled_fs;
	uint64_t handled_net;
	uint64_t scoped;
	int abi_max;		/* 0 = no ceiling; else refuse a newer kernel */
	/*
	 * "access fs" and "access net-tcp" mean "every right the running
	 * kernel supports".  They are recorded here and expanded in dl_apply,
	 * not during parsing.  Expanding during parsing would query the
	 * kernel ABI before the parser has finished, so a malformed line
	 * later in the file would be reported as an ABI problem.  By
	 * definition a wildcard cannot raise the ABI a policy requires.
	 */
	int want_all_fs;
	int want_all_net;
	int abi_floor;
	uint64_t pledge_bits;	/* bit (1 << i) set: dl_pledge_names[i] */
	int have_pledge;	/* a pledge directive was present */
	int npath;
	int nnet;
	struct dl_path_rule path_rules[DL_PATH_RULES_MAX];
	struct dl_net_rule net_rules[DL_NET_RULES_MAX];
	char *content;		/* owns the storage the paths point into */
	char source[DL_PATH_MAX];
};

/* ------------------------------------------------------------------ */
/* Diagnostics                                                         */
/* ------------------------------------------------------------------ */

static void
dl_write(const char *s)
{
	size_t n;

	if (s == NULL)
		return;
	n = strlen(s);
	while (n > 0) {
		ssize_t w = write(2, s, n);

		if (w <= 0)
			return;
		s += w;
		n -= (size_t)w;
	}
}

/*
 * Every refusal ends here.  A NULL-terminated piece list rather than a format
 * string, so that a message can name both the offending token and the file it
 * came from without any formatting machinery on the startup path.
 */
static void
dl_refusev(const char *const *parts)
{
	int i;

	dl_write("dashlock: ");
	for (i = 0; parts[i] != NULL; i++)
		dl_write(parts[i]);
	dl_write("\n");
	_exit(DASHLOCK_EXIT_CONFIG);
}

static void
dl_refuse(const char *a, const char *b, const char *c)
{
	const char *parts[4];

	parts[0] = a;
	parts[1] = b;
	parts[2] = c;
	parts[3] = NULL;
	dl_refusev(parts);
}

/* ------------------------------------------------------------------ */
/* Small string helpers.  No stdio, no locale.                         */
/* ------------------------------------------------------------------ */

static int
dl_isspace(int c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v';
}

static char *
dl_trim(char *s)
{
	char *e;

	while (*s && dl_isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && dl_isspace((unsigned char)e[-1]))
		e--;
	*e = '\0';
	return s;
}

static void
dl_utoa(unsigned long v, char *out, size_t outlen)
{
	char tmp[32];
	size_t i = 0, j = 0;

	do {
		tmp[i++] = (char)('0' + (v % 10));
		v /= 10;
	} while (v > 0 && i < sizeof(tmp));
	if (i >= outlen)
		i = outlen - 1;
	while (i > 0)
		out[j++] = tmp[--i];
	out[j] = '\0';
}

/*
 * F6: refusals caused by a failed system call carry the errno value, so
 * that "cannot apply policy" from a layer-limit E2BIG is distinguishable
 * from any other failure without a debugger.  Numeric rather than
 * strerror(): no locale machinery on the startup path.
 */
static void
dl_refuse_errno(const char *a, const char *b, int err)
{
	char ebuf[16];
	const char *parts[6];

	dl_utoa((unsigned long)err, ebuf, sizeof(ebuf));
	parts[0] = a;
	parts[1] = (b != NULL) ? b : "";
	parts[2] = " (errno ";
	parts[3] = ebuf;
	parts[4] = ")";
	parts[5] = NULL;
	dl_refusev(parts);
}

/*
 * Concatenate up to three pieces.  Refuses rather than truncating: a
 * truncated policy path would select the wrong file.
 */
static void
dl_join(char *dst, size_t dstlen, const char *a, const char *b, const char *c)
{
	size_t n = 0;
	const char *parts[3];
	int i;

	parts[0] = a;
	parts[1] = b;
	parts[2] = c;
	for (i = 0; i < 3; i++) {
		size_t l;

		if (parts[i] == NULL)
			continue;
		l = strlen(parts[i]);
		if (n + l + 1 > dstlen)
			dl_refuse("policy path too long", NULL, NULL);
		memcpy(dst + n, parts[i], l);
		n += l;
	}
	dst[n] = '\0';
}

/*
 * Split off the next comma-separated field.  Returns NULL when the list is
 * exhausted.  Empty fields are reported as an empty string so that the
 * caller can reject them.
 */
static char *
dl_next_csv(char **listp)
{
	char *s = *listp;
	char *comma;

	if (s == NULL)
		return NULL;
	comma = strchr(s, ',');
	if (comma != NULL) {
		*comma = '\0';
		*listp = comma + 1;
	} else {
		*listp = NULL;
	}
	return dl_trim(s);
}

static const struct dl_name_bit *
dl_lookup(const struct dl_name_bit *table, const char *name)
{
	const struct dl_name_bit *e;

	for (e = table; e->name != NULL; e++)
		if (strcmp(e->name, name) == 0)
			return e;
	return NULL;
}

#ifdef DASHLOCK_BACKEND_LANDLOCK

/* ------------------------------------------------------------------ */
/* Kernel ABI                                                          */
/* ------------------------------------------------------------------ */

static int dl_abi_cache = -1;

/*
 * Query the running Landlock ABI version.  Cached: the value cannot change
 * during the lifetime of the process, and both the parser and the enforcer
 * need it.
 */
static int
dl_abi(void)
{
	long v;

	if (dl_abi_cache > 0)
		return dl_abi_cache;
	v = dl_sys_create(NULL, 0, DL_CREATE_RULESET_VERSION);
	if (v < 1)
		dl_refuse_errno("landlock unavailable: enable it in "
				"CONFIG_LSM or the lsm= boot parameter",
				NULL, errno);
	dl_abi_cache = (int)v;
	return dl_abi_cache;
}

static uint64_t
dl_mask(const struct dl_name_bit *table, int abi)
{
	const struct dl_name_bit *e;
	uint64_t m = 0;

	for (e = table; e->name != NULL; e++)
		if (e->abi <= abi)
			m |= e->bit;
	return m;
}

#endif /* DASHLOCK_BACKEND_LANDLOCK */

/* ------------------------------------------------------------------ */
/* BEHAVIOR/INTERNAL: open-and-validate-policy-file                    */
/* ------------------------------------------------------------------ */

/*
 * Verify a stat result for a policy-path component: owned by root and not
 * writable by group or other.  A correct file inside a directory a non-root
 * account can rename or replace is not a correct file, so every ancestor is
 * held to the same standard as the file.
 */
static void
dl_check_owner_mode(const struct stat *st, const char *what)
{
	if (st->st_uid != 0)
		dl_refuse(what, " is not owned by root", "");
	if ((st->st_mode & (S_IWGRP | S_IWOTH)) != 0)
		dl_refuse(what, " is writable by non-root", "");
}

/*
 * Open a policy file after verifying its entire path from the root with
 * directory descriptors.  Each component is opened with O_NOFOLLOW, so no
 * symbolic link is traversed anywhere in the chain, and each opened
 * component is checked on its descriptor with fstat, so the object that was
 * checked is the object that was traversed.  This closes the gap between a
 * descriptor-checked file and stat-checked ancestors: there is no separate
 * pathname walk, and there is no window in which a component can change
 * between the check and the use.
 *
 * Returns the open file descriptor on success and stores the file's stat in
 * *stp.  Returns -2 when the file is genuinely absent, so that the caller can
 * try a lower-priority candidate.  Every other condition is a refusal.
 *
 * path must be absolute; the caller always builds it that way.
 */
static int
dl_open_verified(const char *path, struct stat *stp)
{
	char buf[DL_PATH_MAX];
	struct stat st;
	size_t n = strlen(path);
	char *p;
	int dirfd;
	int fd;

	if (path[0] != '/')
		dl_refuse(path, " is not absolute", "");
	if (n >= sizeof(buf))
		dl_refuse("policy path too long", NULL, NULL);
	memcpy(buf, path, n + 1);

	/* The root directory itself must be root-owned and not group- or
	 * other-writable; open it with the walk flags and check the
	 * descriptor. */
	dirfd = open("/", DL_WALK_FLAGS);
	if (dirfd < 0)
		dl_refuse_errno("cannot open / for ", path, errno);
	if (fstat(dirfd, &st) != 0) {
		int err = errno;

		close(dirfd);
		dl_refuse_errno("cannot stat / for ", path, err);
	}
	dl_check_owner_mode(&st, "/");

	/*
	 * Walk the components between the leading and trailing slashes.  Each
	 * intermediate component is opened relative to its verified parent
	 * with DL_WALK_FLAGS (O_NOFOLLOW included) and checked on its
	 * descriptor.
	 */
	p = buf + 1;
	for (;;) {
		char *slash = strchr(p, '/');
		const char *component;
		int nextfd;
		int err;

		if (slash == NULL)
			break;			/* p is the final component */
		*slash = '\0';
		if (*p == '\0')		/* empty component, e.g. "//" */
			dl_refuse(path, " has an empty path component", "");

		/*
		 * buf currently holds the path truncated at this component,
		 * so buf names the directory being checked, e.g.
		 * "/etc/dashlock".  This is what the diagnostic should name,
		 * not the full policy-file path.
		 */
		component = buf;

		nextfd = openat(dirfd, p,
				DL_WALK_FLAGS);
		err = errno;
		close(dirfd);
		if (nextfd < 0) {
			if (err == ENOENT)
				return -2;
			dl_refuse_errno("cannot open policy path ", path, err);
		}
		dirfd = nextfd;
		if (fstat(dirfd, &st) != 0) {
			err = errno;
			close(dirfd);
			dl_refuse_errno("cannot stat policy path ", path, err);
		}
		dl_check_owner_mode(&st, component);
		*slash = '/';			/* restore for the next round */
		p = slash + 1;
	}

	if (*p == '\0')			/* trailing slash: a directory */
		dl_refuse(path, " is not a regular file", "");

	/*
	 * Open the final component relative to its verified parent.
	 * O_NOFOLLOW rejects a final symlink; O_NONBLOCK so that a FIFO
	 * cannot block startup before the regular-file check rejects it.
	 */
	{
		int err;

		fd = openat(dirfd, p,
			    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
		err = errno;
		close(dirfd);
		if (fd < 0) {
			if (err == ENOENT)
				return -2;
			dl_refuse_errno("cannot open ", path, err);
		}
	}
	if (fstat(fd, stp) != 0) {
		int err = errno;

		close(fd);
		dl_refuse_errno("cannot stat ", path, err);
	}
	return fd;
}

/*
 * Returns the file content on success, or NULL when the file does not exist
 * so that the caller can try the next candidate.  Every other condition is a
 * refusal: a candidate that exists but fails validation must never be
 * silently replaced by a lower-priority candidate.
 */
static char *
dl_read_policy_file(const char *path)
{
	struct stat st;
	struct stat st2;
	char *buf;
	size_t total = 0;
	int fd;

	fd = dl_open_verified(path, &st);
	if (fd == -2)
		return NULL;

	if (!S_ISREG(st.st_mode)) {
		close(fd);
		dl_refuse(path, " is not a regular file", "");
	}
	dl_check_owner_mode(&st, path);
	if (st.st_size < 0) {
		close(fd);
		dl_refuse(path, " has a negative size", "");
	}
	if (st.st_size > (off_t)DL_FILE_MAX) {
		close(fd);
		dl_refuse(path, " is too large", "");
	}

	/*
	 * Read to end of file rather than to the size observed by fstat, into
	 * a buffer one byte larger than the ceiling.  A policy that changed
	 * under us must not be parsed as a prefix: an omitted suffix can carry
	 * "access net-tcp" or a "scope" directive, so a short read is not
	 * merely a narrower policy, it can be a weaker one.  Reading past the
	 * ceiling by one byte is what detects growth; the file is then
	 * refused as too large.
	 */
	buf = malloc((size_t)DL_FILE_MAX + 1);
	if (buf == NULL) {
		close(fd);
		dl_refuse("out of memory", NULL, NULL);
	}
	for (;;) {
		ssize_t r = read(fd, buf + total, (size_t)DL_FILE_MAX + 1 - total);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			dl_refuse_errno("cannot read ", path, errno);
		}
		if (r == 0)
			break;
		total += (size_t)r;
		if (total > (size_t)DL_FILE_MAX) {
			close(fd);
			dl_refuse(path, " is too large", "");
		}
	}

	/*
	 * Refuse a file whose size changed between the metadata check and the
	 * read, so that a non-atomic administrator update cannot install a
	 * partially written policy.  Policy updates must be atomic: write a
	 * new root-owned file and rename it into place.
	 */
	if (fstat(fd, &st2) != 0) {
		int err = errno;

		close(fd);
		dl_refuse_errno("cannot stat ", path, err);
	}
	if (st2.st_size != (off_t)total || st2.st_ino != st.st_ino ||
	    st2.st_dev != st.st_dev) {
		close(fd);
		dl_refuse(path, " changed while it was being read", "");
	}
	close(fd);
	/*
	 * F9: a NUL byte would silently truncate one line of an allowlist.
	 * Truncation can only narrow, so it is not a widening channel, but a
	 * policy the parser did not see in full must not be applied.
	 */
	if (memchr(buf, '\0', total) != NULL)
		dl_refuse(path, " contains a NUL byte", "");
	buf[total] = '\0';
	return buf;
}

/* ------------------------------------------------------------------ */
/* BEHAVIOR/INTERNAL: parse-policy                                     */
/* ------------------------------------------------------------------ */

static uint64_t
dl_parse_access_list(struct dl_policy *pol, const struct dl_name_bit *table,
		     char *list, const char *what)
{
	const char *parts[7];
	uint64_t bits = 0;
	char *tok;

	parts[0] = "unknown ";
	parts[1] = what;
	parts[2] = " name ";
	parts[4] = " in ";
	parts[5] = pol->source;
	parts[6] = NULL;

	while ((tok = dl_next_csv(&list)) != NULL) {
		const struct dl_name_bit *e;

		if (*tok == '\0') {
			parts[0] = "empty ";
			parts[2] = " name in ";
			parts[3] = pol->source;
			parts[4] = NULL;
			dl_refusev(parts);
		}
		e = dl_lookup(table, tok);
		if (e == NULL) {
			parts[3] = tok;
			dl_refusev(parts);
		}
		bits |= e->bit;
	}
	if (bits == 0) {
		parts[0] = "empty ";
		parts[2] = " list in ";
		parts[3] = pol->source;
		parts[4] = NULL;
		dl_refusev(parts);
	}
	return bits;
}

static unsigned int
dl_parse_port(struct dl_policy *pol, const char *s)
{
	unsigned long v = 0;
	const char *p;

	if (*s == '\0')
		dl_refuse("invalid port in ", pol->source, "");
	for (p = s; *p != '\0'; p++) {
		if (*p < '0' || *p > '9')
			dl_refuse("invalid port in ", pol->source, "");
		v = v * 10 + (unsigned long)(*p - '0');
		if (v > 65535)
			dl_refuse("invalid port in ", pol->source, "");
	}
	/*
	 * Port 0 is meaningful for bind-tcp: it permits bind() with an
	 * ephemeral port.  It is meaningless for connect-tcp.  The value is
	 * accepted here and the bind-only restriction is enforced by the
	 * caller, which has the access set.
	 */
	return (unsigned int)v;
}

static void
dl_parse_rule(struct dl_policy *pol, char *rest)
{
	char *colon = strchr(rest, ':');
	char *type;
	char *arg;

	if (colon == NULL)
		dl_refuse("malformed rule in ", pol->source, "");
	*colon = '\0';
	type = dl_trim(rest);
	arg = colon + 1;

	if (strcmp(type, "path-beneath") == 0) {
		char *sep = strchr(arg, ':');
		char *path;
		uint64_t access;

		/*
		 * Only the first colon after the access list separates the
		 * path, so a path may itself contain colons.
		 */
		if (sep == NULL)
			dl_refuse("malformed rule in ", pol->source, "");
		*sep = '\0';
		path = dl_trim(sep + 1);
		access = dl_parse_access_list(pol, dl_fs_names,
					      dl_trim(arg), "access");
		if (path[0] != '/')
			dl_refuse("rule path must be absolute in ",
				  pol->source, "");
		if (pol->npath >= DL_PATH_RULES_MAX)
			dl_refuse("too many rules in ", pol->source, "");
		pol->path_rules[pol->npath].access = access;
		pol->path_rules[pol->npath].path = path;
		pol->npath++;
		return;
	}

	if (strcmp(type, "net-port") == 0) {
		char *sep = strchr(arg, ':');
		uint64_t access;
		unsigned int port;

		if (sep == NULL)
			dl_refuse("malformed rule in ", pol->source, "");
		*sep = '\0';
		access = dl_parse_access_list(pol, dl_net_names,
					      dl_trim(arg), "access");
		port = dl_parse_port(pol, dl_trim(sep + 1));
		/* Port 0 is only meaningful for bind-tcp. */
		if (port == 0 && (access & DL_NET_CONNECT_TCP) != 0)
			dl_refuse("port 0 is only valid for bind-tcp in ",
				  pol->source, "");
		if (pol->nnet >= DL_NET_RULES_MAX)
			dl_refuse("too many rules in ", pol->source, "");
		pol->net_rules[pol->nnet].access = access;
		pol->net_rules[pol->nnet].port = port;
		pol->nnet++;
		return;
	}

	{
		const char *parts[6];

		parts[0] = "unknown rule type ";
		parts[1] = type;
		parts[2] = " in ";
		parts[3] = pol->source;
		parts[4] = NULL;
		dl_refusev(parts);
	}
}

static void
dl_parse_access(struct dl_policy *pol, char *rest)
{
	const char *parts[6];

	if (strcmp(rest, "fs") == 0) {
		pol->want_all_fs = 1;
		return;
	}
	if (strncmp(rest, "fs:", 3) == 0) {
		pol->handled_fs |= dl_parse_access_list(pol, dl_fs_names,
							rest + 3, "access");
		return;
	}
	if (strcmp(rest, "net-tcp") == 0) {
		pol->want_all_net = 1;
		return;
	}
	if (strncmp(rest, "net-tcp:", 8) == 0) {
		pol->handled_net |= dl_parse_access_list(pol, dl_net_names,
							 rest + 8, "access");
		return;
	}
	parts[0] = "unknown access category ";
	parts[1] = rest;
	parts[2] = " in ";
	parts[3] = pol->source;
	parts[4] = NULL;
	dl_refusev(parts);
}

/*
 * pledge directive: space-separated promise names, validated against
 * dl_pledge_names on every backend so that a typo is caught on the machine
 * where the policy was written, not only on the one where it is enforced.
 * The union across several pledge lines is taken.  Only the unveil backend
 * enforces the result; the Landlock backend refuses the directive at
 * enforcement time, per the backend contract.
 */
static void
dl_parse_pledge(struct dl_policy *pol, char *rest)
{
	char *p = rest;
	int found = 0;

	while (*p != '\0') {
		char *tok = p;
		int i;

		while (*p != '\0' && !dl_isspace((unsigned char)*p))
			p++;
		if (*p != '\0') {
			*p++ = '\0';
			while (*p != '\0' && dl_isspace((unsigned char)*p))
				p++;
		}
		for (i = 0; dl_pledge_names[i] != NULL; i++)
			if (strcmp(dl_pledge_names[i], tok) == 0)
				break;
		if (dl_pledge_names[i] == NULL) {
			const char *parts[6];

			parts[0] = "unknown promise name ";
			parts[1] = tok;
			parts[2] = " in ";
			parts[3] = pol->source;
			parts[4] = NULL;
			dl_refusev(parts);
		}
		pol->pledge_bits |= (uint64_t)1 << i;
		found = 1;
	}
	if (!found)
		dl_refuse("pledge without promises in ", pol->source, "");
	pol->have_pledge = 1;
}

static void
dl_parse_abi_min(struct dl_policy *pol, const char *s)
{
	unsigned long v = 0;
	const char *p;

	if (*s == '\0')
		dl_refuse("invalid abi-min in ", pol->source, "");
	for (p = s; *p != '\0'; p++) {
		if (*p < '0' || *p > '9')
			dl_refuse("invalid abi-min in ", pol->source, "");
		v = v * 10 + (unsigned long)(*p - '0');
		if (v > 255)
			dl_refuse("invalid abi-min in ", pol->source, "");
	}
	if (v < 1)
		dl_refuse("invalid abi-min in ", pol->source, "");
	/* F8: with several abi-min lines the maximum wins; a later line
	 * must not be able to lower an earlier floor. */
	if ((int)v > pol->abi_floor)
		pol->abi_floor = (int)v;
}

/*
 * abi-max caps the kernel ABI the policy is trusted against.  A wildcard
 * category ("access fs") handles every right this build knows; on a future
 * kernel with a new right, that right would be left unhandled and therefore
 * unrestricted.  An author who uses a wildcard can set abi-max to the newest
 * ABI they reviewed, and a newer kernel is then refused rather than silently
 * under-restricting.  With several abi-max lines the minimum wins.
 */
static void
dl_parse_abi_max(struct dl_policy *pol, const char *s)
{
	unsigned long v = 0;
	const char *p;

	if (*s == '\0')
		dl_refuse("invalid abi-max in ", pol->source, "");
	for (p = s; *p != '\0'; p++) {
		if (*p < '0' || *p > '9')
			dl_refuse("invalid abi-max in ", pol->source, "");
		v = v * 10 + (unsigned long)(*p - '0');
		if (v > 255)
			dl_refuse("invalid abi-max in ", pol->source, "");
	}
	if (v < 1)
		dl_refuse("invalid abi-max in ", pol->source, "");
	if (pol->abi_max == 0 || (int)v < pol->abi_max)
		pol->abi_max = (int)v;
}

/*
 * An unknown directive, rule type, access name or scope name is always a
 * refusal and never a skipped line.  Silently ignoring a line the parser
 * does not understand is the standard way a security configuration parser
 * fails open.
 */
static void
dl_parse(struct dl_policy *pol)
{
	char *line = pol->content;

	while (line != NULL) {
		char *next = strchr(line, '\n');
		char *hash;
		char *kw;
		char *rest;

		if (next != NULL)
			*next++ = '\0';
		hash = strchr(line, '#');
		if (hash != NULL)
			*hash = '\0';
		line = dl_trim(line);
		if (*line == '\0') {
			line = next;
			continue;
		}

		kw = line;
		rest = line;
		while (*rest != '\0' && !dl_isspace((unsigned char)*rest))
			rest++;
		if (*rest != '\0') {
			*rest++ = '\0';
			rest = dl_trim(rest);
		}

		if (strcmp(kw, "abi-min") == 0)
			dl_parse_abi_min(pol, rest);
		else if (strcmp(kw, "abi-max") == 0)
			dl_parse_abi_max(pol, rest);
		else if (strcmp(kw, "access") == 0)
			dl_parse_access(pol, rest);
		else if (strcmp(kw, "rule") == 0)
			dl_parse_rule(pol, rest);
		else if (strcmp(kw, "pledge") == 0)
			dl_parse_pledge(pol, rest);
		else if (strcmp(kw, "scope") == 0)
			pol->scoped |= dl_parse_access_list(pol,
							    dl_scope_names,
							    rest, "scope");
		else {
			const char *parts[6];

			parts[0] = "unknown directive ";
			parts[1] = kw;
			parts[2] = " in ";
			parts[3] = pol->source;
			parts[4] = NULL;
			dl_refusev(parts);
		}

		line = next;
	}

	if (pol->handled_fs == 0 && pol->handled_net == 0 &&
	    pol->scoped == 0 && !pol->want_all_fs && !pol->want_all_net)
		dl_refuse(pol->source, " handles no access", "");

	if (pol->abi_max != 0 && pol->abi_max < pol->abi_floor)
		dl_refuse("abi-max below abi-min in ", pol->source, "");

	/*
	 * F7: a rule granting a right the ruleset does not handle would
	 * reach the kernel and fail there with a bare EINVAL.  Refusing at
	 * parse time names the actual mistake.  With the wildcard category
	 * in force every parseable right is handled, and kernel support is
	 * guaranteed separately by the required-ABI check.
	 */
	if (!pol->want_all_fs) {
		int i;

		for (i = 0; i < pol->npath; i++) {
			if ((pol->path_rules[i].access &
			     ~pol->handled_fs) != 0) {
				const char *parts[6];

				parts[0] = "rule for ";
				parts[1] = pol->path_rules[i].path;
				parts[2] = " uses access not handled in ";
				parts[3] = pol->source;
				parts[4] = NULL;
				dl_refusev(parts);
			}
		}
	}
	if (!pol->want_all_net) {
		int i;

		for (i = 0; i < pol->nnet; i++) {
			if ((pol->net_rules[i].access &
			     ~pol->handled_net) != 0) {
				char pbuf[16];
				const char *parts[6];

				dl_utoa(pol->net_rules[i].port, pbuf,
					sizeof(pbuf));
				parts[0] = "rule for port ";
				parts[1] = pbuf;
				parts[2] = " uses access not handled in ";
				parts[3] = pol->source;
				parts[4] = NULL;
				dl_refusev(parts);
			}
		}
	}
}

#ifdef DASHLOCK_BACKEND_LANDLOCK

/* ------------------------------------------------------------------ */
/* BEHAVIOR/INTERNAL: compute-required-abi (landlock backend)          */
/* ------------------------------------------------------------------ */

/*
 * Derived from the directives the file uses; abi-min can only raise it.
 * Deriving rather than trusting a declaration means a policy written for a
 * newer kernel is refused on an older one instead of being applied with
 * parts of it silently dropped.
 */
static int
dl_required_abi(const struct dl_policy *pol)
{
	const struct dl_name_bit *e;
	uint64_t fs = pol->handled_fs;
	int req = pol->abi_floor;
	int i;

	for (i = 0; i < pol->npath; i++)
		fs |= pol->path_rules[i].access;
	for (e = dl_fs_names; e->name != NULL; e++)
		if ((fs & e->bit) != 0 && e->abi > req)
			req = e->abi;
	if (pol->handled_net != 0 || pol->nnet > 0 || pol->want_all_net) {
		if (req < 4)
			req = 4;
	}
	if (pol->scoped != 0) {
		if (req < 6)
			req = 6;
	}
	return req;
}

#endif /* DASHLOCK_BACKEND_LANDLOCK */

/* ------------------------------------------------------------------ */
/* BEHAVIOR/INTERNAL: locate-policy-file                               */
/* ------------------------------------------------------------------ */

static void
dl_load(struct dl_policy *pol, const char *key, int is_narrow)
{
	const char *subdir = is_narrow ? "/narrow/" : "/users/";
	char path[DL_PATH_MAX];
	char *content;
	int i;

	memset(pol, 0, sizeof(*pol));
	pol->abi_floor = 1;

	for (i = 0; i < 4; i++) {
		switch (i) {
		case 0:
			dl_join(path, sizeof(path), DASHLOCK_ETCDIR, subdir,
				key);
			break;
		case 1:
			dl_join(path, sizeof(path), DASHLOCK_LIBDIR, subdir,
				key);
			break;
		case 2:
			if (is_narrow)
				continue;
			dl_join(path, sizeof(path), DASHLOCK_ETCDIR,
				"/users/default", NULL);
			break;
		default:
			if (is_narrow)
				continue;
			dl_join(path, sizeof(path), DASHLOCK_LIBDIR,
				"/users/default", NULL);
			break;
		}
		content = dl_read_policy_file(path);
		if (content != NULL) {
			pol->content = content;
			dl_join(pol->source, sizeof(pol->source), path, NULL,
				NULL);
			dl_parse(pol);
			return;
		}
	}

	if (is_narrow)
		dl_refuse("no narrow policy ", key, "");
	dl_refuse("no policy for user ", key, "");
}

#ifdef DASHLOCK_BACKEND_LANDLOCK

/* ------------------------------------------------------------------ */
/* BEHAVIOR/INTERNAL: enforce-policy-landlock                          */
/* ------------------------------------------------------------------ */

static void
dl_apply(const struct dl_policy *pol)
{
	struct dl_ruleset_attr attr;
	size_t attrsize;
	int abi = dl_abi();
	int fd;
	int i;

	memset(&attr, 0, sizeof(attr));
	attr.handled_access_fs = pol->handled_fs;
	attr.handled_access_net = pol->handled_net;
	if (pol->want_all_fs)
		attr.handled_access_fs |= dl_mask(dl_fs_names, abi);
	if (pol->want_all_net)
		attr.handled_access_net |= dl_mask(dl_net_names, abi);
	attr.handled_access_fs &= dl_mask(dl_fs_names, abi);
	attr.handled_access_net &= dl_mask(dl_net_names, abi);
	attr.scoped = pol->scoped & dl_mask(dl_scope_names, abi);

	if (abi < 4)
		attrsize = offsetof(struct dl_ruleset_attr, handled_access_net);
	else if (abi < 6)
		attrsize = offsetof(struct dl_ruleset_attr, scoped);
	else
		attrsize = sizeof(attr);

	fd = (int)dl_sys_create(&attr, attrsize, 0);
	if (fd < 0)
		dl_refuse_errno("cannot create ruleset", NULL, errno);

	for (i = 0; i < pol->npath; i++) {
		struct dl_path_beneath_attr pb;
		int pfd;

		{
			struct dl_open_how how;

			memset(&how, 0, sizeof(how));
			how.flags = (uint64_t)(O_PATH | O_CLOEXEC);
			how.resolve = RESOLVE_NO_SYMLINKS;
			pfd = (int)dl_sys_openat2(-100 /* AT_FDCWD */,
						  pol->path_rules[i].path,
						  &how, sizeof(how));
		}
		if (pfd < 0) {
			/*
			 * ELOOP here means a symbolic-link component was
			 * refused by RESOLVE_NO_SYMLINKS.  ENOSYS means the
			 * kernel predates openat2; on the ABI-6 target it is
			 * always present, so treat its absence as a refusal
			 * rather than fall back to a symlink-following open.
			 */
			dl_refuse_errno("cannot open rule path ",
					pol->path_rules[i].path, errno);
		}
		memset(&pb, 0, sizeof(pb));
		pb.allowed_access = pol->path_rules[i].access &
				    dl_mask(dl_fs_names, abi);
		pb.parent_fd = pfd;
		if (dl_sys_add(fd, DL_RULE_PATH_BENEATH, &pb, 0) != 0) {
			int err = errno;

			close(pfd);
			dl_refuse_errno("cannot add rule for ",
					pol->path_rules[i].path, err);
		}
		close(pfd);
	}

	for (i = 0; i < pol->nnet; i++) {
		struct dl_net_port_attr np;
		char portbuf[16];

		memset(&np, 0, sizeof(np));
		np.allowed_access = pol->net_rules[i].access &
				    dl_mask(dl_net_names, abi);
		np.port = pol->net_rules[i].port;
		if (dl_sys_add(fd, DL_RULE_NET_PORT, &np, 0) != 0) {
			int err = errno;

			dl_utoa(pol->net_rules[i].port, portbuf,
				sizeof(portbuf));
			dl_refuse_errno("cannot add rule for port ", portbuf,
					err);
		}
	}

	if (dl_sys_restrict(fd, 0) != 0) {
		int err = errno;

		close(fd);
		dl_refuse_errno("cannot apply policy", NULL, err);
	}
	close(fd);
}

#endif /* DASHLOCK_BACKEND_LANDLOCK */

#ifdef DASHLOCK_BACKEND_UNVEIL

/* ------------------------------------------------------------------ */
/* BEHAVIOR/INTERNAL: enforce-policy-unveil                            */
/* ------------------------------------------------------------------ */

/*
 * Declared in unistd.h on OpenBSD.  Declared here as well so that this
 * section compile-checks on a non-OpenBSD review host (see the hints
 * file); an identical redeclaration is legal C.
 */
int unveil(const char *, const char *);
int pledge(const char *, const char *);

/*
 * The PortableClass mapping from the specification.  One-directional
 * coarsening: a class may cover more than the named rights, never less.
 * ioctl-dev maps to no class: unveil does not mediate device ioctl by
 * path; those fall under the pledge promises.
 */
#define DL_UV_R (DL_FS_READ_FILE | DL_FS_READ_DIR)
#define DL_UV_W (DL_FS_WRITE_FILE | DL_FS_TRUNCATE)
#define DL_UV_X (DL_FS_EXECUTE)
#define DL_UV_C (DL_FS_MAKE_CHAR | DL_FS_MAKE_DIR | DL_FS_MAKE_REG | \
		 DL_FS_MAKE_SOCK | DL_FS_MAKE_FIFO | DL_FS_MAKE_BLOCK | \
		 DL_FS_MAKE_SYM | DL_FS_REMOVE_DIR | DL_FS_REMOVE_FILE | \
		 DL_FS_REFER)

/*
 * Build the unveil permission string for a rule, fixed order "rwxc".
 * out must hold 5 bytes.  Returns the number of classes granted; 0 means
 * the rule maps to nothing this backend mediates and the caller refuses.
 */
static int
dl_uv_classes(uint64_t access, char *out)
{
	int j = 0;

	if ((access & DL_UV_R) != 0)
		out[j++] = 'r';
	if ((access & DL_UV_W) != 0)
		out[j++] = 'w';
	if ((access & DL_UV_X) != 0)
		out[j++] = 'x';
	if ((access & DL_UV_C) != 0)
		out[j++] = 'c';
	out[j] = '\0';
	return j;
}

/*
 * Verified rule paths, one slot per rule.  pfd is the open descriptor of
 * the verified parent directory; leaf is the final component, re-resolved
 * by name inside unveil(2), because OpenBSD has no handle-based unveil.
 * pfd -1 marks a rule on the root directory, which has no parent.  File
 * scope rather than the stack: 64 slots with a name buffer each would be
 * a large frame, and dashlock_init runs strictly single-threaded before
 * the shell starts.
 */
struct dl_uv_slot {
	int pfd;
	char leaf[256];		/* NAME_MAX + 1 on OpenBSD */
};

static struct dl_uv_slot dl_uv_slots[DL_PATH_RULES_MAX];

/*
 * Verify one rule path on open directory handles, before any unveil call.
 * After the first unveil the process's own openat walks would already be
 * filtered by the partial set, while unveil(2) itself resolves
 * unrestricted, so verification of every rule must complete before the
 * first unveil (spec, enforce-policy-unveil).  Each intermediate
 * component is opened O_NOFOLLOW relative to its verified parent, which
 * pins the ancestors by handle.  The final component is checked with
 * fstatat(AT_SYMLINK_NOFOLLOW) rather than opened, because opening a
 * device node has side effects: /dev/tty fails with ENXIO without a
 * controlling terminal, and a policy rule must not depend on that.  The
 * leaf is then re-resolved by name inside unveil(2); that one-system-call
 * window is the documented residual difference from openat2 on Linux.
 */
static void
dl_uv_verify(const char *path, struct dl_uv_slot *slot)
{
	char buf[DL_PATH_MAX];
	struct stat st;
	size_t n = strlen(path);
	char *p;
	int dirfd;

	if (n >= sizeof(buf))
		dl_refuse_errno("cannot open rule path ", path, ENAMETOOLONG);
	memcpy(buf, path, n + 1);
	while (n > 1 && buf[n - 1] == '/')
		buf[--n] = '\0';

	if (buf[1] == '\0') {
		/*
		 * The root itself: no parent to pin, and "/" cannot be a
		 * symbolic link.  Applied later as unveil("/", ...).
		 */
		slot->pfd = -1;
		slot->leaf[0] = '/';
		slot->leaf[1] = '\0';
		return;
	}

	dirfd = open("/", DL_WALK_FLAGS);
	if (dirfd < 0)
		dl_refuse_errno("cannot open rule path ", path, errno);

	p = buf + 1;
	for (;;) {
		char *slash = strchr(p, '/');
		int next;

		if (slash == NULL)
			break;
		*slash = '\0';
		next = openat(dirfd, p, DL_WALK_FLAGS);
		if (next < 0) {
			int err = errno;

			close(dirfd);
			dl_refuse_errno("cannot open rule path ", path, err);
		}
		close(dirfd);
		dirfd = next;
		p = slash + 1;
	}

	if (fstatat(dirfd, p, &st, AT_SYMLINK_NOFOLLOW) != 0) {
		int err = errno;

		close(dirfd);
		dl_refuse_errno("cannot open rule path ", path, err);
	}
	if (S_ISLNK(st.st_mode)) {
		close(dirfd);
		dl_refuse_errno("cannot open rule path ", path, ELOOP);
	}
	if (strlen(p) >= sizeof(slot->leaf)) {
		close(dirfd);
		dl_refuse_errno("cannot open rule path ", path, ENAMETOOLONG);
	}
	memcpy(slot->leaf, p, strlen(p) + 1);
	slot->pfd = dirfd;
}

/*
 * The enforcement sequence of the spec, steps 1 to 10 in order.  The
 * unveil set and its lock survive execve only while execution promises
 * are in force, so both are installed here, before the shell reads
 * anything.
 */
static void
dl_unveil_apply(const struct dl_policy *pol)
{
	char promises[DL_PLEDGE_MAX];
	int saved;
	int i;

	/*
	 * Backend contract, rule 1: a restriction this backend cannot
	 * enforce is a refusal, never a skip.  abi-min and abi-max are
	 * Landlock preconditions and gate nothing here (rule 2).
	 */
	if (pol->want_all_net || pol->handled_net != 0)
		dl_refuse("backend cannot enforce access net-tcp in ",
			  pol->source, "");
	if (pol->nnet > 0)
		dl_refuse("backend cannot enforce rule net-port in ",
			  pol->source, "");
	if (pol->scoped != 0)
		dl_refuse("backend cannot enforce scope in ",
			  pol->source, "");
	if (!pol->want_all_fs && pol->handled_fs != 0) {
		const struct dl_name_bit *e;
		const char *parts[6];

		for (e = dl_fs_names; e->name != NULL; e++)
			if ((pol->handled_fs & e->bit) != 0)
				break;
		parts[0] = "backend cannot enforce access fs:";
		parts[1] = (e->name != NULL) ? e->name : "";
		parts[2] = " in ";
		parts[3] = pol->source;
		parts[4] = NULL;
		dl_refusev(parts);
	}
	for (i = 0; i < pol->npath; i++) {
		char cls[5];

		if (dl_uv_classes(pol->path_rules[i].access, cls) == 0) {
			const char *parts[4];

			parts[0] = "rule for ";
			parts[1] = pol->path_rules[i].path;
			parts[2] = " grants nothing this backend mediates";
			parts[3] = NULL;
			dl_refusev(parts);
		}
	}

	saved = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (saved < 0)
		dl_refuse_errno("cannot save working directory", NULL, errno);

	for (i = 0; i < pol->npath; i++)
		dl_uv_verify(pol->path_rules[i].path, &dl_uv_slots[i]);

	for (i = 0; i < pol->npath; i++) {
		char cls[5];

		(void)dl_uv_classes(pol->path_rules[i].access, cls);
		if (dl_uv_slots[i].pfd == -1) {
			if (unveil("/", cls) != 0)
				dl_refuse_errno("cannot unveil ",
						pol->path_rules[i].path,
						errno);
			continue;
		}
		if (fchdir(dl_uv_slots[i].pfd) != 0)
			dl_refuse_errno("cannot unveil ",
					pol->path_rules[i].path, errno);
		if (unveil(dl_uv_slots[i].leaf, cls) != 0)
			dl_refuse_errno("cannot unveil ",
					pol->path_rules[i].path, errno);
		close(dl_uv_slots[i].pfd);
	}

	if (unveil(NULL, NULL) != 0)
		dl_refuse_errno("cannot lock unveil", NULL, errno);

	/*
	 * Execution promises are what the kernel requires for the unveil
	 * set to survive execve (see the hints file and design.md section
	 * 7).  The default is every promise this build knows: the
	 * restriction of this design is the filesystem allowlist, so
	 * pledge restricts as little as the mechanism allows.  A pledge
	 * directive replaces the default.  An unknown name on an older
	 * kernel fails the whole pledge call, and the session refuses:
	 * version skew fails closed.
	 */
	{
		size_t n = 0;

		for (i = 0; dl_pledge_names[i] != NULL; i++) {
			size_t l;

			if (pol->have_pledge &&
			    (pol->pledge_bits & ((uint64_t)1 << i)) == 0)
				continue;
			l = strlen(dl_pledge_names[i]);
			if (n + l + 2 > sizeof(promises))
				dl_refuse("cannot set execution promises",
					  NULL, NULL);
			if (n > 0)
				promises[n++] = ' ';
			memcpy(promises + n, dl_pledge_names[i], l);
			n += l;
		}
		promises[n] = '\0';
	}
	if (pledge(NULL, promises) != 0)
		dl_refuse_errno("cannot set execution promises", NULL, errno);

	if (fchdir(saved) != 0)
		dl_refuse_errno("cannot restore working directory", NULL,
				errno);
	close(saved);
}

#endif /* DASHLOCK_BACKEND_UNVEIL */

/* ------------------------------------------------------------------ */
/* BEHAVIOR/INTERNAL: resolve-user-key                                 */
/* ------------------------------------------------------------------ */

/*
 * F10: a usable file key is printable ASCII without a path separator.  The
 * name is echoed into refusal messages, so C0 and C1 control bytes are
 * rejected to keep a hostile name service from injecting terminal escape
 * sequences; bytes outside ASCII are rejected with them, which also keeps
 * the key set independent of any locale.  Real oddities such as trailing
 * "$" in machine accounts pass.
 */
static int
dl_valid_user_key(const char *s)
{
	const char *p;

	if (*s == '\0')
		return 0;
	if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0)
		return 0;
	for (p = s; *p != '\0'; p++) {
		if (*p < '!' || *p > '~' || *p == '/')
			return 0;
	}
	return 1;
}

/*
 * The real user ID selects the policy, because the account is what the
 * administrator wrote the policy for.
 *
 * F1: the fallback rules distinguish three cases, and the distinction is
 * the security property.  "No entry" keys the session by decimal user ID,
 * as does an entry whose name is unusable as a file key; pw_name is
 * assigned by the administrator and cannot be changed by the account, so
 * neither fallback is user-triggerable.  A failing lookup, by contrast,
 * refuses: buffer exhaustion and name service outages can be
 * user-adjacent (GECOS growth, backend load), and a user-adjacent failure
 * must not be able to select a different policy file.
 */
static void
dl_user_key(char *out, size_t outlen)
{
	uid_t uid = getuid();
#ifdef HAVE_GETPWUID_R
	struct passwd pw;
	struct passwd *res = NULL;
	char *buf;
	size_t buflen = 1024;
	int rc;

	for (;;) {
		buf = malloc(buflen);
		if (buf == NULL)
			dl_refuse("out of memory", NULL, NULL);
		res = NULL;
		rc = getpwuid_r(uid, &pw, buf, buflen, &res);
		if (rc == EINTR) {
			free(buf);
			continue;
		}
		if (rc == ERANGE) {
			free(buf);
			if (buflen >= 65536)
				dl_refuse_errno("user lookup failed", NULL,
						rc);
			buflen *= 2;
			continue;
		}
		break;
	}

	/*
	 * The only unambiguous "no such user" result is a zero return with a
	 * null result pointer.  A nonzero return can mean a missing NSS
	 * backend as easily as a missing user, and treating that as no-entry
	 * could select a weaker numeric or default policy on an induced
	 * backend failure.  So: zero-with-null keys by uid, an existing entry
	 * with an unusable name keys by uid, and every nonzero return
	 * refuses.
	 */
	if (rc == 0 && res != NULL) {
		const char *name = res->pw_name;

		if (name != NULL && dl_valid_user_key(name) &&
		    strlen(name) < outlen) {
			memcpy(out, name, strlen(name) + 1);
			free(buf);
			return;
		}
		free(buf);	/* entry exists, name unusable as a key */
	} else if (rc == 0) {
		free(buf);	/* definitive no-entry: zero return, null result */
	} else {
		dl_refuse_errno("user lookup failed", NULL, rc);
	}
#endif
	dl_utoa((unsigned long)uid, out, outlen);
}

/* ------------------------------------------------------------------ */
/* BEHAVIOR/INTERNAL: consume-narrow-argument                          */
/* ------------------------------------------------------------------ */

static int
dl_valid_narrow_name(const char *s)
{
	const char *p;

	if (*s == '\0')
		return 0;
	for (p = s; *p != '\0'; p++) {
		if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
		    (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')
			continue;
		return 0;
	}
	return 1;
}

/*
 * Recognised in the first argument position only.  Anywhere else the token
 * is an ordinary shell argument.  Bounding it to one position keeps the
 * option parser of the shell untouched.
 */
static const char *
dl_consume_narrow(int *argcp, char **argv)
{
	const char *name;
	int i;

	if (argv[1] == NULL || strcmp(argv[1], "--narrow") != 0)
		return NULL;
	if (argv[2] == NULL)
		dl_refuse("--narrow requires an argument", NULL, NULL);
	if (!dl_valid_narrow_name(argv[2]))
		dl_refuse("invalid narrow policy name", NULL, NULL);

#ifdef DASHLOCK_BACKEND_UNVEIL
	/*
	 * Spec, consume-narrow-argument step 4: unveil sets do not
	 * intersect, so this backend has no narrowing layer.  Refusing
	 * here, before any policy file is read, shows the administrator
	 * the actual limitation instead of a missing-file message.
	 */
	dl_refuse("narrowing is not supported by this backend", NULL, NULL);
#endif

	name = argv[2];
	for (i = 1; argv[i + 2] != NULL; i++)
		argv[i] = argv[i + 2];
	argv[i] = NULL;
	/*
	 * Two entries were removed from the vector.  Decrement argc so that
	 * any code trusting argc, rather than scanning to the terminating
	 * NULL, does not read an interior NULL or a stale pointer past the
	 * new end.
	 */
	if (argcp != NULL)
		*argcp -= 2;
	return name;
}

/* ------------------------------------------------------------------ */
/* BEHAVIOR: gate-on-invocation-name                                   */
/* ------------------------------------------------------------------ */

void
dashlock_init(int *argcp, char **argv)
{
	struct dl_policy base;
	struct dl_policy narrow;
	const char *narrow_name = NULL;
	char key[DL_KEY_MAX];
#ifdef DASHLOCK_BACKEND_LANDLOCK
	int abi;
#endif

#ifdef DASHLOCK_NAME_GATE
	/*
	 * The gate decides on argv[0] alone, so without an argv[0] the
	 * binary cannot have been invoked under the trigger name.
	 */
	if (argv == NULL || argv[0] == NULL)
		return;
	{
		const char *name = strrchr(argv[0], '/');

		name = (name != NULL) ? name + 1 : argv[0];
		if (*name == '-')
			name++;
		if (strcmp(name, DASHLOCK_NAME) != 0)
			return;
	}
#endif

	/*
	 * A refusal must exit 78, not die by signal.  If the launcher hands us
	 * a closed pipe as standard error, a diagnostic write would raise
	 * SIGPIPE and terminate the process before _exit(78).  Set after the
	 * name gate so that a binary invoked as plain dash makes no system
	 * call and leaves no observable trace; the shell installs its own
	 * disposition later.
	 */
	signal(SIGPIPE, SIG_IGN);

	/*
	 * F5: the specification forbids set-user-ID and set-group-ID
	 * invocation; enforce it rather than assume it.  The policy is
	 * selected by the real user ID, so a set-ID invocation would
	 * confine one identity while holding the power of another, and
	 * no_new_privs drops nothing that is already in effect.  The check
	 * sits after the name gate so that a binary invoked as plain dash
	 * stays bit-identical to upstream.
	 */
	if (getuid() != geteuid() || getgid() != getegid())
		dl_refuse("set-user-ID or set-group-ID invocation refused",
			  NULL, NULL);

	/*
	 * F3: in the no-gate build an unusable argument vector must not
	 * produce an unconfined session.  Since Linux 5.18 the kernel
	 * rewrites an empty argv to {"", NULL}, so the branch is
	 * unreachable there, but the guarantee should be the program's,
	 * not the kernel's.  Confinement proceeds; only the --narrow
	 * consumption needs argv and is skipped.
	 */
	if (argv != NULL && argv[0] != NULL)
		narrow_name = dl_consume_narrow(argcp, argv);

	dl_user_key(key, sizeof(key));
	dl_load(&base, key, 0);
	if (narrow_name != NULL)
		dl_load(&narrow, narrow_name, 1);

#ifdef DASHLOCK_BACKEND_LANDLOCK
	/*
	 * Backend contract, rule 1: the pledge directive is a restriction
	 * this backend cannot enforce; refusing keeps the policy's meaning
	 * identical on both backends.
	 */
	if (base.have_pledge)
		dl_refuse("backend cannot enforce pledge in ",
			  base.source, "");
	if (narrow_name != NULL && narrow.have_pledge)
		dl_refuse("backend cannot enforce pledge in ",
			  narrow.source, "");

	abi = dl_abi();
	if (base.abi_max != 0 && abi > base.abi_max) {
		char cap[16], have[16];

		dl_utoa((unsigned long)base.abi_max, cap, sizeof(cap));
		dl_utoa((unsigned long)abi, have, sizeof(have));
		dl_write("dashlock: kernel landlock ABI ");
		dl_write(have);
		dl_write(" exceeds policy abi-max ");
		dl_write(cap);
		dl_write("\n");
		_exit(DASHLOCK_EXIT_CONFIG);
	}
	if (narrow_name != NULL && narrow.abi_max != 0 && abi > narrow.abi_max) {
		char cap[16], have[16];

		dl_utoa((unsigned long)narrow.abi_max, cap, sizeof(cap));
		dl_utoa((unsigned long)abi, have, sizeof(have));
		dl_write("dashlock: kernel landlock ABI ");
		dl_write(have);
		dl_write(" exceeds policy abi-max ");
		dl_write(cap);
		dl_write("\n");
		_exit(DASHLOCK_EXIT_CONFIG);
	}
	if (dl_required_abi(&base) > abi) {
		char need[16], have[16];

		dl_utoa((unsigned long)dl_required_abi(&base), need,
			sizeof(need));
		dl_utoa((unsigned long)abi, have, sizeof(have));
		dl_write("dashlock: policy needs landlock ABI ");
		dl_write(need);
		dl_write(", kernel provides ");
		dl_write(have);
		dl_write("\n");
		_exit(DASHLOCK_EXIT_CONFIG);
	}
	if (narrow_name != NULL && dl_required_abi(&narrow) > abi) {
		char need[16], have[16];

		dl_utoa((unsigned long)dl_required_abi(&narrow), need,
			sizeof(need));
		dl_utoa((unsigned long)abi, have, sizeof(have));
		dl_write("dashlock: policy needs landlock ABI ");
		dl_write(need);
		dl_write(", kernel provides ");
		dl_write(have);
		dl_write("\n");
		_exit(DASHLOCK_EXIT_CONFIG);
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		dl_refuse_errno("cannot set no_new_privs", NULL, errno);

	dl_apply(&base);
	if (narrow_name != NULL)
		dl_apply(&narrow);
#endif /* DASHLOCK_BACKEND_LANDLOCK */

#ifdef DASHLOCK_BACKEND_UNVEIL
	dl_unveil_apply(&base);
#endif
}

#else /* !USE_DASHLOCK */

/* ISO C forbids an empty translation unit. */
typedef int dashlock_disabled_t;

#endif /* USE_DASHLOCK */

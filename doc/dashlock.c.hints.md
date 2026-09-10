# dashlock.c.hints

Language hints for `dashlock.spec.md`: C on Linux, and C on OpenBSD for the
unveil backend.

These are implementation facts that do not belong in the specification, which
is language-agnostic. They are advisory and cannot override a spec invariant.
Where a hint and the spec disagree, the spec wins and the hint is wrong.

## Target and integration

- Base: dash 0.5.13.5 (Herbert Xu). The addition is two new files, `src/dashlock.c`
  and `src/dashlock.h`, plus a two-line hook in `src/main.c` and build glue in
  `configure.ac` and `src/Makefile.am`.
- Platform floor: Linux 6.12 (Landlock ABI 6), or OpenBSD 7.9 (unveil and
  pledge). Build-configurable name gate, trigger name, and policy
  directories; the enforcement backend is selected by configure, one per
  build.
- The hook is the first statement of `main()`:

  ```c
  dashlock_init(&argc, argv);
  ```

  It precedes the glibc `dash_errno` assignment, `init()`, and `procargs()`,
  so it runs before any profile file, rc file, or `-c` argument is parsed.

## Why the new file includes no shell header

`src/main.h` does, for glibc:

```c
extern int *dash_errno;
#undef errno
#define errno (*dash_errno)
```

`dash_errno` is assigned inside `main()`. Any shell header pulled into
`dashlock.c` would put an uninitialised-pointer `errno` on the startup path.
`dashlock.c` therefore includes only system headers and `dashlock.h`, and uses
the real libc `errno`.

## No stdio, no shell output layer

Diagnostics use `write(2)` on file descriptor 2 directly. The shell output
layer (`out2str` and friends) is not initialised this early. The refusal path
ends in `_exit(78)`, not `exit()`, so no `atexit` handler and no buffered
output of a half-initialised shell can run. 78 is `EX_CONFIG` from
`sysexits.h`, referenced by value rather than by include to keep the
dependency surface minimal.

## Landlock uapi is defined locally

`dashlock.c` defines every Landlock constant it uses, the three attribute
structs, and the syscall numbers itself, guarded by `#ifndef`, and includes
`linux/landlock.h` only when `HAVE_LINUX_LANDLOCK_H`. Reasons: the build host
header may predate ABI 6; the ruleset attribute passed to the kernel is
size-tagged, so the code must control the struct size it sends; and the syscall
numbers (444, 445, 446) are the asm-generic values, verified for x86-64 and
AArch64 only. A port to another architecture must confirm them against that
architecture's syscall table; the `#ifndef` guards mean an architecture header
that defines them takes precedence.

Cross-checked against the 6.12 header by an independent review: all constant
values, and the field widths, order, and packing of `landlock_ruleset_attr`,
`landlock_path_beneath_attr`, and `landlock_net_port_attr`, match. `dl_path_beneath_attr`
is `__attribute__((packed))`; expected size 12. Do not add `LANDLOCK_CREATE_RULESET_ERRATA`
handling; it is an optional query flag the design does not use.

The ruleset attribute size sent to the kernel is ABI-dependent: 8 bytes below
ABI 4 (fs only), 16 for ABI 4-5 (fs + net), 24 from ABI 6 (fs + net + scope).
This is computed in `dl_apply` with `offsetof`, so a struct-layout change does
not silently desynchronise it.

## Path resolution: the two open paths

Two distinct resolution requirements, both realised with `openat2(2)`
(`__NR_openat2` 437) or the descriptor walk, never a plain `open()` on a
user-influenced path.

Policy files (`dl_open_verified`): walk from `/` with
`open("/", O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`, then `openat(dirfd,
component, O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` for each intermediate
component, `fstat` each descriptor, and finally
`openat(dirfd, leaf, O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK)`. `O_NOFOLLOW`
on a directory open of a symlink returns `ENOTDIR`, which is the correct
refusal; `O_NONBLOCK` keeps a FIFO in the path from blocking startup before the
regular-file check rejects it. This makes the object checked identical to the
object opened, closing the check-versus-use gap that a separate `stat()` walk
would leave.

Rule paths (`dl_apply`): `openat2(AT_FDCWD, path, {flags: O_PATH|O_CLOEXEC,
resolve: RESOLVE_NO_SYMLINKS}, sizeof(how))`. A root-authored policy commonly
names a path whose leaf the confined account controls, such as a home
directory; `RESOLVE_NO_SYMLINKS` stops the account pre-positioning a symlink to
redirect the rule. `ENOSYS` (kernel without `openat2`) is a refusal on the
ABI-6 target, never a fallback to a symlink-following open. `RESOLVE_NO_SYMLINKS`
is `0x04`; `struct open_how` is `{u64 flags; u64 mode; u64 resolve;}`, both
defined locally under `#ifndef` for the same header-age reason as Landlock.

## Build contract

dash injects the generated configuration header into every translation unit
via `AM_CPPFLAGS = -include $(top_builddir)/config.h` in `src/Makefile.am`, so
`USE_DASHLOCK` and the other feature macros are visible at the top of
`dashlock.c` without it including `config.h`. A reviewer reading the patch
alone cannot see that line, so the file states the contract in a comment and
has an `#error` guard that fails the build if the macros ever stop
arriving, rather than silently compiling an inert shell under the dashlock
name.

## errno capture across cleanup

Every failed syscall on the policy-open path saves `int err = errno`
immediately, before any `close()`, and classifies on `err`. A successful
`close()` may reset `errno` on some libcs, and misclassifying a real error as
`ENOENT` would fall through to a lower-priority policy, so the capture is a
correctness requirement, not style. The `dl_open_verified` walk and the
final-file open both follow this.

## SIGPIPE

`dashlock_init` sets `signal(SIGPIPE, SIG_IGN)` before any diagnostic write, so
a refusal exits 78 rather than dying by signal when the launcher hands it a
closed standard error. The shell installs its own disposition later.

## abi-max

Optional ceiling directive. `abi_max` in `struct dl_policy` (0 = none, minimum
wins across lines). Checked in `dashlock_init` after the ABI query: a running
kernel above the ceiling exits 78. `abi-max` below `abi-min` is a parse-time
contradiction. Its purpose is the wildcard-forward-compat gap: masking already
prevents sending an unknown bit, so a wildcard cannot grant a future right, but
it also cannot restrict one, and `abi-max` lets a wildcard policy refuse a
kernel it has not been reviewed against.

## errno discipline

Every refusal caused by a failed syscall or lookup goes through
`dl_refuse_errno`, which appends " (errno N)" (raw number, no `strerror`, no
locale on the startup path). This includes the ABI-version query, `prctl`,
every `open`/`openat`/`fstat`, and every `landlock_*` call. Plain `dl_refuse`
is only for refusals with no underlying errno (policy content errors, "handles
no access", the set-ID refusal).

## Account-name lookup

`getpwuid_r` on the real user ID, in a loop that grows the buffer on `ERANGE` up to
64 KiB and retries on `EINTR`. Definitive no-entry (return 0 with null result,
or `ENOENT`/`ESRCH`) and an unusable returned name both fall back to the
decimal uid; any other failure refuses. "Unusable" is checked by
`dl_valid_user_key`: non-empty, not "." or "..", under 256 bytes, every byte in
printable ASCII `!`..`~`, no `/`. The printable-ASCII rule keeps control bytes
from a hostile name service out of the terminal diagnostics.

Only `rc == 0 && res == NULL` is treated as definitive no-entry (key by uid);
every nonzero `getpwuid_r` return refuses, because a nonzero status can signal a
missing NSS backend rather than a missing user, and a backend failure must not
select a weaker policy.

`configure.ac` makes `getpwuid_r` a hard requirement when dashlock is enabled
(`AC_MSG_ERROR` under `--enable-dashlock`, auto-disable with a warning
otherwise). Without it the lookup would compile out and key every account by
number, which is a different policy decision than the administrator wrote.

## argv and argc

`dl_consume_narrow` takes `int *argcp`. When it removes the leading `--narrow
NAME` pair it shifts the pointers, plants an earlier `NULL`, and subtracts two
from `*argc`, so any dash code that trusts `argc` rather than scanning to the
terminating `NULL` cannot read an interior `NULL` or a stale pointer. In the
no-name-gate build a missing `argv` skips only the narrow consumption and still
confines. Since Linux 5.18 the kernel rewrites an empty argv to `{"", NULL}`,
so the `argv[0] == ""` case reaches the gate as an ordinary non-trigger name.

## Fixed limits (not in the spec)

`DL_FILE_MAX` 65536, `DL_PATH_MAX` 4096, `DL_PATH_RULES_MAX` 64,
`DL_NET_RULES_MAX` 32, `DL_KEY_MAX` 256, and on the unveil backend
`DL_PLEDGE_MAX` 1024 for the built promise string. All produce a refusal
when exceeded, so they are fail-closed. They are documented in the manual page, not the spec,
because the spec is the reviewable source of confinement decisions and these
are implementation ceilings, not policy semantics. If a deployment needs more
rules, raise the constant and rebuild.

## Build options

| configure option | default | effect |
| --- | --- | --- |
| `--disable-dashlock` | enabled where a backend is detected | remove the feature |
| `--enable-dashlock` | | make a missing backend or missing `getpwuid_r` a hard error |
| `--disable-dashlock-name-gate` | gate on | confine under any invocation name |
| `--with-dashlock-name=NAME` | `dashlock` | trigger name |
| `--with-dashlock-etcdir=DIR` | `/etc/dashlock` | admin policy dir, must be absolute |
| `--with-dashlock-libdir=DIR` | `/usr/lib/dashlock` | vendor policy dir, must be absolute |

`dashlock.c` also compiles standalone for review: the config macros have
in-file defaults under `#ifndef`, and unit drivers `#include "dashlock.c"`
directly to exercise `dl_consume_narrow`, `dl_required_abi`, `dl_parse_abi_min`,
and `dl_valid_user_key` without a kernel. With `-DDASHLOCK_BACKEND_UNVEIL`
and stub declarations for `unveil` and `pledge`, the unveil section
compile-checks on a Linux review host.

## OpenBSD backend: kernel facts the code relies on

Verified in openbsd/src at master, 2026-09-09. The manual pages do not state
the first item, and the backend design depends on it.

- `sys/kern/kern_exec.c`, end of `sys_execve` setup: when `PS_EXECPLEDGE` is
  set, the new image gets `ps_pledge = ps_execpledge` and the unveil state is
  kept. Otherwise the kernel calls `unveil_destroy()` and clears
  `ps_uvdone`; the comment reads "Clear our unveil paths out so the child
  starts afresh". Only execpromises keep the unveil set alive across
  `execve`.
- `PS_EXECPLEDGE` is not cleared by `execve`, so grandchildren re-enter the
  same branch: the confinement is transitive.
- `sys/kern/kern_exec.c`, permission checks: a set-user-ID or set-group-ID
  image under `PS_EXECPLEDGE` fails with `EACCES` before it runs. This is
  the OpenBSD counterpart of `no_new_privs`; it blocks where Linux
  de-privileges.
- `sys_unveil` in `sys/kern/vfs_syscalls.c`: `unveil(NULL, NULL)` sets
  `ps_uvdone = 1`; any later `unveil()` returns plain `EPERM`, no kill. An
  unlocked process may add unveils anywhere it has any access, so the lock
  is mandatory. The `namei` call inside `sys_unveil` does not set
  `ni_unveil`, so unveil's own path resolution is not filtered by earlier
  unveils; the process's other system calls are.
- `sys_unveil` resolves the given path with `FOLLOW`: the kernel follows
  symbolic links in the argument. Symlink refusal is therefore our job,
  before the call, and the final component stays name-resolved inside the
  kernel (see the sequence below).
- `sys_pledge` in `sys/kern/kern_pledge.c`: `pledge(NULL, execpromises)`
  sets `ps_execpledge` and `PS_EXECPLEDGE` without touching the caller's own
  promises. Promises and execpromises are only reducible afterwards; parse
  errors fail the call as a whole with `EINVAL`. One table, `pledgereq[]`,
  serves both arguments.
- `sys/sys/proc.h`: `PS_PLEDGE` and `PS_EXECPLEDGE` are in
  `PS_FLAGS_INHERITED_ON_FORK`; `ps_pledge` and `ps_execpledge` sit in the
  fork copy range; `unveil_copy()` copies the path set and `ps_uvdone`.
  Fork inherits everything; exec inherits under execpromises.

One reviewed non-issue: `sys_pledge` destroys the unveil state when a
process pledges promises containing none of rpath, wpath, cpath, dpath,
exec, unix, unveil. That process has also given up `execve` and every
path-taking call, so it cannot produce an unconfined descendant; the
destruction only releases vnode references.

## OpenBSD backend: enforcement sequence

`dl_unveil_apply()` under `#ifdef DASHLOCK_BACKEND_UNVEIL`. The order is
normative (spec, enforce-policy-unveil); the reasons live here.

1. Contract checks first: refuse `handled_net`/`nnet`/`want_all_net`,
   refuse `scoped`, refuse a non-wildcard filesystem category, map every
   rule's access to unveil classes and refuse a rule that maps to nothing.
   All before any file descriptor is opened.
2. Save the working directory: `open(".", O_RDONLY|O_DIRECTORY|O_CLOEXEC)`.
   The fchdir dance below must not change what the shell later reports as
   its working directory.
3. Verify every rule path before the first `unveil()` call. After the first
   unveil the process's own `openat` walks would be filtered by the partial
   set (rule 2's components may be invisible under rule 1), while `unveil()`
   itself resolves unrestricted; verification therefore runs to completion
   first. The walk: open `/` and each intermediate component with
   `openat(dirfd, comp, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`; check
   the final component with `fstatat(dirfd, leaf, &st,
   AT_SYMLINK_NOFOLLOW)` and refuse `S_ISLNK`. `fstatat` rather than an
   open, because opening a device node has side effects: `/dev/tty` opens
   fail with `ENXIO` when the process has no controlling terminal, and a
   policy rule must not depend on that. Keep the parent directory
   descriptor of every rule for step 4; with `DL_PATH_RULES_MAX` 64 that is
   at most 65 descriptors plus the saved working directory, comfortably
   under any default `openfiles` limit, and the count is bounded by the
   rule limit.
4. For each rule, in policy order: `fchdir(parentfd)`, then
   `unveil(leafname, classes)` with the class string built from the mapped
   PortableClass set in the fixed order "rwxc". A rule on "/" itself is
   applied as `unveil("/", classes)` with no directory change: the root
   has no parent and cannot be a symbolic link. The parent handle pins
   every verified ancestor; only the leaf name is re-resolved by the
   kernel. That residual one-syscall window is the documented difference
   from `openat2` on Linux, and it requires write access to the parent
   directory to exploit, which root-owned parents deny.
5. `unveil(NULL, NULL)` to lock.
6. `pledge(NULL, promises)` with the space-joined promise string: the
   policy's pledge set when present, otherwise every entry of
   `dl_pledge_names[]`. Build the string into a fixed buffer,
   `DL_PLEDGE_MAX` 1024; the full current list is under 300 bytes.
7. `fchdir(saved)` and close the saved descriptor. A failure here is a
   refusal like any other: the shell must not start in a directory the
   session did not choose.

There is no `O_PATH` on OpenBSD, which is why the walk opens directories
for reading; a component the account cannot read refuses, which for an
unprivileged account includes search-only directories, and the manual page
says so. `openat`, `fstatat`, `fchdir`, `O_DIRECTORY`, `O_NOFOLLOW`,
`O_CLOEXEC` are all native.

## OpenBSD backend: promise table

`dl_pledge_names[]` is compiled unconditionally, because parse-policy
validates pledge directives on every backend; only the enforcement is
conditional. Snapshot of `pledgereq[]` from `sys/kern/kern_pledge.c`,
2026-09-09, 35 names, "tmppath" removed upstream and deliberately absent:

```c
audio bpf chown cpath disklabel dns dpath drm error exec fattr flock
getpw id inet mcast pf proc prot_exec ps recvfd route rpath sendfd
settime stdio tape tty unix unveil video vminfo vmm wpath wroute
```

The default includes "unveil" and "error" on purpose. "unveil" because the
inherited `ps_uvdone` lock already turns a child's `unveil()` into a clean
`EPERM`; withholding the promise would turn the same call into a pledge
violation and kill the child. "error" because a violation in an arbitrary,
never-pledge-aware child should produce an error return, which is what a
Landlock denial produces, not a `SIGABRT` kill. Version skew fails closed both
ways: an older kernel rejects an unknown name in our list (`EINVAL`, session
refuses), a newer kernel's new promise is missing from the list (children
over-restricted, never under).

## Backend selection in the build

`configure.ac` defines exactly one of `DASHLOCK_BACKEND_LANDLOCK` and
`DASHLOCK_BACKEND_UNVEIL`: landlock when `linux/landlock.h` is present,
unveil when the `unveil` and `pledge` functions link, landlock preferred if
a system ever offered both. Neither present: auto builds plain dash,
`--enable-dashlock` fails with "requires linux/landlock.h or unveil/pledge".
`getpwuid_r` remains a hard requirement on both. `src/dashlock.c` keeps the
single-file layout: common code unconditional, each backend in one
`#ifdef` section, and the standalone-compile mode gains stub declarations
for `unveil` and `pledge` so the unveil section can be compile-checked on a
Linux review host.

Packaging note: `/usr/lib/dashlock` is an unusual vendor path on OpenBSD;
ports would override with `--with-dashlock-libdir=/usr/local/lib/dashlock`.
The default stays as it is because the primary target sets it, and the
option exists.

## Known non-portable assumptions

- Two platforms, one per build. The file is behind `USE_DASHLOCK`; the
  Landlock section (uapi definitions, `openat2`, the syscall numbers) is
  behind `DASHLOCK_BACKEND_LANDLOCK`, the unveil section behind
  `DASHLOCK_BACKEND_UNVEIL`. Common code assumes POSIX plus `getpwuid_r`.
- x86-64 and AArch64 verified for the syscall numbers; both use the asm-generic
  numbers 437/444/445/446. A port to a different architecture must confirm them.
- glibc and musl both provide `getpwuid_r`, `openat2` wrappers vary, which is
  why the syscall is issued directly rather than through a libc wrapper.

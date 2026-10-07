# dashlock.c.hints

Language hints for `dashlock.spec.md`: C on Linux, and C on OpenBSD for the
unveil backend.

Author: Matthias G. Eckermann
Assisted-by: Claude:claude-fable-5
Assisted-by: Vibe (Mistral AI)

The test-seam, policy-checker, and host-matrix sections were added on
2026-10-06, from the proposal Vibe (Mistral AI) made in the review of
2026-10-04.

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

## The ABI ceiling: DASHLOCK_ABI_KNOWN

`DASHLOCK_ABI_KNOWN` is a configure-time constant (`--with-dashlock-abi-known`,
default 6, the maximum `abi` field in the access-right tables; configure
refuses a value below 1 or above that maximum, and a `#if` in `dashlock.c`
refuses a header that disagrees with the tables). `dl_abi()` keeps answering
with the kernel's version; a new `dl_effective_abi()` returns the smaller of
that and the constant, and everything that used the kernel value for policy
purposes uses the effective value instead: `dl_mask()` for the wildcard
expansion, the attribute size branch in `dl_apply()`, and the required-ABI
comparison. The required-ABI refusal names the bound that was hit: the kernel
when its version is the smaller value, the build otherwise ("this build knows
<c>"). Capping is safe because `landlock_create_ruleset` reads the attribute
by the size passed, so a ruleset built for ABI e behaves on a newer kernel as
on ABI e. The `abi_max` field, its parse, and `dl_landlock_ceiling_check()`
go away; `abi-max` in a policy file is then an unknown directive and refuses
at parse time, which is the loud failure the design prefers to a silent
no-op.

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
| `--with-dashlock-abi-known=N` | 6, the tables' maximum | ceiling of the effective ABI; refused outside 1..6 |

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

## Test seam: recording wrappers

The enforcement-sequence tests reuse the `#include "dashlock.c"` unit-driver
pattern that the review compiles already use. The seam is three macros in
`dashlock.c`, each defaulting to the libc entry point: `DL_SYSCALL` (the
Landlock calls and `openat2`), `DL_FSTAT` (every `fstat` of the policy
walk), and `DL_PRCTL`. A driver defines them before the include;
`tests/t_sequence.c` routes `DL_SYSCALL` to a recorder that logs the Landlock
calls, answers the version query with the ABI the scenario chooses, and
passes `openat2` and everything else through to the real kernel, so rule
paths are resolved for real while nothing is enforced. On OpenBSD the
`unveil` and `pledge` functions themselves are the seam: a test driver
defines recording versions (`tests/t_unveil.c`) or no-op versions
(`tests/unveil_stubs.h`), which take precedence over libc's for that
binary. The behavior code above them is then exercised
unchanged, and the test asserts the recorded sequence: on Landlock, the
attribute size per ABI branch, the handled masks after wildcard expansion,
and that no restrict call follows a failed add; on unveil, that every rule
path is verified before the first `unveil`, the class string per rule, the
lock, and the execpromises string. On a Linux host the unveil wrappers are
linked as stub implementations, not only declared, so the unveil sequence
runs there as well as compiling.

The parser and cross-check tests need no seam at all: they call
`dl_parse`, the lookup functions, and `dl_required_abi` directly and read
the refusal through the process exit, one table row per negative example in
the specification. The four review findings of 2026-10-04 are named rows:
the network-wildcard drop, the non-directory ancestor fall-through, the
errno-after-close misclassification, and the truncated-read-as-narrowing
case.

One trust-check case must not be written as a race. A file that grows
between the size check and the end of the read is driven through the
size-and-identity re-check path by the `DL_FSTAT` seam
(`tests/t_trustseam.c`), not by racing a second process that appends while
the reader runs, which would be nondeterministic in automation. The policy
file is `fstat`ed twice on the regular-file descriptor, once in the verified
open and once after the read to end of file, and the change detection
compares the second size with the bytes actually read; the seam enlarges
the second answer. The same driver fails the first `fstat` with `EIO` to
show the errno survives the `close()` that precedes the refusal. A single
genuine-race run stays a manual check.

## The policy checker: dashlock-check

Lint to add for the service-manager escape (design, section 11): warn when
the account named on the command line has a reachable user service manager,
that is `/etc/systemd/system/user@<uid>.service` is not a symlink to
`/dev/null` or `/var/lib/systemd/linger/<name>` exists. Advisory, Linux
only, never in the exit code; the fix is deployment, not policy, until the
kernel floor reaches ABI 9 and `RESOLVE_UNIX` becomes a rule.

`dashlock-check.c` includes `dashlock.c` the way the unit drivers do and
provides its own `main`, so it links the shell's own `dl_user_key`,
`dl_load` (lookup, trust checks, and `dl_parse`), `dl_required_abi`, and
`dl_refuse`. One code motion inside `dashlock.c` makes the pre-kernel checks
callable without confining: the pledge-directive refusal of
enforce-policy-landlock step 1 moves into `dl_landlock_check()`, its
required-ABI check (step 4, against the effective ABI) into
`dl_landlock_required_check()`, and steps 1 to 4 of enforce-policy-unveil (the
contract refusals and the class mapping) move into `dl_unveil_check()`;
each apply path calls its check functions first, unchanged in effect, and
the checker calls them directly. Pure extraction, no semantic change,
covered by the sequence tests. The checker's command line is
`dashlock-check [-k | -d] [-l] [-q] [-n narrow] [user]` and `-V`; the
manual page `dashlock-check(8)` is normative for it. No sink abstraction is
introduced: the write-and-exit refusal the shell uses is exactly what the
checker wants, because validate and kernel modes report at most the one
refusal a session would hit first. Dump mode runs after a successful parse,
so it needs the parsed policy intact; since `dl_parse` splits the buffer in
place, the checker parses a private copy and keeps the original for the
normalized printout.

The shell translation unit built as the shell never reaches validate-policy:
the behavior is implemented in `dashlock-check.c`, which has its own `main`,
and the
shell's `main` is `src/main.c` with its two-line hook. The build contract
(`#error` guard plus the `-include config.h` line) already guarantees the
shell binary is the confining one; the checker is a separate target and a
separate binary.

Advisory lints are emitted on the standard error descriptor and never change
the exit code. The set is backend-appropriate:

- Landlock: a rule tree that grants neither read nor execute on the library
  directories the loader needs; the loader cache (`/etc/ld.so.cache`)
  unreadable; `ioctl-dev` missing on the terminal devices for a policy that
  looks interactive.
- Either backend: a declared access category with no rules in it; a policy
  for an interactive account that grants nothing under the account's home
  directory.

These are recommendations, phrased in plain language and labeled advisory,
so they never dilute the pass-or-fail judgment. `/etc/ld.so.cache` and the
loader-tree lint are Linux-only; the unveil backend's loader paths differ
and its default policy grants them through the `/usr` and `/bin` rules.

## Host matrix for the on-kernel tests

The parser, cross-check, and sequence tests run on any host. The
confinement and ABI-refusal tests need a kernel the test build controls, which a hosted runner does not
provide. A virtual machine with a pinned kernel and
controlled boot parameters is the deterministic option: it boots kernels on
both sides of a policy's requirement to exercise the `abi-min` refusal and the build ceiling in
both directions, and boots with Landlock removed from the LSM list to
exercise the unavailable-kernel path. The OpenBSD leg has no hosted runner
either; it runs in a local virtual machine under the platform's own
hypervisor, the same sandbox the backend was first verified in.

The build matrix: `--disable-dashlock` (must produce plain dash),
`--enable-dashlock`, and `--disable-dashlock-name-gate`; a
`--enable-dashlock` build on a host where `linux/landlock.h` is hidden must
fail; gcc and clang with `-Wall -Wextra -Werror` on the fork's objects
only, passed as `make DASHLOCK_WARN_CFLAGS="-Wall -Wextra -Werror"`, since
upstream dash does not build under `-Wextra` and its flags stay upstream's
(the checker compiles `dashlock.c` through its include, so the shell's
confinement code is covered); one build of the kernel-free layers under the
undefined-behavior and address sanitizers. The inertness check
(`tests/t_inertness.sh`) compares a `--disable-dashlock` build byte-for-byte
against upstream dash 0.5.13.5 built from the same source with the same
flags and a fixed `SOURCE_DATE_EPOCH`, taking upstream from `UPSTREAM_SRC`
or from the "Release 0.5.13.5" commit in the fork's history; it passes only
because `src/Makefile.am` links `dashlock.o` solely when the feature is
built. The root-run layers (`t_trust.sh`, `t_kernel.sh`,
`t_kernel_unveil.sh`) write under `/var/dashlock-test` and the real
policy directory for one test account, so they run only under
`DASHLOCK_TESTS_SYSTEM=1` and report SKIP otherwise; `.github/workflows/ci.yml`
sets it for the root job.

A coverage-guided fuzzer over the parse path, seeded with the shipped
policies, needs no change to the refusal paths when it is a forking fuzzer:
a clean `_exit(78)` is a normal result, not a crash. An in-process fuzzer
would need the parser not to exit, which is not justified for the confined
code; use the forking driver.

# dashlock

A fork of the Debian Almquist Shell (dash) that applies a kernel-enforced
confinement policy to itself before it executes anything:
[Landlock](https://docs.kernel.org/userspace-api/landlock.html) on Linux,
[unveil](https://man.openbsd.org/unveil.2) and
[pledge](https://man.openbsd.org/pledge.2) on OpenBSD.
The backend is selected at build time; section 7 of `doc/design.md` covers
the OpenBSD side.

The policy comes from a root-owned file selected by user name. Once applied,
the restriction is inherited by every process the session starts and cannot be
removed afterwards by any privilege level, including root.

```console
$ echo hello > ~/notes
$ bash -c 'cat ~/notes'
hello
$ dashlock -c 'bash -c "cat ~/notes"'
cat: /home/mge/notes: Permission denied
```

Same user, same file, same interpreter. The only difference is that the second
command started inside the domain, and the domain survived the `exec` into
bash.

## Relationship to upstream dash

This is a fork, not a replacement, and it is not endorsed by or affiliated with
the dash maintainers.

| | |
| --- | --- |
| Upstream | `https://git.kernel.org/pub/scm/utils/dash/dash.git` |
| Upstream maintainer | Herbert Xu |
| Forked at | `037bbdf`, release 0.5.13.5 |

Report bugs in the shell itself upstream. Report anything in `src/dashlock.c`,
`src/dashlock.h`, the policy format, or the `DASHLOCK` manual section here.

The `master` branch tracks upstream unchanged. All work happens on the
`dashlock` branch, so `git diff master..dashlock` is exactly the addition and
nothing else.

## What the fork adds

The addition is inert unless the binary is invoked under the name `dashlock`.
Invoked as `dash`, `ash`, or `sh`, the same binary behaves exactly like
upstream: no policy file is opened and no system call is made. One binary can
therefore serve as the system `/bin/sh` and, through a second name, as a
confining login shell.

- `src/dashlock.c`, `src/dashlock.h` - the implementation, self-contained
- `src/main.c` - two lines, calling the hook first in `main()`
- `configure.ac`, `src/Makefile.am`, `policy/` - build integration and example policies
- `src/dash.1` - a `DASHLOCK` manual section covering the policy format, the
  lookup order, exit status 78, and the limits

## Requirements

Linux 6.12 or later, which is Landlock ABI version 6. That is the first level
at which the design closes, because scoping abstract UNIX sockets is what stops
a confined process reaching an unconfined broker and having it run something
outside the domain. Earlier kernels are refused rather than partially enforced.

`CONFIG_SECURITY_LANDLOCK=y` alone is not enough: `landlock` must also appear in
`CONFIG_LSM` or in the `lsm=` boot parameter. Check with:

```console
$ dmesg | grep -i landlock
$ cat /sys/kernel/security/lsm
```

Developed and tested on SUSE Linux Enterprise 16.

## Building

```console
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

Build options:

| Option | Default | Effect |
| --- | --- | --- |
| `--enable-dashlock` | auto | fail the build if prerequisites are missing, rather than silently producing plain dash |
| `--disable-dashlock` | | omit the feature entirely |
| `--disable-dashlock-name-gate` | gate on | confine under any invocation name |
| `--with-dashlock-name=NAME` | `dashlock` | trigger name |
| `--with-dashlock-etcdir=DIR` | `/etc/dashlock` | administrator policy directory |
| `--with-dashlock-libdir=DIR` | `/usr/lib/dashlock` | vendor policy directory |

For packaging, pass `--enable-dashlock` explicitly. Without it, a missing
`linux/landlock.h` or a missing `getpwuid_r` disables the feature with a
warning, and a package expected to confine would ship a shell that does not.

`--disable-dashlock-name-gate` produces the build for the strictest
deployments: installed under any name, it cannot be invoked without a policy.
Where the confined party can choose the name it invokes the binary under, only
this build is a boundary. See "Security model" below.

The build also produces `dashlock-check`, which reports whether a policy is
well-formed and would apply, with the session's own refusal message and exit
status 78 when it would not, without confining anything; `dashlock-check -d`
prints a normalized, diffable form of a policy and `-l` adds advisory lints.
See `dashlock-check(8)`.

### Tests

```console
$ make check
$ sudo env DASHLOCK_TESTS_SYSTEM=1 make check   # adds the root-run layers
```

`make check` runs the kernel-free layers on any host: the parser and
cross-check table (one row per negative example in the specification), the
Landlock enforcement sequence through recording seams, and the unveil
sequence with stub calls. With `DASHLOCK_TESTS_SYSTEM=1` as root it also runs
the policy-file trust fixtures under `/var/dashlock-test` and, on a kernel
with Landlock (or on OpenBSD), a confined session for one unprivileged test
account under the real policy directory. The inertness test builds the fork
with the feature disabled and compares it byte for byte with upstream dash
0.5.13.5 from the repository history. `.github/workflows/ci.yml` runs all of
it, plus a build with the Landlock header hidden that must fail, a sanitizer
build, and a bounded fuzzing run of the parser.

## Policy files

Selected by the account name of the real user ID, first match wins:

```
1. /etc/dashlock/users/<name>
2. /usr/lib/dashlock/users/<name>
3. /etc/dashlock/users/default
4. /usr/lib/dashlock/users/default
5. refuse to start, exit 78
```

Administrator files under `/etc` mask vendor files under `/usr/lib` per file
name. A file that exists but fails validation stops the search, so a tampered
administrator file is never silently replaced by a vendor one. Every file and
every directory above it must be owned by root and not writable by group or
other, and no component may be a symbolic link.

There is no degraded mode. A missing, malformed, or untrusted policy means the
shell does not start. A `dashlock` that fell back to unconfined operation would
be worse than none, because the account would look confined in `/etc/passwd`
while it was not.

### Format

Line oriented, `#` starts a comment. No includes, no globbing, no variable
substitution. An unknown directive or access name is a refusal, never a skipped
line.

```
# /etc/dashlock/users/agent
abi-min 6
abi-max 6

access fs
rule path-beneath:execute,read-file,read-dir:/usr
rule path-beneath:read-file,read-dir:/etc
rule path-beneath:read-file,read-dir:/proc
rule path-beneath:read-file,write-file,ioctl-dev:/dev/tty
rule path-beneath:read-file,write-file:/dev/null
rule path-beneath:read-file,write-file,read-dir,make-reg,make-dir,remove-file,remove-dir,refer,truncate:/home/agent/work
rule path-beneath:read-file,write-file,read-dir,make-reg,make-dir,remove-file,remove-dir,refer,truncate:/tmp

access net-tcp
rule net-port:connect-tcp:443

scope abstract-unix-socket,signal
```

Access right names are those used by `setpriv(1)` from util-linux, so a policy
line can be tried on the command line before it is installed. `abi-min` refuses
an older kernel; `abi-max` refuses a newer one, which a policy needs when it uses the
`access fs` wildcard, since that handles only the rights this build knows
about.

Two entries are easy to leave out and awkward to debug. Read and execute on the
library tree, because the domain is inherited and every dynamically linked
program the session runs needs the loader; under a merged `/usr` a rule on
`/usr` covers it. And read on `/etc/ld.so.cache`, without which the loader falls
back to searching and dynamic binaries fail in a way that reads like a
permission bug three levels down.

See the `DASHLOCK` section of `dash(1)` for the full reference.

### Narrowing a single invocation

```console
$ dashlock --narrow readonly -c 'make test'
```

applies a second policy layer from `/etc/dashlock/narrow/readonly` on top of the
user policy. The kernel intersects layers, so a narrowing policy can only remove
access, never add it. Whoever builds the command line can therefore influence
the policy without being trusted. Because layers intersect, a narrowing policy
must repeat every path it wants to keep: one it does not mention becomes
inaccessible.

## Security model

The confinement is real and cannot be escaped from inside once applied. What it
depends on is the launch, and those conditions cannot be established by a shell
from within itself. They are preconditions, not caveats:

- **The initial execution environment is not controlled by the confined party.**
  The dynamic loader and any constructors run before `main()`, so `LD_PRELOAD`
  bypasses the confinement entirely. The standard login paths sanitize the
  environment; a custom launcher must do the same.
- **Either the invocation name is truthful, or the name gate is disabled at
  build time.** The gate reads `argv[0]` and nothing else.
- **The user and mount namespaces are the trusted host's.** Ownership by user
  ID 0 is namespace-relative, so a party able to create its own user namespace
  can present its own policy as root-owned. Disable unprivileged user
  namespaces for confined accounts.
- **The process starts single-threaded** and with a known set of inherited
  descriptors. A descriptor opened before the domain exists is not subject to
  it and cannot be revoked by it.
- **No unintended capabilities are in effect.** Equal real and effective IDs do
  not prove their absence, and `no_new_privs` does not remove privilege already
  held. The binary must not have file capabilities set on it.

Also true of the design, and relevant before deploying:

- `no_new_privs` disables `sudo`, `su`, `pkexec`, and file-capability binaries
  such as `ping` for the session.
- Confinement applies to the shell. Paths that reach an account without starting
  one, such as the SFTP subsystem, the per-user service manager, and cron, must
  be closed separately.
- Landlock has no hooks for `mount`, `chdir`, or metadata operations such as
  `chmod` and `chown`, and on the network side covers TCP only. UDP, ICMP, and
  raw sockets are outside its scope.
- A Landlock rule binds to the resolved object, not to the path text. Rule paths
  should name locations whose parent directories the confined account cannot
  write.
- Diagnosing a denial on 6.12 means `EACCES` and `strace`. Audit records arrive
  with ABI 7 on kernel 6.15.

This does not address hypervisor escape. If the threat is an agent breaking out
of a virtual machine, the measures that apply are a minimal virtual machine
monitor, no user-mode networking stack in the emulator process, host-side
mandatory access control around the emulator, and CPU mitigations enabled.
Landlock operates at a different layer.

## Documentation

- `doc/design.md` - why the confinement belongs in a shell, why that shell is
  dash, and which alternatives were rejected
- `doc/dashlock.spec.md` - what the implementation must do, language-agnostic
- `doc/dashlock.c.hints.md` - how it is realized in C on Linux

The latter two are split that way on purpose, following
[PCD](https://github.com/mge1512/pcd). The specification states every rule that
decides whether a session is confined, in prose that names no language and no
system call, so it can be reviewed by someone who does not read C and so a
second implementation could be checked against it. The hints file covers what is
true only of this implementation: system-call numbers, structure layouts,
header handling, the build contract, and the fixed limits. Where the two
disagree, the specification wins and the hints file is wrong.

Each behavior in the specification lists its preconditions, steps,
postconditions, and error exits, and every error exit has a matching negative
example. Revisions can therefore be diffed against each other, and the DELTA
section records what changed and why.

## Provenance and review status

This section records how the code was produced, what has been reviewed, and
what has been tested on hardware as opposed to only read.

### How it was produced

The design decisions are the author's: gating on the invocation name, per-user
policy files with the administrator directory masking the vendor one, dynamic
rather than static linking, dash as the base, and Landlock ABI 6 as the floor.
The implementation, the specification, and the design notes were drafted with
an AI coding assistant against those decisions, then reviewed, corrected, and
tested by the author.

Commits include an `Assisted-by:` trailer recording the assistant and model
version,
following the convention in the kernel's
[AI Coding Assistants](https://docs.kernel.org/process/coding-assistants.html)
document. That convention deliberately avoids co-authorship: an assistant
cannot hold copyright and cannot certify the Developer Certificate of Origin,
so the `Signed-off-by:` line and the responsibility behind it are the author's
alone. Copyright on the new files is likewise the author's.

### What has been reviewed

Three rounds of independent security review, each conducted by a model from a
different vendor than the one used to write the code, working from the patch,
the specification, and the kernel Landlock header, without access to the
authoring conversation.

The rounds found, among other things: a fail-open path where a policy that used
the network wildcard could apply with its network portion silently dropped; a
non-directory component in a higher-priority policy path falling through to a
lower-priority file instead of refusing; `errno` read after `close()` on the
policy-open path, where a misclassification could have selected the wrong
policy; and a truncated read being treated as narrowing when an omitted suffix
can in fact make a policy weaker. All are fixed. The specification's DELTA
section records each round and what changed.

Reviews also raised the bootstrap conditions repeatedly. Those are not code
defects and are not fixed; they are stated as preconditions in "Security model"
above, because self-confinement in a dynamically linked binary cannot close
them from inside.

### What is verified, and what is not

Verified on Linux 6.12: the domain is installed, it is inherited across
`execve` into another interpreter, and it denies access to a file the invoking
user owns and that ordinary permissions would allow. The example at the top of
this file is that last case.

Verified by construction: the refusal paths, the policy parser, the file and
path validation, and the three build configurations, exercised by a test matrix
on a kernel where Landlock is compiled out.

Not verified: behavior on kernels above 6.12, architectures other than x86-64
and AArch64, and interactive terminal handling with job control under a policy
that handles `ioctl-dev`. The syscall numbers are the asm-generic values and
have been confirmed for two architectures only.

Independent review is welcome, particularly of the policy parser, which runs
unconfined on administrator-supplied input before the domain exists.

## License

BSD-3-Clause, inherited from dash and from the NetBSD ash it derives from.
Copyright is held by the Regents of the University of California, Christos
Zoulas, and Herbert Xu; see `COPYING` for the full text and the complete list.

One file, `src/mksignames.c`, is GPL-2.0-or-later, taken from GNU Bash. It is a
build-time helper whose output is linked into the shell. This arrangement comes
from upstream dash and is unchanged here.

New files added by this fork (`src/dashlock.c`, `src/dashlock.h`) are
BSD-3-Clause, copyright 2026 Matthias G. Eckermann.

# dashlock design notes

Why the confinement belongs in a shell, why that shell is dash, and how the
pieces fit together. The normative statement of behavior is
`dashlock.spec.md`; this document gives the reasoning behind it, including the
alternatives that were considered and rejected.

Author: Matthias G. Eckermann
Assisted-by: Claude:claude-fable-5
Assisted-by: Vibe (Mistral AI)

## 1. Summary

`dashlock` is a fork of the Debian Almquist Shell (dash) that applies a
kernel-enforced confinement policy to itself before it executes anything. On
Linux the mechanism is Landlock; on OpenBSD it is unveil and pledge. The
policy comes from a root-owned file selected by user name. Once applied, the
restriction is inherited by every process the session starts and cannot be
removed, including by root.

The patch fires only when the binary is invoked under the name `dashlock`.
Invoked as `dash`, `ash`, or `sh`, the same binary behaves exactly like
upstream dash. The name check can be disabled at build time, which produces a
binary that always confines itself regardless of the name it was called by.

Primary target is SLES 16 / openSUSE Leap 16, and later; the kernel floor is
6.12, which corresponds to Landlock ABI version 6. A second enforcement
backend targets OpenBSD 7.9 and later, using unveil and pledge; section 7
gives the reasoning and the rules that bind both backends.

## 2. Problem

We want to run coding agents that can build, test, and debug software. That
means giving the agent a full development userland, which means the agent can
run arbitrary code. The usual answer is a virtual machine.

Trail of Bits published a report on 2026-08-26 in which a cyber-capable agent
escaped a QEMU/KVM virtual machine three times: once through a recently
disclosed host kernel bug, once through a libslirp bug combined with a fix that
never received a CVE and therefore never reached the distribution, and once
through a chain of three previously unknown bugs plus one upstream fix that was
not classified as a security issue. The same agent could not escape Firecracker
in the time available.

Two conclusions from that report apply directly to us:

- A general-purpose virtual machine monitor is a large attack surface. A
  minimal one is a much harder target.
- Fixes that are correct but not labeled as security fixes never enter a
  backport queue. This is a structural gap in CVE-driven maintenance, and it is
  our gap as much as anyone else's.

Neither conclusion is addressed by anything inside the guest. Landlock does not
help against a hypervisor escape, and this document does not claim that it
does. What Landlock addresses is the layer above: keeping the agent inside its
intended working set so that a compromise has to start by defeating the
confinement rather than by reading whatever happens to be mounted.

## 3. What Landlock provides

Landlock is a stackable Linux Security Module, upstream since kernel 5.13. An
unprivileged process builds a ruleset and applies it to itself. Properties that
decide the design:

- The domain is inherited across `fork` and `execve`.
- It cannot be relaxed or removed afterwards, by any privilege level.
- Applying a further ruleset adds a layer, and layers intersect. A nested
  domain can only narrow, never widen.
- `no_new_privs` is required, so set-user-ID binaries stop conferring
  privilege for the session.
- Root is bound by it. Landlock is not capability-gated.

The version ladder, with the kernel that introduced each level:

| ABI | Kernel | Adds |
| --- | --- | --- |
| 1 | 5.13 | filesystem path rules |
| 2 | 5.19 | `refer` (link and rename across hierarchies) |
| 3 | 6.2 | `truncate` |
| 4 | 6.7 | TCP bind and connect port rules |
| 5 | 6.10 | `ioctl-dev` on device nodes |
| 6 | 6.12 | scoping for abstract UNIX sockets and signals |
| 7 | 6.15 | audit log control |
| 8, 9 | 7.0 era | thread synchronization, pathname UNIX socket connect |

ABI 6 is the first level at which the design closes, because scoping is what
stops a confined process from reaching an unconfined broker over an abstract
socket and having it run code outside the domain. SLE 16 ships a 6.12 kernel,
so ABI 6 is what we target. On a 6.4 kernel, which is what SLE 15 SP7 ships,
only ABI 3 is available and the broker path cannot be closed. We do not support
that configuration.

Two operational notes. `CONFIG_SECURITY_LANDLOCK=y` alone is not enough:
`landlock` also has to appear in `CONFIG_LSM` or in the `lsm=` boot parameter,
otherwise the module is compiled in but never initialized. Check with
`dmesg | grep -i landlock` for the startup line and `cat /sys/kernel/security/lsm`
for the active list.

Landlock also does not mediate everything. It has no hooks for `mount`,
`chdir`, or metadata operations such as `chmod`, `chown`, and `setxattr`. On
the network side it covers TCP bind and connect only, so UDP, ICMP, and raw
sockets are outside its scope. A policy has to be written with that in mind.

## 4. Why put this in a shell

Three placements were considered.

### 4.1 A PAM module

This would be the natural place, because PAM session hooks fire on every login
path including sshd's `internal-sftp`, which no shell can reach. It does not
work. `pam_sm_open_session` runs in a process that has to survive the session:
`login` and sshd fork the user's shell as a child and then write utmp, tear
down the pty, and call `pam_close_session`. A Landlock domain applied there is
irreversible and inherited, so it confines the session manager and breaks its
own cleanup. A correct hook would have to run after the change of user identity and
before the `execve`, and PAM offers none there.

`pam_apparmor` works in that slot because `aa_change_hat()` is reversible with
a magic token and because AppArmor has profile transitions on `execve`.
Landlock has neither, by design: its model is a subject restricting itself, not
an administrator imposing a transition on a subject. Closing this gap needs a
kernel feature, not a PAM module, and the upstream answer to a request for that
feature would correctly be that AppArmor and SELinux already occupy the role.

### 4.2 A wrapper binary in the login shell slot

Roughly 200 lines of C that applies the domain and then executes the
distribution shell. This works and remains a reasonable fallback. It does not
give a session whose executable surface is a single inode.

### 4.3 The shell itself

One `execve` from login into a confined session, no argument mangling of `-c`,
and the confinement is applied before any profile file, any rc file, and any
command is parsed. This is the design specified in section 6.

The shell hook does not cover paths that never reach the shell: `internal-sftp`,
`systemd --user`, cron, and at. Those are closed in `sshd_config` and in the
service manager, not here.

## 5. Why dash

The requirement was a small, auditable, permissively licensed POSIX shell with
proven `-c` behavior.

- dash has been `/bin/sh` on Debian and Ubuntu for over fifteen years, so its
  `-c` handling is exercised by every `scp`, `rsync`, and `git` over SSH
  invocation in existence. This is the failure mode that would otherwise appear
  months into deployment.
- It is the smallest POSIX shell in current use, small enough to read
  completely before adding security logic to it.
- BusyBox `ash` is itself derived from dash. The concept ports across with the
  libbb scaffolding removed and re-added, which makes the BusyBox step later a
  port rather than a second design.
- License is BSD-3-Clause, which is compatible with everything we might want to
  do downstream.

Shells that were considered and set aside: yash (GPL-2.0, but its identity is
portable POSIX conformance across any POSIX.1-2001 system, so a Linux-only
security module hook cuts against the project's purpose), mksh and the OpenBSD
ksh ports (same portability objection, plus built-in line editing that enlarges
the policy), bash (GPL-3.0-or-later, large, and readline adds terminfo,
inputrc, and history to the policy), ksh93 and the Schily Bourne shell
(EPL-1.0 and CDDL, both incompatible with a GPL combination if we ever want
one).

`loksh`, a Linux port of the OpenBSD ksh, is unusual in that a Linux-specific
security hook is not a scope violation there, so upstreaming would be easier.
It stays on the list as a second target if the dash fork proves the design.

## 6. Design

### 6.1 Where the domain is applied

`dashlock_init()` is called as the first statement of `main()` in `src/main.c`,
before `init()`, before `procargs()`, and therefore before `/etc/profile`,
`$HOME/.profile`, `$ENV`, and any `-c` argument are read or parsed. Errors are
reported with a direct `write(2)` to file descriptor 2, because the shell's own
output layer is not initialized yet.

Every failure path exits with status 78, which is `EX_CONFIG` from
`sysexits.h`. There is no degraded mode. A `dashlock` that falls back to
unconfined operation when the policy is missing is worse than no `dashlock` at
all, because the account then looks confined in `/etc/passwd` while it is not.

### 6.2 Name gating

The invocation name is `basename(argv[0])` with a leading `-` stripped, so a
login shell invoked as `-dashlock` is recognized. If that name is not
`dashlock`, the function returns immediately and the binary behaves exactly
like upstream dash.

This is deliberate. One binary can be installed as `dash` for general use and
hard-linked or symlinked to `dashlock` for confined accounts, and the general
case gains no new behavior and no new failure mode.

Build-time controls:

| Option | Default | Effect |
| --- | --- | --- |
| `--disable-dashlock` | enabled | remove the feature entirely; the binary is upstream dash |
| `--disable-dashlock-name-gate` | gate enabled | always confine, whatever the invocation name |
| `--with-dashlock-name=NAME` | `dashlock` | change the trigger name |
| `--with-dashlock-etcdir=DIR` | `/etc/dashlock` | administrator policy directory |
| `--with-dashlock-libdir=DIR` | `/usr/lib/dashlock` | vendor policy directory |

`--disable-dashlock-name-gate` is the setting for the strictest deployments: a
separate build, installed under any name, that cannot be invoked without a
policy. Whether the gate applies is a property of the binary, not of its
runtime environment, because a runtime switch for "should I confine myself" is
not a security control.

### 6.3 Policy lookup

The user is the real user ID, resolved to a name with `getpwuid_r()`. An
account with no password database entry, or one whose name is unusable as a
file name (outside printable ASCII, containing `/`, or 256 bytes and longer),
is keyed by its decimal user ID; those names are administrator-assigned, so
the fallback is not user-triggerable. A failing lookup, by contrast, refuses
the session rather than falling back, so a name service outage or buffer
exhaustion cannot select a different policy file. A set-user-ID or
set-group-ID invocation is refused before any policy file is read. Lookup
order, first hit wins:

```
1. /etc/dashlock/users/<name>
2. /usr/lib/dashlock/users/<name>
3. /etc/dashlock/users/default
4. /usr/lib/dashlock/users/default
5. refuse to start, exit 78
```

Administrator files in `/etc` mask vendor files in `/usr/lib` per file name,
following usrmerge and the conventions already used by systemd, tmpfiles, and
udev rules. The package ships item 4 and owns an empty
`/etc/dashlock/users/`. On a transactional or read-only `/usr`, the vendor
default is then tamper-resistant at runtime.

One convention is deliberately not adopted. A symlink to `/dev/null`
conventionally means "disabled". Here, disabled confinement is the dangerous
reading, so a `/dev/null` symlink is rejected like any other non-regular file
and the shell refuses to start. This is stated in the manual page because
somebody will sooner or later try it expecting the systemd meaning.

The lookup uses a bare user name and never a path fragment, so no input from
the session can traverse out of the policy directories.

### 6.4 File validation

The parse runs as the user, before any domain is applied, so this is the only
window in which the file's trustworthiness has to be established by the code
rather than by the kernel. The path is verified from the root downward,
one component at a time, opening each with `O_NOFOLLOW` and checking it on the
returned descriptor rather than on its name. This means the object checked is
the object used, no component can be swapped between check and use, and a
symbolic link anywhere in the chain is refused even when its target would pass.
The root, every intermediate directory, and the file must be owned by user
ID 0 and not writable by group or other; the file must be a regular file under
64 KiB. A FIFO in the path cannot stall startup, because the open is
non-blocking until the regular-file check has passed.

Rule paths get the same symbolic-link treatment for a sharper reason. A
root-authored policy routinely names a path whose leaf the confined account
owns, such as its home directory. If the account replaces that leaf with a
symbolic link before the session starts, a naive open would attach the Landlock
rule to wherever the link points, broadening a base allowlist or defeating a
narrowing layer. Each rule path is therefore resolved with symbolic-link
following disabled, and a link component is a refusal.

### 6.5 Policy format

Line oriented, one directive per line, `#` starts a comment. No includes, no
globbing, no shell expansion, no variable substitution. The parser is a
tokenizer over whitespace and colons and nothing else.

```
# /etc/dashlock/users/agent
abi-min  6

access   fs
rule     path-beneath:execute,read-file,read-dir:/usr
rule     path-beneath:read-file,read-dir:/etc
rule     path-beneath:read-file,write-file,read-dir,make-reg,make-dir,remove-file,remove-dir,refer,truncate:/home/agent
rule     path-beneath:read-file,write-file,read-dir,make-reg,make-dir,remove-file,remove-dir:/tmp

access   net-tcp
rule     net-port:connect-tcp:443

scope    abstract-unix-socket,signal
```

The access right names are taken from `setpriv(1)` in util-linux, which added
`--landlock-access` and `--landlock-rule` in version 2.40 and is the closest
thing to an established vocabulary for expressing a Landlock policy. The names
are the kernel uapi constants lowercased with hyphens: `execute`, `read-file`,
`write-file`, `read-dir`, `remove-file`, `remove-dir`, `make-char`, `make-dir`,
`make-reg`, `make-sock`, `make-fifo`, `make-block`, `make-sym`, `refer`,
`truncate`, `ioctl-dev`.

Reusing that vocabulary buys two things. A policy can be tested with a stock
`setpriv` command line before it is installed, and if the file format is ever
proposed upstream the naming discussion is already settled.

Parser rules that are security properties rather than conveniences:

- An unknown directive or an unknown access name is a refusal, never a skip.
  Silently ignoring a line the parser does not understand is the standard way a
  security configuration parser fails open.
- A policy with no `access` directive is a refusal. Handling nothing means
  confining nothing.
- The minimum ABI is computed from the directives the file uses, and the
  explicit `abi-min` only raises that floor. A policy that uses `scope` on a
  kernel at ABI 3 is refused rather than silently applied without the scoping.
- No best-effort degradation. If the running kernel cannot enforce the policy
  as written, the shell does not start.

### 6.6 Policy content

Two entries are needed in practice and are easy to leave out:

- Read and execute on the library tree. The domain is inherited, so every
  dynamically linked program the session runs needs the loader and the
  libraries. Under usrmerge a rule on `/usr` covers
  `/lib64/ld-linux-x86-64.so.2`, because Landlock evaluates the resolved inode
  and the compatibility symlink lands in `/usr/lib64`.
- Read on `/etc/ld.so.cache`. Without it the loader falls back to searching the
  directories, which works only if they are readable and is slower in any case.
  With neither, dynamic binaries fail in a way that reads like a permission bug
  three levels down.

A wildcard access category ("access fs") handles every right the build knows,
and the ceiling of that expansion is the build itself: AbiKnown, a constant
set at configure time, defaulting to the maximum of the access-right tables.
A session's effective ABI is the smaller of the kernel's and AbiKnown. A
kernel newer than the build changes nothing, because Landlock reads a ruleset
attribute by the size the caller passes and treats a ruleset with an older
layout exactly as that older ABI would; rights the build does not know stay
unhandled, which is what the author reviewed. Earlier revisions put the
ceiling into each policy file as "abi-max" and refused a newer kernel; that
made every author restate a fact about the binary, and the first kernel
reporting a newer ABI refused every session under the shipped default. A
policy that must mean the same across builds with different tables lists its
rights explicitly instead of using the wildcard.

We do not link `dashlock` statically. Dynamic linking keeps library patching a
distribution-level operation instead of a rebuild of every consumer, which is
the reason distributions object to vendored dependencies in the first place.
The security argument for static linking would have been a smaller policy, and
it does not survive contact with the inheritance property described above: the
policy has to grant the library tree for the children regardless.

### 6.7 Per-call narrowing

`dashlock --narrow NAME -c '...'` applies a second layer on top of the user
policy. `NAME` is a bare name matched against `[A-Za-z0-9_-]+`, resolved under
`/etc/dashlock/narrow/` and then `/usr/lib/dashlock/narrow/`, and validated
exactly like a user policy. It is only recognized as the first argument;
anywhere else it is passed through to the shell unchanged.

This is safe by construction. The kernel intersects layers, so a nested domain
can only remove access, never add it. Whoever builds the command line can
therefore be allowed to influence the policy without being trusted, because the
worst they can do is restrict themselves further. That property is what lets a
task runner select a per-invocation policy without the task runner becoming
part of the trusted computing base.

## 7. Portability: an unveil and pledge backend

dash descends from the NetBSD Almquist shell and builds on any POSIX system.
A Linux-only security hook in a shell with that history is the first objection
an upstream submission will meet, and the honest answer to it is a second
enforcement backend rather than an argument. The systems were surveyed for a
primitive with the same properties as Landlock: unprivileged, self-applied,
inherited by children, irrevocable.

| System | Primitive | Why it does not fit |
| --- | --- | --- |
| FreeBSD | Capsicum | capability mode removes the global namespace; after `cap_enter` a process cannot start arbitrary programs by path, and a shell must |
| NetBSD | kauth(9), secmodel | administrator-side frameworks; no unprivileged self-confinement call, despite dash's ancestry |
| macOS | `sandbox_init` | deprecated for a decade; the supported replacements are entitlement-based and not self-applied |
| Windows | restricted tokens, AppContainer | a broker constructs the confined process; a process cannot reduce only its filesystem view for itself and its descendants |
| OpenBSD | `unveil(2)`, `pledge(2)` | path-based filesystem restriction plus system-call-class restriction, both unprivileged and self-applied |

OpenBSD is the match, and the design needs the two calls together. The
reason is below; the manual pages do not state it.

### 7.1 What the kernel does on execve

The property this design depends on is what survives `execve`, and that is
only visible in the kernel source. Verified in openbsd/src as of 2026-09
(`sys/kern/kern_exec.c`, `sys_unveil` in `sys/kern/vfs_syscalls.c`,
`sys_pledge` in `sys/kern/kern_pledge.c`, `sys/sys/proc.h`):

- On `execve`, the unveil set and its lock survive only when execpromises are
  in force (`PS_EXECPLEDGE`). Without them the kernel destroys the unveil
  state; the comment in `kern_exec.c` reads "Clear our unveil paths out so the
  child starts afresh". An unveil-only confinement therefore ends at the first
  child. For this design, pledge is the inheritance vehicle and unveil is the
  restriction.
- `pledge(NULL, execpromises)` installs execpromises without restricting the
  calling process. Every later `execve` starts the new image pledged with
  exactly those promises, the flag is not cleared by `execve`, so
  grandchildren inherit the same way. A descendant can drop promises and
  cannot regain them; requests to raise are ignored or fail, and nothing
  widens.
- `unveil(NULL, NULL)` locks the set. Every later `unveil()` in that process
  and in every fork or exec descendant returns plain `EPERM`. Fork copies the
  set and the lock; under execpromises, `execve` keeps both.
- An unlocked unveil set is not a confinement: the process can keep adding
  paths anywhere it has any access. The lock is what turns a path list into a
  boundary.
- Executing a set-user-ID or set-group-ID binary under execpromises fails
  with `EACCES`. Linux under `no_new_privs` runs such a binary without the
  elevation; OpenBSD refuses the execution outright. Both fail closed; the
  failure mode differs and the manual page states it.

### 7.2 Three rules for every backend

The build selects exactly one enforcement backend: Landlock where
`linux/landlock.h` is present, unveil and pledge where those system calls
are. The policy format is one grammar with one parser on every backend, and
enforcement is bound by three rules:

1. A restriction the backend cannot enforce is a refusal, never a skip. On
   the unveil backend that covers the network category and net-port rules,
   the scope directive, a partial filesystem category (the first unveil call
   governs all four of its permission classes at once, so "handle reads
   only" is not expressible), and the `--narrow` layer. On the Landlock
   backend it covers the pledge directive.
2. A precondition that does not apply to the backend is ignored. `abi-min`
   gates the Landlock version ladder; unveil has no ladder and
   nothing to gate. Ignoring them loses nothing, because every feature they
   would guard is covered by rule 1.
3. Coarsening runs toward more denial, never less. The sixteen Landlock
   rights map onto unveil's four permission classes; where the classes are
   coarser, the backend denies more than the policy asked, not less. A right
   the backend does not mediate by path (ioctl-dev on unveil) contributes
   nothing to a rule, and a rule whose whole access list contributes nothing
   is refused as an authoring mistake rather than silently accepted.

### 7.3 The portable subset

The subset of the policy grammar that works on every backend unchanged:

```
access   fs
rule     path-beneath:ACCESS:PATH
```

with the class mapping, normative in the specification:

| unveil class | Landlock rights it covers |
| --- | --- |
| r | read-file, read-dir |
| w | write-file, truncate |
| x | execute |
| c | make-reg, make-dir, make-sock, make-fifo, make-char, make-block, make-sym, remove-file, remove-dir, refer |
| (none) | ioctl-dev: not path-mediated by unveil; device ioctls fall under pledge promises |

Everything outside the subset is backend-specific: `abi-min`,
`access fs:<subset>`, `access net-tcp`, `rule net-port` and `scope` belong to
the Landlock backend; a `pledge` directive belongs to the unveil backend.

The format deliberately gains no conditional syntax for this. No includes
and no OS switches inside a policy file: the parser being small enough to
review completely is a security property, and it outranks the convenience of
one file for two systems. Policies are per-host files under per-host
directories anyway; what the subset buys is that the allowlist body, the
part that takes review effort, reads identically on both.

### 7.4 What differs between the backends

| Property | Landlock backend | unveil and pledge backend |
| --- | --- | --- |
| granularity | 16 filesystem rights | 4 classes r, w, x, c |
| device ioctl | ioctl-dev per path | not path-mediated; pledge promise classes |
| TCP | per-port bind and connect rules | not expressible; `inet` promise is all or nothing |
| IPC scoping | abstract sockets and signals, ABI 6 | no equivalent; abstract socket namespace does not exist |
| version gate | ABI ladder: abi-min in the policy, the ceiling in the build | none; the mechanism ships complete with the release |
| symbolic links in rule paths | refused via handle-based resolution, no race | refused at verification; final component re-resolved by name, one-syscall race remains |
| inherited descriptors | not revoked | not revoked |
| set-ID binaries in session | run without elevation (`no_new_privs`) | execution refused with `EACCES` |
| a child confining itself | adds an intersecting layer, up to 16 | `unveil()` returns `EPERM` after the lock; pledge reductions work |
| AF_UNIX sockets by path | connect governed from ABI 9, outside current floor | `w` on the socket path governs connect |

The child-self-confinement row has an operational consequence: OpenBSD base
utilities routinely unveil themselves, treat a failing `unveil()` as fatal,
and will exit under this backend. That is the fail-closed direction, it is
visible and diagnosable, and the manual page documents it. The alternative,
leaving the set unlocked so children can unveil, is not a confinement.

### 7.5 The execpromises default

Since execpromises must be installed for inheritance, their content is
policy. The default is every promise this implementation knows, including
"error", and a `pledge` directive in the policy replaces that default with
the listed promises.

The reasoning: the restriction of this design is the filesystem allowlist,
and the Landlock backend restricts nothing else. Defaulting execpromises to
the full set keeps the two backends semantically as close as the mechanisms
allow; pledge then keeps the unveil set alive across `execve` and restricts
little by itself. "error" is included because a promise violation in an
arbitrary, never-pledge-aware child should produce an error return, which is
what a Landlock denial produces, rather than a killed process.

Version skew fails closed in both directions: an older kernel that does not
know a name in the list rejects the whole `pledge` call and the session
refuses; a newer kernel's new promise is absent from the list, so a child
needing it is denied. The parallel to the wildcard-and-ceiling reasoning in
section 6.6 is deliberate.

### 7.6 Considered and rejected

- Pledging the shell process itself. The shell needs a wide promise set, the
  set would need maintenance with every dash change, and it restricts the one
  process whose code we already control. Execpromises confine the processes
  that need it: everything the session starts.
- Emulating the network category by withholding `inet` and `dns` from
  execpromises. That denies all of TCP, UDP and name resolution to enforce a
  policy that asked for one closed port; the distance between what was
  written and what happens is too large for a security tool. Refusal is
  honest, per rule 1.
- Treating `scope abstract-unix-socket` as satisfied on OpenBSD because the
  abstract namespace does not exist there. True but unenforced: the
  specification would then claim an enforcement the code never performs, and
  the `signal` half of the same directive has no equivalent at all. Refusal,
  per rule 1.
- A userspace intersection of two unveil sets to support `--narrow`.
  Computable for directory prefixes, subtle for name-based entries, and
  exactly the kind of security-relevant complexity the kernel does for free
  on Linux. Deferred until something needs it.

### 7.7 Prior art, and what is taken from it

Three projects implement the same idea from the other side, OpenBSD's
vocabulary realized on Linux, where dashlock realizes Linux's vocabulary on
OpenBSD:

- jart/pledge (ISC): the pledge and unveil code of Cosmopolitan libc as a
  standalone port. Every pledge promise becomes a seccomp-BPF filter,
  including the argument-level checks a promise implies, open flags for
  `rpath` against `wpath`, socket families for `inet` against `unix`, the
  ioctl set for `tty`; unveil becomes Landlock. The split between syscall
  classes and paths is the one this design has.
- marty1885/landlock-unveil, "llunveil" (WTFPL, with a 0BSD alternative):
  an unveil-like function on Landlock, with the four classes r, w, x, c
  mapped onto Landlock rights, the inverse of the PortableClass table in
  section 7.3. Its stated limitation, that a file which does not exist
  cannot be unveiled, is the object-versus-name divergence of section 7.4
  seen from the other direction.
- gnoack/landlockjail (Günther Noack, a Landlock maintainer), the program
  llunveil was rewritten from, and the more authoritative reference for
  Landlock API usage and ABI handling.

What is taken from them is reading, not code. Two reasons, in order:

1. Licensing policy. This tree takes code only under BSD-family or GPL-family
   licenses. WTFPL does not pass that policy, and the jart port, permissive
   as ISC is, is bound to Cosmopolitan's own libc and would come in as a
   dependency rather than as a few reviewable functions, which the next
   reason rules out on its own.
2. The implementation stays one file with no new library. The reviewability
   of `dashlock.c`, the inert build byte-identical to upstream, and the
   upstream submission to dash all rest on that. Where an outside project
   has worked out a mapping, the mapping is recorded as a table with its
   provenance, the way the pledge promise names already are, and the code
   that applies it is written here.

The concrete consequence for the next step: syscall-class restriction on
Linux will be the `pledge` directive enforced with seccomp-BPF, with the
promise-to-syscall mapping derived from the jart tables as a reviewed
snapshot, promises without a clean Linux mapping refused under rule 1, the
architecture check first, and an error return rather than a kill by
default. One directive, two backends. The alternative that was proposed, a
deny-list profile copied from a container runtime, is rejected in section
12; it would govern a general login session with a list tuned for a known
workload and fail open on every syscall added later.

## 8. Assurance: testing and policy validation

Sections 1 to 7 describe what is confined and why. This section describes
how the confinement is kept correct over time, and how an administrator
checks a policy before it reaches a session. Both came out of the review of
2026-10-04; Vibe (Mistral AI) proposed them in that review, and the
corrections below are the result of reconciling the proposal with the
mechanisms as built.

The motivation is concrete. Three independent reviews
found four defects, and all four were in refusal logic: a network wildcard
that could apply with its network portion dropped, a non-directory component
in a higher-priority policy path that could fall through to a lower-priority
file, an errno read after close() that misclassified an open failure, and a
truncated read that could pass as narrowing. A defect in a refusal path does
not announce itself: the session still starts, and it starts weaker than the
policy says. Reviews are point-in-time, and nothing in the tree reruns them.
The development matrix (recording stubs, a kernel with Landlock compiled
out, sessions on Linux 6.12 and OpenBSD 7.9) proved itself while the backend
was built, but it exists in a developer's shell history and not in the
repository.

### 8.1 Test layers

The layers are ordered by cost. The cheap ones run on any host and catch the
class of defect the reviews actually found; the expensive ones need a kernel
and answer the question the cheap ones cannot.

Layer 1, parser and validation, pure C with no kernel and no filesystem. The
specification already lists, for every behavior, its preconditions, steps,
postconditions, error exits, and one negative example per error exit. That is
a test table: one row per negative example, asserting the exact refusal
message and exit 78. The four review findings become four named regression
rows. This layer is where most of the regression risk goes away for the least
effort, because the parser and the cross-checks are where the defects were.

Layer 2, the enforcement sequence, with recording stubs. The Landlock calls
pass through the `dl_sys_*` wrappers, which is the test seam: a build whose
wrappers record instead of calling the kernel lets the sequence be asserted
without privilege. What to assert differs per backend, and stating one
backend's invariant for the other would assert the wrong thing. On Landlock:
the ruleset attribute size matches the ABI branch, the handled masks match
the policy including wildcard expansion against the queried ABI, and
`restrict_self` is never reached after a failed `add_rule`.
On unveil the invariant is different and stronger: every rule path is
verified before the first `unveil` call, because the process's own view
shrinks with each call while `unveil` itself resolves unrestricted.

Layer 3, policy-file trust, which needs a filesystem fixture: root-owned and
non-root files, group-writable directories, a symbolic link in each position
of the chain, a FIFO, a file with a NUL byte, a file above the size ceiling,
and a truncated file. Each must refuse with its documented message, and only
a fully valid path may pass. The ownership checks need root-owned files, so
this group runs as root in a disposable environment, which also exercises the
real descriptor walk. One case does not belong in this group as a race: a
file that grows between the size check and the read. Racing an appender
against the reader is nondeterministic and will flake in automation; the
size-and-identity re-check is driven through a test seam instead, and a
single genuine-race run is kept as a manual check outside the automated set.

Layer 4, confinement on a real kernel: build the shell, install a policy for
a dedicated test account, start `dashlock`, and probe. An allowed read
succeeds, a denied read returns the documented error and exit status, the
domain survives `execve` into another interpreter, and every refusal category
produces exit 78. Only this layer exercises a confined session itself; the
others exercise models of it.

Layer 5, the backend contract. The refusal matrix (`access net-tcp`, `rule
net-port`, `scope`, a partial filesystem category, and `--narrow` on unveil;
the `pledge` directive on Landlock) is asserted as exit 78 on both backends.
The unveil backend already declares its prototypes for review hosts, so it
compile-checks on Linux; linking stub implementations of `unveil` and
`pledge` lets its sequence tests run there too, which is how the September
work verified the sequence before the OpenBSD sandbox existed.

### 8.2 Inertness as a tested property

The promise that the binary is byte-for-byte upstream dash under any other
name is a security claim, and it can be checked mechanically rather than
argued. A `--disable-dashlock` build should be identical to upstream dash
0.5.13.5 built from the same release tarball with the same flags and a fixed
`SOURCE_DATE_EPOCH`; with the gate enabled, the only differences among the
sources compiled into the shell are the two lines in `main.c` and the added
`dashlock` translation unit. The
behavioral corpus that backs this up stays small on purpose: it needs to
cover the option-parsing paths around the `--narrow` consumption, the only
point where the fork touches argv before the shell starts. The baseline is
upstream 0.5.13.5, not dash master, because comparing against master would
measure upstream's drift since the fork point rather than anything about the
fork. Making the comparison pass took one change: a disabled build still
linked an empty `dashlock.o`, visible as one file symbol in the symbol
table, so the object is now linked only when the feature is built.

### 8.3 Build matrix and the parser as attack surface

The configurations that must be built: `--disable-dashlock` (produces plain
dash), `--enable-dashlock`, and `--disable-dashlock-name-gate`. A build with
`--enable-dashlock` on a host where `linux/landlock.h` has been hidden must
fail, which is the fail-the-build contract made executable. Compilers are gcc
and clang with `-Wall -Wextra -Werror` on the fork's own objects (upstream
dash does not build under `-Wextra`, and its flags are not the fork's to
change), and one build of the kernel-free layers runs under the
undefined-behavior and address sanitizers.

The confinement and ABI-refusal tests need control over the kernel, which a
hosted runner does not give. A virtual machine with a pinned kernel and
controlled boot parameters is the deterministic option: the same image boots
kernels on both sides of a policy's ABI to exercise the `abi-min` and
refusal path from both sides of the build ceiling, and boots with Landlock disabled
to exercise the unavailable-kernel path. There is no hosted OpenBSD runner;
the OpenBSD leg runs in a local virtual machine under the platform's own
hypervisor, the same sandbox the backend was first tested in.

The parser is the pre-domain attack surface: it runs unconfined, before the
domain exists, on administrator-supplied input. Once the Layer 1 tests exist,
a coverage-guided fuzzer over the parse path seeded with the shipped policies
is cheap to add. A forking fuzzer needs no change to the refusal paths,
because a clean `_exit(78)` is a normal result to it, not a crash; only an
in-process fuzzer would require the parser not to exit, and that change is not
justified for the confined code. Run it bounded on each commit and longer
on a schedule.

Tests and fixtures live in their own directory with their own make target, so
the diff against upstream stays limited to the files the fork already touches.

## 9. A policy validation tool

An administrator today has two ways to find out that a policy is wrong: read
the specification and the manual page closely, or install the policy and open
a session. The first misses mistakes; the second breaks the session on the
account in question, and on kernel 6.12 the only diagnostic for a denial is
the error plus a system-call trace. Audit records arrive with ABI 7 on 6.15,
which helps after an incident but still does not tell an author in advance
whether a policy is well-formed and applicable.

The tool is a separate binary, `dashlock-check`, and the shell binary is left
untouched. Putting a check option on `dashlock` itself is not viable: any
first argument is a potential command name, and the existing `--narrow`
handling works only because it is consumed before the shell parses arguments.
That exception should stay the only one. The checker is built from the same
translation unit as the shell and uses the same lookup and parse code, so
validation and enforcement cannot diverge. It does this as a second
translation unit, `dashlock-check.c`, that includes `dashlock.c` the way the
unit drivers in the hints file do, provides its own entry point, calls the
same user-key, lookup, parse, and cross-check functions the shell calls, and
stops before enforcement. The one change this needs inside `dashlock.c` is
a code motion: each backend's pre-kernel checks move into a function of
their own, which the apply function calls first and the checker calls
directly. No second implementation of the refusal
functions is introduced; the refusal path that the four defects lived in is
not rebuilt for the checker, it is reused unchanged. First-finding-only is the
correct fidelity, because a session also stops at the first problem, so the
tool reproducing a session refusal reports exactly what the session reported.

Modes:

- Validate, the default. Read the policy the given user would receive,
  through the same lookup order and the same trust checks on the path, parse
  it, run every cross-check, and exit 0 when it would apply or 78 with the
  session's own message when it would not. Same message, same exit code: an
  administrator can reproduce a refusal and get the session's report.
- Kernel. Additionally query the running Landlock ABI and report whether the
  policy applies on this kernel: the derived required ABI, `abi-min`, any
  build's ceiling, the kernel value and the effective ABI. Meaningful only
  on the deployment kernel or a copy of it, which the output states.
- Dump. Print the normalized policy: handled rights per category, each path
  rule with its rights, net-port rules, scopes, the pledge set, and the
  derived required ABI. This is a canonical form, diffable between revisions
  and storable next to a policy as its reviewed meaning.
- Advisory lints, on stderr, never changing the exit code. The omissions that
  read like permission bugs belong in these lints, each one backend-specific: on
  Landlock, read and execute on the library tree missing, or the loader cache
  unreadable; on either backend, an interactive account whose policy grants
  nothing under the home directory, a declared access category with no rules,
  or an interactive session without terminal-device access. These are plain-
  language recommendations, labeled advisory, so the hard pass-or-fail
  semantics stay undiluted.
- Machine-readable output, a quiet form with one finding per line, so a
  policy repository can gate commits: a refusal is the session's own line,
  an advisory is one line marked as such, and the exit status carries the
  judgment. Line numbers are not part of it, because the refusal messages
  identify the directive, not the line. The shipped policies are validated
  this way on every change.

One mode from the proposal is deliberately left out. A computed preview of
the `--narrow` intersection would have to model, in user space, how Landlock
intersects layers: per right, per layer, with rules accumulating along a
path. That model would drift from the kernel, and a preview that can be
wrong about what a session allows is worse than none. The checker prints the
base policy and the narrowing policy side by side and lets the reader see
both; the kernel alone computes the intersection.

What the tool does not promise: that a session under the policy can log in
and do useful work. That is behavior, and it belongs to the Layer 4
confinement tests, which apply a policy in a disposable session and probe
expected allowed and denied operations. The checker answers whether a policy
is well-formed and applicable; the confinement tests answer whether a
confined session behaves as intended. The two are strongest together, which
is also the order of work: the parser tests, the stub sequence tests, and the
checker's validate mode first, since all three harden the code that runs
before the domain exists and the checker reuses the test scaffolding; then the
file-trust and confinement tests; then the checker's dump and kernel modes;
then the virtual-machine kernel control, the fuzzer, the OpenBSD leg, and the
inertness corpus.

## 10. Sequencing

| Phase | Deliverable | Where |
| --- | --- | --- |
| 1 | dash fork with `dashlock_init()`, policy parser, manual page | our tree |
| 2 | policy files for the accounts that need them | our tree |
| 3 | BusyBox: `--landlock-access` and `--landlock-rule` in the `setpriv` applet | proposed to BusyBox |
| 4 | BusyBox: `ash` applet alias with the same gating | local patch |

Phase 3 needs explaining. Adding confinement logic inside BusyBox `ash` is
unlikely to be accepted: `ash.c` is size-sensitive and delicate, the feature is
narrow, and a site-specific applet name is not something upstream will accept.
The route with a serious chance is to extend the existing BusyBox `setpriv` applet
with the options util-linux `setpriv` already has, because BusyBox's stated
design rule is compatibility with the original tool. That turns the review into
a check for symmetry instead of a debate about a new concept. The applet alias
then stays a local patch, small enough to rebase indefinitely.

Both submissions should include size numbers from `make bloatcheck` with the
configuration symbol off and on, because that is the first question BusyBox
review asks.

The implementation has been through three rounds of independent security
review, and the specification records the resulting change log. The findings
that became code fixes are recorded there. The ones that remain deployment
preconditions, a trusted launcher, a sanitized loader environment,
unprivileged user namespaces disabled, and no file capabilities on the binary,
are in section 11 and in the manual page, because self-confinement in a
dynamically linked binary cannot close them from inside.

Packaging follows the usual route: signed packages built in the Open Build
Service, with the policy files in a separate package so that a policy change
does not require a shell rebuild.

## 11. Limits

What this design does not do, in each case for a structural reason rather
than a missing feature.

- No protection against a hypervisor escape. Section 2 describes the threat
  that motivated the work; this design does not address it. The measures that
  do are a minimal virtual machine monitor, no user-mode networking stack in
  the emulator process, host-side mandatory access control around the emulator,
  CPU mitigations enabled, and a kernel that tracks upstream stable.
- The shell hook covers the shell. `internal-sftp`, `systemd --user`, cron, and
  at reach the account without passing through it.
- Confinement begins in `main()`. The dynamic loader and any constructors it
  runs execute first, so a launcher that passes a user-controlled environment
  hands the account `LD_PRELOAD` before the policy exists. The standard login
  paths sanitize the environment; a custom launcher must give the same
  guarantee. Self-confinement in a dynamically linked binary cannot close this
  from the inside.
- `no_new_privs` disables `sudo`, `su`, `pkexec`, and file-capability binaries
  such as `ping` for the session. Usually intended, occasionally a
  support surprise.
- `LANDLOCK_MAX_NUM_LAYERS` is 16. A script that re-invokes `dashlock`
  recursively past that depth gets `E2BIG` from `landlock_restrict_self` and,
  with fail-closed semantics, refuses to start. Unrealistic interactively,
  plausible in a build script.
- Diagnosing a denial on a 6.12 kernel means `EACCES` and `strace`. Audit
  records arrive with ABI 7 on kernel 6.15. If we get the choice, 6.15 is a
  better floor than 6.12 for operability, though not for function.
- Landlock has no hooks for `mount`, `chdir`, or metadata operations, and on
  the network side covers TCP only.
- The ownership check reads user ID 0 in the caller's user namespace. Where
  unprivileged user namespaces are enabled, a user can become namespace-root
  and present a policy that passes the check. For a confined account this is
  closed by disabling unprivileged user namespaces, or by a launcher that
  establishes the namespace before exec; the intended deployment combines the
  no-gate build with a trusted launcher. This is a deployment precondition,
  not something the shell can verify from inside.
- Every Landlock ruleset denies cross-hierarchy `refer` (link and rename)
  whether or not the policy handles it, so even a network-only or scope-only
  narrowing layer changes filesystem link and rename behavior. Policies that
  need cross-hierarchy rename must grant `refer` explicitly.

Limits specific to the unveil and pledge backend:

- The backend verifies every rule path component by component on directory
  handles and refuses symbolic links, but OpenBSD has no handle-based
  `unveil()`, so the final component is re-resolved by name inside the
  system call. A rule whose parent directory is owned by the confined
  account keeps a one-syscall race that the Linux backend does not have.
  Rule paths whose parents are root-owned do not.
- The rule-path verification opens each directory component for reading. A
  component the session cannot read is refused; for an unprivileged
  account that includes search-only (`--x`) directories. The Landlock
  backend, which opens with `O_PATH`, accepts them.
- Once the session's unveil set is locked, a child's own `unveil()` call
  returns `EPERM`. OpenBSD base utilities that unveil themselves and treat
  the failure as fatal will exit. This is the fail-closed direction; the
  manual page documents it.
- No `--narrow` layer, no network category, no scoping, no partial
  filesystem category: rule 1 of section 7.2 refuses each of them rather
  than approximating.

## 12. Open questions

1. Does the policy for the agent account belong in the `dashlock` package, in a
   separate policy package, or in a configuration management layer? A separate
   package is proposed, but this touches how we ship reference policies
   generally.
2. Container images that run their workload as root are the case where Landlock
   is most useful, because it is not capability-gated. Should we ship a
   reference policy for such images?
3. Do we want a session record: which policy file was in force, with a digest,
   written where the denial records go? When something is refused six months
   from now, "which ruleset was loaded" is the first question, and a `.d`
   directory that has changed since cannot answer it after the fact.
4. Is `loksh` worth a parallel attempt for the upstreamable variant? It would
   give us interactive line editing and a maintainer with no portability
   objection.
5. Does anything else we ship want the same treatment? The pattern generalizes
   to any process that reads untrusted instructions and then runs commands.
6. Syscall-class restriction on Linux. The shape is decided (section 7.7:
   the `pledge` directive enforced with seccomp-BPF, ERRNO rather than kill,
   promises without a Linux mapping refused), the timing is after the ABI
   ceiling move and as a specification delta of its own. A deny-list
   profile copied from a container runtime was considered and rejected: an
   allowlist of several hundred syscalls with argument rules is tuned for a
   known workload, breaks rootless containers, debuggers and newer
   programs in a general session, and a deny list fails open on every
   syscall added after it was written. A promise vocabulary names what a
   program needs, which is the question a policy author can answer.

## 13. References

- Landlock user-space documentation: `Documentation/userspace-api/landlock.rst`
  in the kernel tree, and `landlock(7)`
- `unveil(2)` and `pledge(2)`, OpenBSD manual pages; the execve coupling in
  section 7.1 is from the kernel source: `sys/kern/kern_exec.c`,
  `sys/kern/vfs_syscalls.c`, `sys/kern/kern_pledge.c` in openbsd/src,
  reviewed 2026-09
- `setpriv(1)`, util-linux 2.40 and later, for the access right vocabulary
- jart/pledge: OpenBSD pledge and unveil on Linux with seccomp-BPF and
  Landlock, ISC; https://github.com/jart/pledge
- marty1885/landlock-unveil: an unveil-like function on Landlock, WTFPL
  with a 0BSD alternative; https://github.com/marty1885/landlock-unveil
- gnoack/landlockjail: the Landlock jail llunveil was rewritten from, by a
  Landlock maintainer; https://github.com/gnoack/landlockjail
- Trail of Bits, "VMs won't contain cyber-capable agents", 2026-08-26
- dash upstream: Herbert Xu, current release 0.5.13.5
- Vibe (Mistral AI), review of 2026-10-04: the proposal behind the test
  infrastructure of section 8 and the policy validation tool of section 9

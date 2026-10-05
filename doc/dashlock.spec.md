# dashlock

## META

Deployment:   enhance-existing
Language:     any
Version:      0.7.0
Spec-Schema:  0.4.0
Hints-file:   dashlock.c.hints.md
Author:       Matthias G. Eckermann
Assisted-by:  Claude:claude-fable-5
Assisted-by:  Vibe (Mistral AI)
License:      BSD-3-Clause
Verification: none
Safety-Level: QM

---

This specification is written in PCD form but is not intended to be executed as
a full PCD translation. It is language-agnostic; the platform realizations,
C on Linux and C on OpenBSD, including system-call numbers, structure layouts,
header handling, and the build options, are in the accompanying hints file
`dashlock.c.hints.md`. The existing implementation is dash 0.5.13.5 by Herbert
Xu, a long-established C codebase that is not going to be regenerated from a
specification. What the PCD form buys here is the discipline: every rule that
decides whether a session is confined is written down once, in a place where it
can be reviewed and diffed, instead of being distributed across a patch.

The result is a fork named `dashlock`. It applies a kernel-enforced
confinement policy to itself before it reads any profile file, any rc file,
or any command, and the restriction is then inherited by every process the
session starts and cannot be removed by any privilege level. The enforcement
backend is selected at build time: Landlock on Linux, unveil and pledge on
OpenBSD. One grammar and one parser serve both; the backend contract in
enforce-policy states what each backend must refuse.

The addition is inert unless the binary is invoked under the name `dashlock`.
Invoked as `dash`, `ash`, or `sh`, the binary behaves exactly like upstream
dash: no new file is opened, no system call is made, no error path is reachable.

Target platforms are SLE 16 and later (kernel 6.12, Landlock ABI version 6)
and OpenBSD 7.9 and later (unveil and pledge, verified against the kernel
source as of 2026-09).

## TYPES

```
InvocationName := string
  // The final path component of the invocation name, with at most one leading
  // "-" removed, so that a login shell whose name has the conventional
  // leading "-" is recognised.

UserKey := string where non-empty and contains no "/" and is not "." and is not ".."
  // The account name from the password database, or the decimal real user ID
  // when no password database entry exists.

NarrowName := string where matches "^[A-Za-z0-9_-]+$"
  // Name of a narrowing policy. Deliberately excludes "/" and "." so that no
  // value supplied on the command line can leave the policy directories.

PolicyPath := string where non-empty
  // Absolute path of a policy file, always built by the program from a
  // configured directory plus a UserKey or a NarrowName.

AbiVersion := integer where value >= 1
  // Landlock ABI version. The running value is obtained from the kernel; a
  // required value is computed from a Policy.

FsAccessName := "execute" | "write-file" | "read-file" | "read-dir"
             | "remove-dir" | "remove-file" | "make-char" | "make-dir"
             | "make-reg" | "make-sock" | "make-fifo" | "make-block"
             | "make-sym" | "refer" | "truncate" | "ioctl-dev"
  // Filesystem access right names, identical to the names used by
  // setpriv(1) from util-linux, which are the kernel uapi constants
  // lowercased with underscores replaced by hyphens.

NetAccessName := "bind-tcp" | "connect-tcp"
  // Network access right names.

ScopeName := "abstract-unix-socket" | "signal"
  // IPC scoping names, available from Landlock ABI version 6.

PortableClass := "r" | "w" | "x" | "c"
  // The unveil permission classes. The mapping from FsAccessName values is
  // normative and one-directional: it may deny more than the named rights,
  // never less.
  //
  //   r  <- read-file, read-dir
  //   w  <- write-file, truncate
  //   x  <- execute
  //   c  <- make-reg, make-dir, make-sock, make-fifo, make-char,
  //         make-block, make-sym, remove-file, remove-dir, refer
  //
  // ioctl-dev maps to no class: unveil does not mediate device ioctl by
  // path, so the name contributes nothing on that backend. A rule whose
  // whole access set maps to nothing is refused by enforce-policy-unveil.

PledgeName := "audio" | "bpf" | "chown" | "cpath" | "disklabel" | "dns"
            | "dpath" | "drm" | "error" | "exec" | "fattr" | "flock"
            | "getpw" | "id" | "inet" | "mcast" | "pf" | "proc"
            | "prot_exec" | "ps" | "recvfd" | "route" | "rpath" | "sendfd"
            | "settime" | "stdio" | "tape" | "tty" | "unix" | "unveil"
            | "video" | "vminfo" | "vmm" | "wpath" | "wroute"
  // OpenBSD pledge promise names known to this implementation, the state of
  // OpenBSD 7.9 and -current as of 2026-09. Every backend validates pledge
  // directives against this list at parse time; only the unveil backend
  // enforces them, per the enforce-policy contract. "tmppath" was removed
  // from OpenBSD and is deliberately absent.

FsAccessSet := set of FsAccessName where non-empty
NetAccessSet := set of NetAccessName where non-empty
ScopeSet := set of ScopeName

PathRule := {
  access: FsAccessSet,
  path:   string where non-empty and starts with "/"
}

NetRule := {
  access: NetAccessSet,
  port:   integer where value >= 0 and value <= 65535
}
  // Port 0 is permitted only when access is exactly bind-tcp, where it means
  // "bind to a kernel-assigned ephemeral port". It is refused for a rule whose
  // access includes connect-tcp, where it has no meaning.

Policy := {
  handledFs:  FsAccessSet | empty,
  handledNet: NetAccessSet | empty,
  scoped:     ScopeSet,
  pathRules:  PathRule[],
  netRules:   NetRule[],
  abiFloor:   AbiVersion,
  abiCeiling: AbiVersion | none,
  pledged:    set of PledgeName | none
}
  // pledged is none when the policy contains no pledge directive; the unveil
  // backend then installs every PledgeName this implementation knows. An
  // empty set is not constructible: a pledge directive with no names is
  // refused at parse time.
  //
  // abiFloor and abiCeiling are precondition values for the landlock
  // backend; the unveil backend records and ignores them, per the
  // enforce-policy contract.
  //
  // abiFloor is the explicit floor from an abi-min directive, defaulting to 1.
  // The effective requirement is computed by compute-required-abi and is
  // always at least as high as abiFloor.
  //
  // abiCeiling is the optional cap from an abi-max directive. When set, a
  // running kernel whose ABI exceeds it is refused. Its purpose is the
  // wildcard categories: "access fs" handles every right the implementation
  // knows, so on a newer kernel with an unknown right the wildcard would
  // leave that right unhandled and therefore unrestricted; an author using a
  // wildcard sets abiCeiling to the newest ABI they reviewed. abiCeiling
  // below abiFloor is a contradiction and is refused. Every shipped example
  // policy that uses a wildcard sets abiCeiling, because an example is what
  // gets copied.

Refusal := {
  reason: string where non-empty
}
  // Every refusal states a reason that is written to file descriptor 2 and
  // identifies which rule rejected the session.
```

## BEHAVIOR: gate-on-invocation-name

Constraint: required

Decides whether the Landlock addition runs at all. It runs at the earliest
point of shell startup, before the shell initialises any of its own state and
before any profile file, rc file, or command is read.

MECHANISM: the decision is taken on `argv[0]` and nothing else. No environment
variable, no configuration file, and no command-line option can turn the
addition on for a binary invoked under another name, or off for a binary
invoked under the trigger name. A runtime switch for "should I confine myself"
would be under the control of the confined party and would therefore not be a
security control.

INPUTS:
```
argv: string[]   // the argument vector of the process, NULL-terminated
```

PRECONDITIONS:
- Invoked at the earliest point of shell startup, before any shell state exists
- The shell output layer is not initialised, so all diagnostics are written
  directly to the standard error file descriptor

STEPS:
1. If the feature was disabled at build time, return immediately.
2. If the name gate is enabled and argv is NULL or argv[0] is NULL, return
   immediately: the gate decides on argv[0], and without one the binary
   cannot have been invoked under the trigger name. If the name gate was
   disabled at build time, a missing argv does not return; continue at
   step 5, skipping only consume-narrow-argument, so that no argument
   vector can produce an unconfined session in that build.
3. Compute InvocationName from argv[0]: take the part after the last "/", then
   remove one leading "-" if present.
4. If the name gate is enabled and InvocationName differs from the configured
   trigger name, return immediately without opening any file or making any
   system call.
5. If the real and effective user IDs differ, or the real and effective group
   IDs differ → refuse with reason "set-user-ID or set-group-ID invocation
   refused". The policy is selected by the real user ID, so a set-ID
   invocation would confine one identity while holding the power of another,
   and no_new_privs drops nothing already in effect.
6. Continue with consume-narrow-argument.

POSTCONDITIONS:
- When the name does not match in a gated build, process state is
  bit-identical to unmodified dash: no file opened, no system call issued, no
  memory allocated
- When the name matches, control reaches the policy path and the process either
  becomes confined or exits
- In a build without the name gate there is no argument vector for which the
  process runs unconfined
- In a gated build the decision depends on argv[0] only

ERRORS:
- Refusal "set-user-ID or set-group-ID invocation refused" when real and
  effective identities differ

## BEHAVIOR/INTERNAL: consume-narrow-argument

Constraint: required

Recognises an optional narrowing policy on the command line and removes it from
the argument vector before the shell parses arguments.

MECHANISM: recognised in the first argument position only. Anywhere else the
token is an ordinary shell argument and is passed through unchanged. Bounding
the recognition to one position removes any interaction with the option parser
of the shell, which is left untouched.

INPUTS:
```
argv: string[]   // the argument vector, NULL-terminated
```

PRECONDITIONS:
- gate-on-invocation-name has decided that the addition runs

STEPS:
1. If argv[1] is NULL or differs from the literal "--narrow", record that no
   narrowing policy was requested and return.
2. If argv[2] is NULL → refuse with reason "--narrow requires an argument".
3. If argv[2] does not match the NarrowName pattern → refuse with reason
   "invalid narrow policy name".
4. If the build's enforcement backend has no narrowing layer → refuse with
   reason "narrowing is not supported by this backend". The refusal comes
   before any policy file is read, so the administrator sees the actual
   limitation instead of a missing-file message.
5. Record argv[2] as the requested NarrowName.
6. Remove argv[1] and argv[2] from the argument vector by moving every
   following element two positions towards the front, including the
   terminating NULL.
7. Return.

POSTCONDITIONS:
- The shell never observes the "--narrow" token or its argument
- The relative order of all remaining arguments is unchanged
- A "--narrow" token in any position other than the first is left in place and
  reaches the shell as an ordinary argument
- The recorded NarrowName contains no "/" and no "."

ERRORS:
- Refusal "--narrow requires an argument" when the value is missing
- Refusal "invalid narrow policy name" when the value contains anything outside
  [A-Za-z0-9_-]
- Refusal "narrowing is not supported by this backend" when the enforcement
  backend has no narrowing layer

## BEHAVIOR/INTERNAL: resolve-user-key

Constraint: required

Determines the UserKey used to select the policy file.

MECHANISM: the distinction between the fallback and the refusal is the
security property. The account name is assigned by the administrator and
cannot be changed by the account itself, so keying an odd or absent name by
user ID is not a downgrade a user can trigger. A failing lookup can be
user-adjacent (buffer exhaustion from a grown GECOS field, a name service
backend under load), so it refuses: no user-adjacent failure may select a
different policy file than the administrator intended.

INPUTS:
```
realUid: integer   // the real user ID of the process
```

PRECONDITIONS:
- The domain is not yet applied, so name service lookups still work

STEPS:
1. Look up realUid in the password database. On a buffer-too-small result,
   retry with a doubled buffer up to 64 KiB; on an interrupted call, retry
   unchanged.
2. If the buffer limit is reached, or the lookup returns any nonzero status →
   refuse with reason "user lookup failed". Only a zero return with a null
   result pointer is a definitive no-entry; a nonzero status can mean a
   missing name-service backend as readily as a missing user, and treating it
   as no-entry could select a weaker numeric or default policy on an induced
   backend failure.
3. On a definitive no-entry result (zero return, null result), format realUid
   as a decimal string, use it as the UserKey, and return.
4. If the returned name is unusable as a file key, format realUid as a
   decimal string, use it as the UserKey, and return. Unusable means: empty,
   ".", "..", 256 bytes or longer, or containing any byte outside the
   printable ASCII range "!" to "~", or containing "/". The printable-ASCII
   restriction also keeps control bytes from a hostile name service out of
   diagnostics written to the terminal.
5. Use the name as the UserKey and return.

POSTCONDITIONS:
- The UserKey never contains "/", is never "." or "..", and contains only
  printable ASCII
- An account with no password database entry, or with a name unusable as a
  file key, resolves to its decimal user ID
- No user-triggerable lookup failure selects a different policy file; such
  failures refuse
- The real user ID is used, not the effective one, because the account is what
  selects the policy

ERRORS:
- Refusal "user lookup failed" on buffer exhaustion or any lookup failure
  other than a definitive no-entry result

## BEHAVIOR/INTERNAL: locate-policy-file

Constraint: required

Selects the policy file for a UserKey, or for a NarrowName.

MECHANISM: administrator files under the configured `etc` directory mask vendor
files under the configured `lib` directory per file name, following the
convention already used for systemd units, tmpfiles, and udev rules. A
transactional or read-only vendor directory then makes the shipped default
tamper-resistant at runtime.

INPUTS:
```
key:      string   // a UserKey, or a NarrowName
isNarrow: boolean  // selects the users/ or the narrow/ subdirectory
```

PRECONDITIONS:
- key contains no "/" and is neither "." nor ".."

STEPS:
1. Build candidate 1 as etcdir + subdirectory + "/" + key.
2. Build candidate 2 as libdir + subdirectory + "/" + key.
3. If isNarrow is false, build candidate 3 as etcdir + "/users/default" and
   candidate 4 as libdir + "/users/default"; otherwise there are only two
   candidates.
4. Try each candidate in order; the first one that opens and passes
   open-and-validate-policy-file is the result.
5. If a candidate exists but fails validation → refuse with the reason reported
   by open-and-validate-policy-file, without trying any later candidate.
6. If no candidate exists → refuse with reason "no policy for user <key>", or
   "no narrow policy <key>" when isNarrow is true.

POSTCONDITIONS:
- Lookup order is etc-specific, lib-specific, etc-default, lib-default
- A narrowing policy has no default; a missing narrowing policy is a refusal
- A candidate that exists but fails validation stops the search, so a
  tampered administrator file is never silently replaced by a vendor file
- A symlink to /dev/null is not treated as "disabled"; it fails validation like
  any other non-regular file and the session is refused

ERRORS:
- Refusal "no policy for user <key>" when no user policy candidate exists
- Refusal "no narrow policy <key>" when no narrowing candidate exists
- Any refusal produced by open-and-validate-policy-file

## BEHAVIOR/INTERNAL: open-and-validate-policy-file

Constraint: required

Establishes that a candidate policy file is administrator-controlled. This runs
as the user, before any domain is applied. Trust in the file therefore has to be
established by the program here; everywhere after this the kernel enforces it.

INPUTS:
```
path: PolicyPath   // an absolute candidate path built by locate-policy-file
```

PRECONDITIONS:
- path was constructed by the program from a configured directory and a
  validated key, never taken from the environment or from the command line

STEPS:
1. Resolve and open path so that no component of it is a symbolic link and the
   final component is opened for reading only. If the file is genuinely absent,
   report "absent" so that the caller can try the next candidate. If a
   component of a higher-priority path exists but is not a directory, that is a
   broken or tampered hierarchy, not an absent file → refuse. On any other open
   error → refuse with reason "cannot open <path>".
2. Take every subsequent check from the open descriptor, never from the path
   string, so that the object checked is the object that was opened. On failure
   to read the descriptor's metadata → refuse with reason "cannot stat <path>".
3. If the file is not a regular file → refuse with reason "<path> is not a
   regular file".
4. If the owner is not user ID 0 → refuse with reason "<path> is not owned by
   root".
5. If the mode has the group-write or other-write bit set → refuse with reason
   "<path> is writable by non-root".
6. If the size exceeds 65536 bytes → refuse with reason "<path> is too large".
7. Verify the path from the root downward rather than from the file upward:
   open "/" and then each intermediate component relative to its already
   verified parent, refusing any component that is a symbolic link, and check
   each opened component on its own handle. If a component is not owned by
   user ID 0, or has the group-write or other-write bit set → refuse with
   reason "<dir> is writable by non-root", which names that component. Open the
   final component relative to the verified containing directory. Checking
   handles rather than names means the object checked is the object used, so
   no component can be substituted between the check and the use.
8. Read the file content to end of file rather than to the size reported by
   the earlier metadata check, into a buffer one byte larger than the size
   ceiling so that growth is detected rather than truncated. Refuse if the
   content exceeds the ceiling, if the size differs from the earlier check, or
   if the file identity changed during the read. An omitted suffix can contain
   a handled-access or scope directive, so a truncated policy can be weaker
   than the complete file and not only narrower. Policy updates must therefore
   be atomic, written to a new root-owned file and renamed into place.
9. If the content contains a NUL byte → refuse with reason "<path> contains a
   NUL byte". A NUL would silently truncate one line; truncation in an
   allowlist can only narrow, but a policy the parser did not see in full
   must not be applied.
10. Return the descriptor content and report "present".

POSTCONDITIONS:
- All checks are performed on open handles, so the object that was checked is
  the object that is read
- No component of the path is ever a symbolic link
- A file whose directory chain is writable by a non-root account is refused
  even when the file itself is correct, and a symbolic link anywhere in the
  chain is refused even when its target is correct
- A genuinely absent file lets the caller continue to another candidate; a
  non-directory component of a higher-priority path, and every other error,
  is a refusal

ERRORS:
- Refusal "cannot open <path>" for any open error other than ENOENT
- Refusal "cannot stat <path>"
- Refusal "<path> is not a regular file"
- Refusal "<path> is not owned by root"
- Refusal "<path> is writable by non-root"
- Refusal "<path> is too large"
- Refusal "<path> has a negative size"
- Refusal "<path> changed while it was being read"
- Refusal "<path> contains a NUL byte"
- Refusal "<dir> is writable by non-root"

## BEHAVIOR/INTERNAL: parse-policy

Constraint: required

Turns the content of a validated policy file into a Policy.

MECHANISM: a tokeniser over whitespace and colons, and nothing else. No
includes, no globbing, no variable substitution, no shell expansion, no
continuation lines. The parser is the last thing that runs unconfined, so its
input language is kept small enough to review completely.

INPUTS:
```
content: string   // the bytes of a validated policy file
source:  string   // the path, used only in diagnostics
```

PRECONDITIONS:
- content came from open-and-validate-policy-file

STEPS:
1. Split content into lines at "\n".
2. For each line: cut it at the first "#", then trim leading and trailing
   whitespace. Skip the line if nothing remains.
3. Split the remainder into a directive keyword and the rest of the line.
4. If the keyword is "abi-min": parse the rest as a decimal integer between 1
   and 255; on failure → refuse with reason "invalid abi-min in <source>".
   Record the maximum of it and the current abiFloor: with several abi-min
   lines the highest wins, so a later line cannot lower an earlier floor.
   If the keyword is "abi-max": parse the rest the same way; on failure →
   refuse with reason "invalid abi-max in <source>". Record the minimum of it
   and the current abiCeiling: with several abi-max lines the lowest wins.
5. If the keyword is "access": if the rest is "fs", request the filesystem
   wildcard, which handles every FsAccessName this implementation knows,
   intersected at enforcement time with those the running kernel supports.
   The wildcard cannot handle a right introduced after the implementation was
   written, which is what abi-max exists to guard. If the rest starts with
   "fs:", add each named right in the comma-separated remainder to handledFs.
   If the rest is "net-tcp", add both NetAccessName values to handledNet. If
   the rest starts with "net-tcp:", add each named right to handledNet. On any
   unknown name → refuse with reason "unknown access name <name> in <source>".
6. If the keyword is "rule": split the rest at the first colon to obtain the
   rule type.
   6a. For "path-beneath": split the remainder at the first colon into an
       access list and a path. The path may itself contain colons. On a missing
       colon → refuse with reason "malformed rule in <source>". Parse the
       comma-separated access list into an FsAccessSet; on an unknown name →
       refuse with reason "unknown access name <name> in <source>". If the path
       does not start with "/" → refuse with reason "rule path must be absolute
       in <source>". Append a PathRule.
   6b. For "net-port": split the remainder at the first colon into an access
       list and a port. Parse the access list into a NetAccessSet; on an
       unknown name → refuse with reason "unknown access name <name> in
       <source>". Parse the port as a decimal integer between 0 and 65535; on
       failure → refuse with reason "invalid port in <source>". If the port is
       0 and the access set includes connect-tcp → refuse with reason "port 0
       is only valid for bind-tcp in <source>". Append a NetRule.
   6c. For any other rule type → refuse with reason "unknown rule type <type>
       in <source>".
7. If the keyword is "scope": add each name in the comma-separated remainder to
   scoped; on an unknown name → refuse with reason "unknown scope name <name>
   in <source>".
8. If the keyword is "pledge": split the rest at whitespace into promise
   names. An empty list → refuse with reason "pledge without promises in
   <source>". Any name outside PledgeName → refuse with reason "unknown
   promise name <name> in <source>". Add the names to pledged; with several
   pledge lines the union is taken. The validation runs on every backend, so
   a typo is caught on the machine where the policy was written, not only on
   the one where it is enforced. A pledge directive does not make a policy
   handle access; the check in step 10 is unchanged.
9. For any other keyword → refuse with reason "unknown directive <keyword> in
   <source>".
10. After all lines: if handledFs and handledNet are both empty, scoped is
    empty, and neither wildcard category was requested → refuse with reason
    "<source> handles no access". If abiCeiling is set and is below abiFloor →
    refuse with reason "abi-max below abi-min in <source>".
11. Unless the filesystem wildcard category was requested: for every PathRule
    whose access set is not contained in handledFs → refuse with reason
    "rule for <path> uses access not handled in <source>". A rule granting an
    unhandled right would otherwise reach the kernel and fail there with a
    bare invalid-argument error; refusing here names the actual mistake. With
    the wildcard in force every parseable right is handled, and kernel
    support is guaranteed separately by compute-required-abi.
12. Unless the network wildcard category was requested: for every NetRule
    whose access set is not contained in handledNet → refuse with reason
    "rule for port <port> uses access not handled in <source>".
13. Return the Policy.

The wildcard categories "access fs" and "access net-tcp" are recorded as
requests and expanded against the running kernel only at enforcement time.
Expanding during parsing would query the kernel before the parser has
finished, so a malformed line later in the file would be reported as a kernel
problem. By definition a wildcard cannot raise the ABI version a policy
requires.

POSTCONDITIONS:
- An unknown directive, rule type, access name, or scope name is always a
  refusal and never a skipped line
- A policy that handles nothing is refused, because handling nothing would
  confine nothing while appearing to succeed
- Every rule that is accepted was fully understood by the parser
- The path in a path-beneath rule may contain colons, because only the first
  two colons are separators

ERRORS:
- Refusal "invalid abi-min in <source>"
- Refusal "invalid abi-max in <source>"
- Refusal "abi-max below abi-min in <source>"
- Refusal "unknown access name <name> in <source>"
- Refusal "unknown scope name <name> in <source>"
- Refusal "pledge without promises in <source>"
- Refusal "unknown promise name <name> in <source>"
- Refusal "unknown rule type <type> in <source>"
- Refusal "unknown directive <keyword> in <source>"
- Refusal "malformed rule in <source>"
- Refusal "rule path must be absolute in <source>"
- Refusal "invalid port in <source>"
- Refusal "port 0 is only valid for bind-tcp in <source>"
- Refusal "<source> handles no access"
- Refusal "rule for <path> uses access not handled in <source>"
- Refusal "rule for port <port> uses access not handled in <source>"

## BEHAVIOR/INTERNAL: compute-required-abi

Constraint: required (landlock backend)

Derives the Landlock ABI version a Policy needs, so that a policy is never
applied with parts of it silently dropped. Only the landlock backend calls
this; unveil has no version ladder, and every feature the ladder would gate
is refused there by the enforce-policy contract.

MECHANISM: the requirement is derived from the directives the file uses, and
the explicit abi-min directive can only raise it. Deriving it means an
administrator cannot under-declare by accident, and a policy written for a
newer kernel is refused on an older one instead of being partially enforced.

INPUTS:
```
policy: Policy   // output of parse-policy
```

PRECONDITIONS:
- policy was produced by parse-policy

STEPS:
1. Start with required = policy.abiFloor.
2. For every filesystem access right used in handledFs or in any PathRule,
   raise required to the ABI version that introduced it: 2 for "refer", 3 for
   "truncate", 5 for "ioctl-dev", 1 for all others.
3. If handledNet is non-empty, any NetRule exists, or the network wildcard
   category was requested, raise required to 4. The wildcard request must
   count here: without it, a policy stating the wildcard category alongside a
   filesystem category would compute a filesystem-only requirement, pass on an
   older kernel, and silently apply with the network portion dropped.
4. If scoped is non-empty, raise required to 6.
5. Return required.

POSTCONDITIONS:
- required is at least policy.abiFloor
- required reflects every feature the policy uses
- A policy using scoping can never be applied on a kernel below ABI 6

ERRORS:
- None. This behavior always succeeds.

## BEHAVIOR: enforce-policy

Constraint: required

Applies the policy to the calling process. After this returns, the shell
continues its normal startup and every process the session starts inherits
the restriction.

MECHANISM: the build selects exactly one enforcement backend at configure
time: landlock where the Linux Landlock interface is available, unveil where
the OpenBSD unveil and pledge system calls are. One policy grammar and one
parser serve every backend; what differs is enforcement, and it is bound by
three rules. First, a restriction directive the backend cannot enforce is a
refusal, never a skip. Second, a precondition directive that does not apply
to the backend is ignored; abi-min and abi-max gate the Landlock version
ladder and gate nothing elsewhere, and every feature they would guard on the
Landlock backend is already covered by the first rule. Third, access mapping
may coarsen toward more denial, never toward less.

Directive applicability, normative for every backend:

| Directive | landlock backend | unveil backend |
| --- | --- | --- |
| `abi-min`, `abi-max` | version gate | ignored, nothing to gate |
| `access fs` (wildcard) | enforced | enforced |
| `access fs:<subset>` | enforced | refused: unveil governs all four classes at once |
| `access net-tcp`, `rule net-port` | enforced | refused |
| `rule path-beneath` | enforced per right | enforced per PortableClass mapping |
| `scope` | enforced | refused |
| `pledge` | refused | enforced |

INPUTS:
```
base:   Policy            // the user policy
narrow: Policy | absent   // the narrowing policy, when --narrow was given
```

PRECONDITIONS:
- Both policies came from parse-policy
- No profile file, rc file, or command has been read or parsed yet
- On the unveil backend, narrow is always absent: consume-narrow-argument
  refused any narrowing request before a policy was read

STEPS:
1. On the landlock backend, run enforce-policy-landlock for base and narrow.
2. On the unveil backend, run enforce-policy-unveil for base.
3. Return; the shell continues its normal startup.

POSTCONDITIONS:
- The restriction is applied before /etc/profile, $HOME/.profile, $ENV, and
  any -c argument are read
- Every process the session starts inherits the restriction
- The restriction cannot be removed or relaxed afterwards by any privilege
  level
- There is no partial application: any failure inside the selected backend
  exits rather than continuing with a weaker restriction than the policy
  describes
- There is no best-effort mode; a policy the running kernel cannot enforce as
  written is refused

ERRORS:
- Every refusal produced by the selected backend behavior

## BEHAVIOR/INTERNAL: enforce-policy-landlock

Constraint: required (landlock backend)

Applies the policy with the Linux Landlock interface.

INPUTS:
```
base:   Policy            // the user policy
narrow: Policy | absent   // the narrowing policy, when --narrow was given
```

PRECONDITIONS:
- The build selected the landlock backend

STEPS:
1. If base records a pledge directive, or narrow does → refuse with reason
   "backend cannot enforce pledge in <source>".
2. Query the running Landlock ABI version from the kernel. On failure →
   refuse with reason "landlock unavailable: enable it in CONFIG_LSM or the
   lsm= boot parameter".
3. If base has an abiCeiling and the running version exceeds it → refuse
   with reason "kernel landlock ABI <m> exceeds policy abi-max <n>". Repeat
   for narrow when present.
4. Call compute-required-abi for base; if the running version is lower →
   refuse with reason "policy needs landlock ABI <n>, kernel provides <m>".
   If narrow is present, repeat for it.
5. Set PR_SET_NO_NEW_PRIVS to 1. On failure → refuse with reason "cannot set
   no_new_privs".
6. Apply base: create a ruleset whose handled access is the policy's handled
   sets masked to the rights the running ABI supports, and whose attribute
   size matches the running ABI. On failure → refuse with reason "cannot
   create ruleset".
7. For every PathRule: open the path as a resolvable handle without following
   any symbolic-link component, since a root-authored policy commonly names a
   path whose leaf the confined account controls, and a symbolic link there
   would attach the rule to a different hierarchy than the administrator
   named. On failure, including refusal of a symbolic-link component →
   refuse with reason "cannot open rule path <path>". Add a path-beneath rule
   for the opened handle and release it. On failure → refuse with reason
   "cannot add rule for <path>".
8. For every NetRule: add a net-port rule. On failure → refuse with reason
   "cannot add rule for port <port>".
9. Call landlock_restrict_self on the ruleset and close it. On failure →
   refuse with reason "cannot apply policy".
10. If narrow is present, repeat steps 6 to 9 for it, which adds a second
    layer.

POSTCONDITIONS:
- With a narrowing policy present, the second layer can only remove access,
  because the kernel intersects layers

ERRORS:
- Refusal "backend cannot enforce pledge in <source>"
- Refusal "landlock unavailable: enable it in CONFIG_LSM or the lsm= boot parameter"
- Refusal "kernel landlock ABI <m> exceeds policy abi-max <n>"
- Refusal "policy needs landlock ABI <n>, kernel provides <m>"
- Refusal "cannot set no_new_privs"
- Refusal "cannot create ruleset"
- Refusal "cannot open rule path <path>"
- Refusal "cannot add rule for <path>"
- Refusal "cannot add rule for port <port>"
- Refusal "cannot apply policy"

## BEHAVIOR/INTERNAL: enforce-policy-unveil

Constraint: required (unveil backend)

Applies the policy with the OpenBSD unveil and pledge system calls. The
kernel keeps the unveil set across execve only while execution promises are
in force, so the sequence installs both and the order below is normative.

MECHANISM: after the first unveil call the calling process's own filesystem
view is already restricted, while the unveil system call itself resolves
paths unrestricted. Every rule path is therefore verified first, on open
directory handles, before the first unveil call; the handles pin the
verified ancestors so that no component can be substituted between
verification and use. OpenBSD has no handle-based unveil, so the final
component is passed by name relative to its verified parent directory and
re-resolved inside the system call; verification refuses a symbolic link
there, and the residual one-system-call race is documented in the design and
the manual page.

INPUTS:
```
base: Policy   // the user policy
```

PRECONDITIONS:
- The build selected the unveil backend
- No narrowing policy was requested; consume-narrow-argument refused it
  otherwise

STEPS:
1. If base handles the network category or contains a NetRule → refuse with
   reason "backend cannot enforce access net-tcp in <source>" or "backend
   cannot enforce rule net-port in <source>".
2. If base scopes anything → refuse with reason "backend cannot enforce
   scope in <source>".
3. If base handles a filesystem subset rather than the wildcard → refuse
   with reason "backend cannot enforce access fs:<name> in <source>",
   where <name> is the first subset right. The first unveil call governs
   all four permission classes at once; a partial category is not expressible.
4. For every PathRule, map its FsAccessSet to a set of PortableClass values
   per the TYPES mapping. If the mapped set is empty → refuse with reason
   "rule for <path> grants nothing this backend mediates".
5. Save a handle to the current working directory. On failure → refuse with
   reason "cannot save working directory".
6. For every PathRule, before any unveil call: resolve the rule path from
   the root, one component at a time, on open directory handles, refusing
   any symbolic-link component; verify that the final component exists and
   is not a symbolic link; keep the handle of the verified parent directory.
   On any failure → refuse with reason "cannot open rule path <path>". A
   rule for the root directory itself has no parent: it needs no walk,
   the root cannot be a symbolic link, and step 7 applies it as an unveil
   of "/" without a directory change.
7. For every PathRule, in policy order: change directory to the verified
   parent handle, issue the unveil call for the final component with the
   mapped classes. On failure → refuse with reason "cannot unveil <path>".
8. Lock the unveil set. On failure → refuse with reason "cannot lock
   unveil".
9. Install the execution promises: the set from the policy's pledge
   directives, or, when the policy has none, every PledgeName this
   implementation knows. On failure, including a promise name the running
   kernel does not accept → refuse with reason "cannot set execution
   promises".
10. Restore the saved working directory and release the handles. On failure
    → refuse with reason "cannot restore working directory".

POSTCONDITIONS:
- The unveil set is locked and the execution promises are installed before
  any profile file, rc file, or command is read
- Every execve in the session starts the new image with the execution
  promises, which is the condition under which the kernel preserves the
  unveil set and its lock
- A descendant's own unveil call fails cleanly rather than widening the set
- The working directory of the shell is the same as before enforcement
- No unveil call is issued before every rule path has been verified

ERRORS:
- Refusal "backend cannot enforce access net-tcp in <source>"
- Refusal "backend cannot enforce rule net-port in <source>"
- Refusal "backend cannot enforce scope in <source>"
- Refusal "backend cannot enforce access fs:<name> in <source>"
- Refusal "rule for <path> grants nothing this backend mediates"
- Refusal "cannot save working directory"
- Refusal "cannot open rule path <path>"
- Refusal "cannot unveil <path>"
- Refusal "cannot lock unveil"
- Refusal "cannot set execution promises"
- Refusal "cannot restore working directory"

## BEHAVIOR: validate-policy

Constraint: optional

Reports whether a policy is well-formed and whether it would apply, without
confining anything. This behavior is the contract of a separate binary,
`dashlock-check`; the shell does not perform it. It exists so that an
administrator can check a policy before it reaches a session, instead of
learning of a mistake from a broken login.

MECHANISM: validate-policy reuses resolve-user-key, locate-policy-file,
open-and-validate-policy-file, parse-policy, and compute-required-abi,
unchanged and in the same order the shell runs them; in kernel mode it also
queries the running Landlock ABI the same way enforce-policy-landlock does.
It shares one parser and one set of trust checks with enforce-policy, so a
judgment it reports and a judgment the session makes cannot diverge. It
stops before enforce-policy: no ruleset is created, no unveil or pledge call
is made, the calling process is never confined. The refusal behavior is
reused exactly: the same message and the same exit 78 that a session would
print. Because the session stops at its first refusal, validate-policy
reports at most one refusal in validate and kernel modes, which is what makes
"run the tool, get the session's report" true. No second implementation of
refuse is introduced.

The shell translation unit, built as the shell, never reaches this behavior;
validate-policy exists only in the separate binary. The one change inside
that translation unit is a code motion: each backend's pre-kernel checks
move into a function of their own, which the apply function calls first and
the checker calls directly. This is a build-contract property, stated in the
hints file.

INPUTS:
```
mode:      "validate" | "kernel" | "dump"   // default "validate"
userkey:   the account whose policy to read  // default: the caller's own
narrowkey: NarrowName | absent               // checked as the session would; dumped side by side
lints:     boolean                           // emit advisory lints on stderr
quiet:     boolean                           // machine-readable findings, one per line
```

PRECONDITIONS:
- The trust checks on the policy path run as the invoking identity, so a run
  by root validates what root would receive and a run by an unprivileged user
  validates what that user would receive. The result is valid for the
  invoking identity, which the output states.
- Nothing in this behavior depends on the invoking process being the shell,
  being confined, or being gated on an invocation name.

STEPS:
1. Resolve userkey (resolve-user-key); default to the caller's own key.
2. Locate and open the policy (locate-policy-file,
   open-and-validate-policy-file). A trust-check failure is reported exactly
   as the session reports it, with exit 78, and validation stops.
3. Parse the policy (parse-policy) into a private copy of the buffer, so that
   the normalized form is available for dump mode after the in-place split.
   A parse refusal is reported as the session reports it, with exit 78.
4. If narrowkey is present: on the unveil backend → the refusal
   consume-narrow-argument raises, exit 78; on the landlock backend, locate,
   open, and parse the narrowing policy exactly as the session does, and
   apply the cross-checks of step 5 to it as well.
5. In validate and kernel modes, run every cross-check enforce-policy runs
   before it would create a ruleset: the backend-contract refusals for the
   build's backend, the required-ABI derivation on the Landlock backend, and
   on the unveil backend the class mapping and the rule-maps-to-nothing
   check. Any refusal is reported with exit 78.
6. In kernel mode, additionally query the running Landlock ABI the way
   enforce-policy-landlock does, and report the derived required ABI, the
   explicit floor, the ceiling in force, and the running kernel's ABI, with
   a statement that the judgment is for this kernel only.
7. In dump mode, print the normalized policy: handled rights per category,
   each PathRule with its rights, each NetRule, the scope set, the pledge
   set, and the derived required ABI. When narrowkey is present, print the
   base policy and the narrowing policy as two separate normalized blocks.
   Dump mode does not compute a narrowing intersection; the kernel is the
   only component that intersects layers.
8. If lints is set, emit advisory findings on stderr. Lints never change the
   exit code. The lint set is backend-appropriate and is listed in the hints
   file rather than in this specification, because lints are recommendations
   and none of them decides whether a policy applies.
9. Exit 0 when the policy would apply, 78 when it would not, 2 on a usage
   error such as an unknown mode or an unreadable argument.

POSTCONDITIONS:
- The calling process is not confined and no confinement system call was made
- Every pass-or-fail judgment matches what enforce-policy would decide for the
  same policy, backend, and identity
- Advisory lints did not affect the exit code

ERRORS:
- Every refusal that resolve-user-key, open-and-validate-policy-file,
  parse-policy, or the pre-enforcement cross-checks would raise, with the same
  message and exit 78
- Exit 2 on a usage error, which is distinct from a policy refusal

NOTES:
- validate-policy adds no option to the shell. The shell's only pre-shell
  argument handling stays consume-narrow-argument; a check mode on the shell
  binary would add argument surface to the one path that must remain inert,
  so the behavior lives only in the separate binary.
- A computed preview of the narrowing intersection is deliberately absent. It
  would require modeling layer intersection in user space, which would drift
  from the kernel; a preview that can misstate what a session allows is worse
  than none. The side-by-side dump gives the reviewer both layers without
  claiming to compute their intersection.

## BEHAVIOR: refuse

Constraint: required

Terminates the process when the session cannot be confined as specified.

MECHANISM: the refusal exit status is 78, the conventional "configuration
error" status, chosen because it is distinct from the shell's own exit
statuses. A shell exiting 2 for a usage error or 127 for a missing command is
common; 78 identifies a policy problem without ambiguity, which a calling
script can act on rather than having to parse the message.

INPUTS:
```
reason: string   // identifies which rule rejected the session
```

PRECONDITIONS:
- Reached only from a rule that decided the session cannot proceed

STEPS:
1. Write "dashlock: ", then the reason, then a newline, directly to the
   standard error file descriptor, because the shell output layer is not
   initialised. When the refusal stems from a failed system call or lookup,
   the reason ends with the raw error number, so that a layer-limit condition
   is distinguishable from any other failure without a debugger.
2. Exit the process with status 78 by the most direct means the platform
   offers, so that no exit handler and no buffered output of a partially
   initialised shell can run.

POSTCONDITIONS:
- No shell command is ever executed after a refusal
- The exit status is always 78, for every refusal reason
- The reason names the rule that refused, so the administrator can find the
  line in the policy without a debugger
- Nothing is written to standard output

ERRORS:
- None. This behavior terminates the process.

## PRECONDITIONS

The conditions in this section are normative. The security property does not
hold without them, and none of them can be established by the shell from
inside itself. A deployment that cannot meet them should treat this as a
defence-in-depth measure rather than a boundary.

Launch conditions, all the responsibility of whatever invokes the shell:

- The initial execution environment is not under the control of the confined
  party. In particular the dynamic loader environment is sanitised, since a
  preloaded object runs before any code in this specification.
- Either the invocation name is truthful, or the build has the name gate
  disabled. Where the confined party can choose the name it invokes, only the
  no-gate build is a boundary.
- On Linux, the user and mount namespaces are those of the trusted host.
  Ownership by user ID 0 is a namespace-relative fact there, so a party able
  to create its own user namespace can present its own policy as root-owned.
  OpenBSD has no unprivileged equivalent, so on the unveil backend this
  condition holds by construction.
- The process starts single-threaded, since a sibling thread created before
  the domain is applied does not inherit it.
- The set of inherited descriptors is known and intended. A descriptor opened
  before the domain exists is not subject to it, and cannot be revoked by it.
- No capabilities are in effect beyond those the deployment intends. Equal
  real and effective identifiers do not prove their absence, and no_new_privs
  does not remove privilege already held.
- Access paths that do not start a shell are closed separately: the SFTP
  subsystem, the per-user service manager, and scheduled job runners each
  reach the account without passing through this code.

Environment conditions:

- The existing dash 0.5.13.5 source tree is present and builds.
- On the landlock backend: the kernel provides Landlock at ABI version 6 or
  higher, which means 6.12 or later, and landlock appears in CONFIG_LSM or in
  the lsm= boot parameter.
- On the unveil backend: the system is OpenBSD 7.9 or later. The behaviors in
  this specification rely on kernel semantics verified against the kernel
  source as of 2026-09, in particular that the unveil set and its lock
  survive execve exactly when execution promises are in force; earlier
  releases have not been evaluated.
- Policy files and their directory chains are owned by root and not writable by
  group or other.
- The binary is not set-user-ID and not set-group-ID.

## POSTCONDITIONS

- A binary invoked under a name other than the trigger name behaves exactly
  like unmodified dash.
- A binary invoked under the trigger name either runs with the policy applied
  or does not run at all.
- The shell's own behavior after the domain is applied is unmodified: option
  parsing, profile handling, -c handling, and job control are untouched.

## INVARIANTS

- [observable]  Invoked as dash, ash, or sh, the binary opens no policy file and issues no confinement system call
- [observable]  Invoked as dashlock with no readable policy, the process exits 78 and executes no command
- [observable]  Every refusal exits with status 78 and writes one line beginning "dashlock: " to file descriptor 2
- [observable]  Every refusal writes nothing to standard output
- [observable]  The domain is applied before /etc/profile, $HOME/.profile, $ENV, or any -c argument is read
- [observable]  A --narrow token in any argument position other than the first reaches the shell unchanged
- [observable]  A policy file that is not owned by root, or whose directory chain is writable by non-root, is refused
- [observable]  A policy containing an unknown directive is refused rather than partially applied
- [observable]  On the landlock backend, a policy that uses scoping is refused on a kernel below ABI 6
- [observable]  On the landlock backend, a policy stating the network wildcard category is refused on a kernel below ABI 4, never applied with the network portion silently dropped
- [observable]  A rule requesting bind on an ephemeral port (port 0) is accepted; port 0 with connect is refused
- [implementation]  No code path exists that applies a subset of a policy and continues
- [implementation]  No environment variable influences whether or how the policy is applied
- [implementation]  All policy paths are built from a configured directory plus a validated key, never from the environment or the command line
- [implementation]  Every component of a policy path, from the root to the file, is checked on an open handle, never on its name
- [implementation]  No component of a policy path is ever a symbolic link, and a symbolic link anywhere in the chain is refused even when its target would pass
- [implementation]  No symbolic-link component of a rule path is ever accepted: the landlock backend resolves and uses the verified handle itself; the unveil backend verifies on directory handles and refuses a symbolic-link final component before the name is passed to the kernel
- [implementation]  Every failed system call's error status is captured before any cleanup call that could overwrite it
- [observable]  A refusal caused by a bad ancestor directory names that directory, not the full policy-file path
- [observable]  A refusal always exits 78 and never terminates by signal, even when the standard error descriptor is closed
- [observable]  Only a definitive no-entry name-service result keys a session by numeric ID; any lookup error refuses
- [implementation]  Diagnostics are written directly to the standard error file descriptor, never through the shell output layer, which is not initialised yet
- [implementation]  A narrowing layer can only intersect (landlock backend) or is refused outright (unveil backend); a caller that controls the command line can never widen the user policy
- [observable]  A set-user-ID or set-group-ID invocation is refused before any policy file is read
- [observable]  No user-triggerable name service failure selects a different policy file; such failures refuse the session
- [observable]  In a build without the name gate, no form of argument vector produces an unconfined session
- [observable]  A policy file containing a NUL byte is refused
- [observable]  A rule granting an access right its policy does not handle is refused at parse time
- [observable]  A pledge directive naming an unknown promise is refused at parse time on every backend
- [observable]  On the landlock backend, a policy containing a pledge directive is refused
- [observable]  On the unveil backend, a policy stating a network category, a network rule, a scope directive, or a partial filesystem category is refused; nothing is silently dropped
- [observable]  On the unveil backend, a --narrow request is refused before any policy file is read
- [observable]  On the unveil backend, the unveil set is locked and the execution promises are installed before any profile file, rc file, or command is read
- [implementation]  On the unveil backend, no unveil call is issued before every rule path has been verified on open directory handles
- [observable]  validate-policy confines nothing: it makes no confinement system call and the invoking process is not restricted afterwards
- [observable]  validate-policy reports a given policy's pass-or-fail judgment with the same message and exit code the session would produce for it
- [observable]  Advisory lints from validate-policy are written to the standard error descriptor and never change its exit code
- [implementation]  validate-policy introduces no second implementation of refuse and no check option on the shell binary; the shell translation unit built as the shell never reaches validate-policy

## EXAMPLES

### EXAMPLE: invoked_as_sh_is_inert
GIVEN:
  the binary is installed as /bin/dash with a symlink /bin/sh
  no policy file exists anywhere
WHEN:
  gate-on-invocation-name runs for argv[0] = "/bin/sh"
THEN:
  the function returns at the name comparison
  no policy file is opened
  no landlock system call is issued
  the shell starts normally and runs commands

### EXAMPLE: login_shell_name_is_recognised
GIVEN:
  /etc/dashlock/users/agent exists, is owned by root, and is mode 0644
  the account "agent" has /usr/bin/dashlock as its login shell
WHEN:
  gate-on-invocation-name runs for argv[0] = "-dashlock"
THEN:
  the leading "-" is removed and the name matches the trigger name
  the policy path /etc/dashlock/users/agent is selected
  the domain is applied before /etc/profile is read

### EXAMPLE: missing_policy_refuses
GIVEN:
  the binary is invoked as dashlock
  neither /etc/dashlock/users/agent nor /usr/lib/dashlock/users/agent exists
  neither users/default file exists
WHEN:
  locate-policy-file runs for UserKey "agent"
THEN:
  refuse is called with reason "no policy for user agent"
  stderr contains "dashlock: no policy for user agent"
  exit code is 78
  no command is executed

### EXAMPLE: user_writable_policy_refuses
GIVEN:
  /etc/dashlock/users/agent exists but is owned by user agent
WHEN:
  open-and-validate-policy-file runs for that path
THEN:
  refuse is called with reason "/etc/dashlock/users/agent is not owned by root"
  stderr contains that reason
  exit code is 78
  the vendor file under /usr/lib is not tried

### EXAMPLE: dev_null_symlink_refuses
GIVEN:
  /etc/dashlock/users/agent is a symlink to /dev/null
WHEN:
  open-and-validate-policy-file runs for that path
THEN:
  the open refuses the final symbolic-link component
  refuse is called, reporting that it cannot open /etc/dashlock/users/agent
  exit code is 78
  the session is not treated as unconfined

### EXAMPLE: unknown_directive_refuses
GIVEN:
  a valid policy file with one extra line: "allow-everything yes"
WHEN:
  parse-policy runs over that content
THEN:
  refuse is called with reason "unknown directive allow-everything in /etc/dashlock/users/agent"
  exit code is 78
  none of the recognised rules from the same file is applied

### EXAMPLE: policy_handling_nothing_refuses
GIVEN:
  a policy file containing only comments and one line "abi-min 6"
WHEN:
  parse-policy runs over that content
THEN:
  refuse is called with reason "handles no access"
  exit code is 78

### EXAMPLE: scoping_on_old_kernel_refuses
GIVEN:
  a policy containing "scope abstract-unix-socket,signal"
  a kernel providing landlock ABI version 3
WHEN:
  compute-required-abi returns 6 and enforce-policy compares it with the
  running version
THEN:
  refuse is called with reason "policy needs landlock ABI 6, kernel provides 3"
  exit code is 78
  the policy is not applied with the scoping silently dropped

### EXAMPLE: landlock_not_enabled_refuses
GIVEN:
  a kernel built with CONFIG_SECURITY_LANDLOCK=y but without landlock in the
  active lsm list
WHEN:
  enforce-policy queries the running ABI version
THEN:
  the query fails
  refuse is called with reason "landlock unavailable: enable it in CONFIG_LSM or the lsm= boot parameter"
  exit code is 78

### EXAMPLE: missing_rule_path_refuses
GIVEN:
  a policy containing "rule path-beneath:read-file:/opt/does-not-exist"
WHEN:
  enforce-policy opens the rule paths
THEN:
  refuse is called with reason "cannot open rule path /opt/does-not-exist"
  exit code is 78
  no partially built domain is applied

### EXAMPLE: successful_confined_session
GIVEN:
  /etc/dashlock/users/agent contains:
    abi-min 6
    access fs
    rule path-beneath:execute,read-file,read-dir:/usr
    rule path-beneath:read-file,read-dir:/etc
    rule path-beneath:read-file,write-file,read-dir,make-reg,make-dir,remove-file,remove-dir,refer,truncate:/home/agent
    access net-tcp
    rule net-port:connect-tcp:443
    scope abstract-unix-socket,signal
  a kernel providing landlock ABI version 6
WHEN:
  enforce-policy runs for that policy with no narrowing policy
THEN:
  no_new_privs is set
  one ruleset is created, six rules are added, and the ruleset is applied
  the shell continues startup and reads /etc/profile
  a later "cat /home/agent/notes" succeeds
  a later "cat /root/.ssh/id_ed25519" fails with EACCES
  a later "sudo -n true" fails because no_new_privs is set

### EXAMPLE: narrowing_layer_intersects
GIVEN:
  the user policy above is in force
  /etc/dashlock/narrow/build contains:
    abi-min 6
    access fs
    rule path-beneath:execute,read-file,read-dir:/usr
    rule path-beneath:read-file:/home/agent
WHEN:
  the process is started as: dashlock --narrow build -c 'cat /home/agent/notes; : > /home/agent/notes'
THEN:
  consume-narrow-argument removes "--narrow" and "build" from the vector
  the shell sees only "-c" and the command string
  the read succeeds because both layers allow read-file under /home/agent
  the write fails with EACCES because the second layer does not allow write-file
  the domain is not widened by anything on the command line

### EXAMPLE: narrow_name_with_traversal_refuses
GIVEN:
  the binary is invoked as: dashlock --narrow ../../etc/shadow -c true
WHEN:
  consume-narrow-argument validates the name against the NarrowName pattern
THEN:
  refuse is called with reason "invalid narrow policy name"
  exit code is 78
  no file is opened

### EXAMPLE: narrow_in_later_position_is_shell_argument
GIVEN:
  a valid user policy is in force
WHEN:
  the process is started as: dashlock -c 'echo --narrow build'
THEN:
  consume-narrow-argument finds argv[1] = "-c" and records no narrowing policy
  the shell executes the command
  stdout contains "--narrow build"

### EXAMPLE: setuid_invocation_refuses
GIVEN:
  the binary is installed set-user-ID root by mistake
  the account "agent" invokes it as dashlock
WHEN:
  gate-on-invocation-name compares the real and effective user IDs
THEN:
  refuse is called with reason "set-user-ID or set-group-ID invocation refused"
  stderr contains that reason
  exit code is 78
  no policy file is read

### EXAMPLE: nss_outage_refuses
GIVEN:
  the account resolves through a remote name service backend
  the backend is unreachable and the lookup fails with a connection error
WHEN:
  resolve-user-key retries on transient conditions and then sees a failure
  that is not a definitive no-entry result
THEN:
  refuse is called with reason "user lookup failed"
  stderr contains "dashlock: user lookup failed"
  exit code is 78
  the session is not keyed to the default policy file

### EXAMPLE: nul_byte_refuses
GIVEN:
  /etc/dashlock/users/agent is root-owned, mode 0644, and contains a NUL byte
  in the middle of a line
WHEN:
  open-and-validate-policy-file reads the content
THEN:
  refuse is called with reason "/etc/dashlock/users/agent contains a NUL byte"
  exit code is 78
  the truncated policy is not applied

### EXAMPLE: unhandled_rule_access_refuses
GIVEN:
  a policy containing:
    access fs:read-file
    rule path-beneath:write-file:/tmp
WHEN:
  parse-policy checks every rule against the handled access sets
THEN:
  refuse is called with reason "rule for /tmp uses access not handled in /etc/dashlock/users/agent"
  exit code is 78
  the mistake is named at parse time instead of failing in the kernel

### EXAMPLE: unveil_backend_confined_session
GIVEN:
  a build with the unveil backend on OpenBSD
  /etc/dashlock/users/agent contains:
    access fs
    rule path-beneath:execute,read-file,read-dir:/usr
    rule path-beneath:execute,read-file,read-dir:/bin
    rule path-beneath:read-file,read-dir:/etc
    rule path-beneath:read-file,write-file,read-dir,make-reg,make-dir,remove-file,remove-dir,refer,truncate:/tmp
WHEN:
  enforce-policy-unveil runs for that policy
THEN:
  every rule path is verified on directory handles before the first unveil call
  /usr and /bin are unveiled with classes rx, /etc with r, /tmp with rwc
  the unveil set is locked and the execution promises are installed
  the shell continues startup and reads /etc/profile
  a later "cat /etc/hosts" succeeds
  a later "cat /root/.ssh/id_ed25519" fails, the path is outside the set
  a later child that calls unveil() itself receives EPERM and cannot widen the set

### EXAMPLE: scope_refused_on_unveil_backend
GIVEN:
  a build with the unveil backend
  a policy containing "scope abstract-unix-socket,signal"
WHEN:
  enforce-policy-unveil checks the directives against the backend contract
THEN:
  refuse is called with reason "backend cannot enforce scope in /etc/dashlock/users/agent"
  exit code is 78
  the policy is not applied with the scoping silently dropped

### EXAMPLE: narrow_refused_on_unveil_backend
GIVEN:
  a build with the unveil backend
  the binary is invoked as: dashlock --narrow readonly -c true
WHEN:
  consume-narrow-argument records the narrowing request
THEN:
  refuse is called with reason "narrowing is not supported by this backend"
  exit code is 78
  no policy file is read

### EXAMPLE: pledge_refused_on_landlock_backend
GIVEN:
  a build with the landlock backend
  a valid policy with one extra line: "pledge stdio rpath exec"
WHEN:
  enforce-policy-landlock checks the directives against the backend contract
THEN:
  refuse is called with reason "backend cannot enforce pledge in /etc/dashlock/users/agent"
  exit code is 78
  the directive is not silently ignored

### EXAMPLE: check_reproduces_a_session_refusal
GIVEN:
  the landlock backend
  /etc/dashlock/users/agent handles the filesystem wildcard and contains one
    rule granting a right outside the handled set
WHEN:
  dashlock-check is run in validate mode for user agent
THEN:
  validate-policy stops at parse-policy with the same refusal the session raises
  the message is "rule for <path> uses access not handled in /etc/dashlock/users/agent"
  exit code is 78
  no confinement system call was made and the invoking process is not confined

### EXAMPLE: check_dumps_normalized_policy
GIVEN:
  the unveil backend
  a valid policy for user agent with a pledge directive and several path rules
WHEN:
  dashlock-check is run in dump mode for user agent
THEN:
  the normalized policy is printed: handled categories, each path rule with its
    rights, the scope set, the pledge set, and the derived required ABI
  exit code is 0
  no narrowing intersection is computed, because the kernel is the only
    component that intersects layers

### EXAMPLE: check_kernel_mode_reports_abi_shortfall
GIVEN:
  the landlock backend on a kernel with Landlock ABI version 4
  a valid policy for user agent containing "scope signal", which needs ABI 6
WHEN:
  dashlock-check is run in kernel mode for user agent
THEN:
  the report states required ABI 6, the policy floor, the ceiling in force,
    kernel ABI 4, and that the judgment holds for this kernel only
  refuse is called with reason "policy needs landlock ABI 6, kernel provides 4"
  exit code is 78, the same the session would produce here

### EXAMPLE: check_refuses_narrowing_on_unveil_backend
GIVEN:
  the unveil backend
  a valid policy for user agent
WHEN:
  dashlock-check is run in validate mode for user agent with narrowkey readonly
THEN:
  refuse is called with reason "narrowing is not supported by this backend"
  exit code is 78
  no narrowing policy file is read, as in the session

### EXAMPLE: check_usage_error_is_not_a_refusal
GIVEN:
  any backend
WHEN:
  dashlock-check is run with an unknown mode
THEN:
  a usage message is written
  exit code is 2, distinct from a policy refusal
  no policy file was read

## DEPENDENCIES

No new external library. The addition uses the platform standard library
plus, per backend, the confinement system calls: landlock_create_ruleset,
landlock_add_rule, and landlock_restrict_self on Linux, together with a
path-open call able to reject symbolic-link components; unveil and pledge on
OpenBSD, together with directory-handle opens, fstatat, and fchdir for the
rule-path verification. Fixed system-call numbers, structure layouts, and
platform-specific constants belong in the language hints file, not here.

Linux uapi header linux/landlock.h:
  minimum-version: any
  rationale: the header on the build host may predate the constants the code
             uses, so every constant, every structure, and every system call
             number is defined defensively in the new source file and the
             header is used only when present
  do-not-fabricate: true

The build must not gain a dependency on libcap, libseccomp, or any Landlock
helper library.

## DELIVERABLES

COMPONENT: confinement-integration
  purpose: Implements every BEHAVIOR in this specification, for the backend
           selected at build time
  required: true
  note: One new source file and one new header, so that the change to the
        existing shell entry point stays at two lines. Common code is shared;
        each backend sits in its own clearly delimited section. Target files
        src/dashlock.c and src/dashlock.h.

COMPONENT: shell-entry-hook
  purpose: Calls gate-on-invocation-name as the first statement of the shell
           entry point
  required: true
  note: Two lines: one include, one call. Target file src/main.c.

COMPONENT: build-integration
  purpose: Configure options, backend detection, and the new source file in
           the build
  required: true
  note: The backend is auto-selected: landlock where linux/landlock.h is
        present, unveil where the unveil and pledge system calls are, an
        error under --enable-dashlock where neither is. No configure option
        selects a backend by hand; a build that silently produced the wrong
        backend would be a policy decision nobody made. Target files
        configure.ac and src/Makefile.am.

COMPONENT: policy-examples
  purpose: A vendor default policy and a narrowing example, installed under the
           vendor directory
  required: true
  note: The default policy is backend-specific and the build installs the
        variant matching its backend under the name "default". The narrowing
        example is installed on the landlock backend only; the unveil backend
        refuses --narrow.

COMPONENT: documentation
  purpose: A manual page section describing the trigger name, the lookup order,
           the policy format, the exit status, and the limits
  required: true

COMPONENT: policy-checker
  purpose: Implements validate-policy as a separate binary, dashlock-check
  required: false
  note: A second translation unit that includes dashlock.c, as the unit
        drivers in the hints file do, so it shares resolve-user-key,
        locate-policy-file, open-and-validate-policy-file, parse-policy,
        compute-required-abi, the backend pre-kernel checks, and refuse with
        the shell, and cannot diverge from them. It adds no option to the
        shell binary. It ships with its own manual page, dashlock-check(8).
        Target files src/dashlock-check.c, src/dashlock-check.8, and the build
        rule in src/Makefile.am.

COMPONENT: test-suite
  purpose: Table-driven parser and cross-check tests, recording-stub
           enforcement-sequence tests, filesystem-fixture trust tests, and
           on-kernel confinement and backend-contract tests
  required: true
  note: Each negative example in this specification is one test row asserting
        the exact refusal message and exit 78; the review findings of
        2026-10-04 are named regression rows. The enforcement-sequence tests
        record through the system-call wrappers rather than confining. Tests
        and fixtures live in their own directory with their own make target,
        so the diff against upstream stays limited to the files the fork
        already touches. The confinement and ABI-refusal tests need a
        controlled kernel; the host matrix is a deployment concern, described
        in the design document and the hints file, not here.

COMPONENT: fuzz-driver
  purpose: Coverage-guided fuzzing of the parse path, seeded with the shipped
           policies
  required: false
  note: A forking fuzzer driver; a clean exit 78 is a normal result to it,
        so no refusal path changes for fuzzing. Bounded on each commit, longer
        on a schedule.

COMPONENT: continuous-integration
  purpose: Runs the test-suite layers on every commit: the host-independent
           layers on a hosted runner, the on-kernel layers in a virtual
           machine with a pinned kernel, the OpenBSD leg in a local virtual
           machine
  required: false
  note: The build matrix and the kernel-control requirement are in the
        design document and the hints file.

## TOOLCHAIN-CONSTRAINTS

- New external library: forbidden.
- Static linking: forbidden. Dynamic linking keeps library patching a
  distribution-level operation instead of a rebuild of every consumer. The
  policy has to grant read and execute on the library tree for the child
  processes in any case, so a static shell would not shrink the policy.
- Change to the shell's parser, option handling, or built-ins: forbidden.
  The policy checker is a separate binary and adds no option to the shell;
  the shell's only pre-shell argument handling stays consume-narrow-argument.
- Behavior change when the binary is invoked under a name other than the
  trigger name: forbidden. This is a testable property: a `--disable-dashlock`
  build is expected to be identical to upstream dash 0.5.13.5 built from the
  same release tarball with the same flags and a fixed source-date epoch, and
  with the gate enabled the only differences among the sources compiled
  into the shell are the two lines in src/main.c and the added translation
  unit.

Build-time options:

| Option | Default | Effect |
| --- | --- | --- |
| `--disable-dashlock` | enabled where a backend is detected | remove the addition entirely |
| `--disable-dashlock-name-gate` | gate enabled | always confine, whatever the invocation name |
| `--with-dashlock-name=NAME` | `dashlock` | trigger name |
| `--with-dashlock-etcdir=DIR` | `/etc/dashlock` | administrator policy directory |
| `--with-dashlock-libdir=DIR` | `/usr/lib/dashlock` | vendor policy directory |

`--disable-dashlock-name-gate` produces the build for the strictest
deployments: installed under any name, it cannot be invoked without a policy.
Whether the gate applies is a property of the binary, not of its runtime
environment.

## DELTA

Version 0.7.0 adds assurance; the confinement behavior is unchanged. It
introduces validate-policy,
an optional behavior realized as a separate binary, dashlock-check, that
reports whether a policy is well-formed and whether it would apply, while
confining nothing. The checker reuses the shell's own resolve-user-key,
lookup, trust checks, parser, required-ABI derivation, and refuse, so a
judgment it reports cannot diverge from a session's; it adds no option to the
shell binary, and it introduces no second implementation of refuse. Its
validate, kernel, and dump modes are specified, along with advisory lints that
never change the exit code. A computed preview of the narrowing intersection
was considered and rejected: user-space modeling of Landlock layer
intersection would drift from the kernel, so dump mode prints both layers
side by side and leaves the intersection to the kernel. The revision also
makes two existing promises testable: every negative example is now a required
test row, and the inertness promise is pinned to a byte-identity comparison
against upstream 0.5.13.5. A test-suite deliverable is added. The confinement
behaviors, the grammar, and the backend contract are unchanged from 0.6.0;
this revision adds no directive and changes no refusal; the one change inside
the shell's translation unit is a code motion that exposes each backend's
pre-kernel checks to the checker. The assurance design was proposed by Vibe
(Mistral AI) in the review of 2026-10-04 and amended as recorded in design.md
section 8.

Version 0.6.0 adds a second enforcement backend, unveil and pledge on
OpenBSD, without changing the grammar's parser model: one grammar, one
parser, every directive validated on every backend. enforce-policy is now a
backend contract with two internal realizations, enforce-policy-landlock
(the previous steps, unchanged in substance) and enforce-policy-unveil (new).
The contract states three rules: a restriction a backend cannot enforce is a
refusal, a precondition that does not apply is ignored, and access mapping
may only coarsen toward more denial. New in the grammar: the pledge
directive, whose promise names are validated at parse time everywhere and
enforced on the unveil backend as execution promises. The default execution
promises are every promise the implementation knows, because on OpenBSD the
promises are what the kernel requires for the unveil set to survive execve,
verified
in the kernel source rather than taken from the manual pages, and the
restriction of this design remains the filesystem allowlist. The unveil
backend refuses the network category, net-port rules, scope, partial
filesystem categories, and --narrow; consume-narrow-argument refuses a
narrowing request before any policy file is read. Rule paths are verified on
open directory handles before the first unveil call, since the calling
process's own view shrinks with each unveil while the unveil call itself
resolves unrestricted; the final component is re-resolved by name inside the
kernel, a residual documented in the design. The shipped default policy
becomes backend-specific.

Version 0.5.0 incorporates a third round of the independent review. Changes
since 0.4.0: the policy file is read to end of file rather than to the size
observed beforehand, and a file whose size or identity changed during the read
is refused, because an omitted suffix can contain a handled-access or scope
directive, so a truncated policy can be weaker than the complete file and not
only narrower; a negative reported size is refused before it can be converted for
allocation; the signal disposition that protects the refusal exit status is now
set after the invocation-name gate, so a binary invoked under a non-trigger
name issues no system call at all; both shipped example policies now set
abi-max, since an example is what gets copied; the procedural description of
path validation now matches the invariant and the implementation, describing
the descriptor walk from the root rather than a name-based walk from the file;
and the wildcard categories are described consistently as handling every right
the implementation knows, which is what abi-max guards.

The build contract is now stated in the implementation: the shell injects the
generated configuration header into every translation unit, so the feature
macros are visible without this file including it, and a guard fails the build
if that ever stops being true rather than silently producing a shell that
has the name and confines nothing.

Version 0.4.0 incorporates a second round of the independent review. Changes
since 0.3.0: only an unambiguous no-entry result from the name-service lookup
keys a session by numeric ID, and any lookup error now refuses, since a backend
failure could otherwise select a weaker policy; every failed system call's
error status is captured before any cleanup that could overwrite it, so an
error is never misclassified as a missing file; a refusal naming a bad ancestor
directory now names that directory rather than the full policy path; a refusal
exits 78 even when the standard error descriptor is closed, rather than dying by
signal; an optional abi-max directive lets a policy that uses a wildcard
category refuse a kernel newer than the author reviewed; and configured policy
directories have trailing slashes stripped so they cannot form an invalid
runtime path. The manual gains the same corrections, states that no component
of a policy or rule path may be a symbolic link, describes the object-identity
semantics of rule paths, and narrows the claim about what abstract-socket
scoping closes.

Version 0.3.0 incorporated a second, independent security review and makes the
specification language-agnostic; platform-specific realisation moved to the
accompanying hints file. Changes since 0.2.0: the network wildcard category now
raises the required ABI, so it can never be applied with the network portion
silently dropped; a non-directory component of a higher-priority policy path is
a refusal rather than a fall-through to a lower-priority file; the full policy
path is verified component by component on open handles with no symbolic link
followed anywhere in the chain, closing the gap between a handle-checked file
and name-checked ancestors; rule paths are opened without following any
symbolic-link component; port 0 is accepted for an ephemeral bind and refused
for connect; the argument count is corrected when the narrowing pair is
removed; and the feature refuses to build without a working account-name
lookup.

Version 0.2.0 incorporated a first review: strict name service failure
semantics, the printable-ASCII user key, the set-ID refusal, the fail-closed
empty-argument path in the no-gate build, the NUL byte refusal, the parse-time
handled-set check, monotone abi-min, error numbers in system-call refusals, and
explicit modes for the installed administrator directories.

Deferred to a later revision:

- An `ioctl-dev` rule for device nodes in the shipped example policies. The
  right is parsed and applied; no example uses it yet.
- Audit integration. Landlock gained audit records at ABI 7 on kernel 6.15;
  until the floor moves, a denial is diagnosed with EACCES and strace.
- Recording which policy file was in force for a session, with a digest.
- A group-keyed lookup step between the user file and the default file.

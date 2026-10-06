#!/bin/sh
# Layer 3: policy-file trust checks against filesystem fixtures.
#
# Builds nothing; uses t_check (dashlock-check compiled against the fixture
# root) and t_trustseam (the DL_FSTAT seam driver).  Needs root for the
# ownership fixtures and writes under FIXTURE_ROOT, so it only runs when
# DASHLOCK_TESTS_SYSTEM=1 is set; otherwise it reports SKIP (exit 77) so
# that "make check" stays green on a developer host.
#
# Every case asserts the exit status and the refusal message of the
# specification (open-and-validate-policy-file and locate-policy-file).

NOBODY=${DASHLOCK_TEST_UID:-65534}
CHECK=./t_check
SEAM=./t_trustseam

if [ "$(id -u)" != 0 ] || [ "${DASHLOCK_TESTS_SYSTEM:-0}" != 1 ]; then
	echo "1..0 # SKIP needs root and DASHLOCK_TESTS_SYSTEM=1"
	exit 77
fi
if [ ! -x "$CHECK" ] || [ ! -x "$SEAM" ]; then
	echo "Bail out! t_check or t_trustseam missing"
	exit 99
fi
# the fixture root is compiled into t_check; read it back rather than
# assuming it
FIXTURE_ROOT=$($CHECK -V | awk '{ for (i = 1; i <= NF; i++) if ($i == "directories") { sub(/\/etc$/, "", $(i + 1)); print $(i + 1) } }')
case "$FIXTURE_ROOT" in /*) ;; *) echo "Bail out! cannot read the fixture root from t_check -V"; exit 99;; esac

n=0
failed=0
E="$FIXTURE_ROOT/etc"
L="$FIXTURE_ROOT/lib"

reset() {
	rm -rf "$FIXTURE_ROOT"
	mkdir -p "$E/users" "$E/narrow" "$L/users" "$L/narrow"
	chmod 0755 "$FIXTURE_ROOT" "$E" "$E/users" "$E/narrow" "$L" \
		"$L/users" "$L/narrow"
}

valid() {
	printf 'access fs\nrule path-beneath:read-file,read-dir:/etc\n' > "$1"
	chmod 0644 "$1"
}

# expect NAME EXIT MESSAGE -- command...
expect() {
	name=$1; want=$2; msg=$3; shift 3
	n=$((n + 1))
	out=$("$@" 2>&1)
	rc=$?
	if [ "$rc" != "$want" ]; then
		echo "not ok $n - $name # exit $rc, expected $want: $out"
		failed=$((failed + 1))
	elif [ -n "$msg" ] && ! printf '%s' "$out" | grep -qF -- "$msg"; then
		echo "not ok $n - $name # message '$msg' not in: $out"
		failed=$((failed + 1))
	else
		echo "ok $n - $name"
	fi
}

echo "1..18"

reset; valid "$E/users/agent"
expect "valid root-owned 0644 policy applies" 0 "would apply" \
	$CHECK agent

reset; valid "$E/users/agent"; chown "$NOBODY" "$E/users/agent"
expect "file not owned by root" 78 "$E/users/agent is not owned by root" \
	$CHECK agent

reset; valid "$E/users/agent"; chmod 0664 "$E/users/agent"
expect "group-writable file" 78 "$E/users/agent is writable by non-root" \
	$CHECK agent

reset; valid "$E/users/agent"; chmod 0775 "$E/users"
expect "group-writable directory in the chain" 78 \
	"$E/users is writable by non-root" $CHECK agent

reset; valid "$E/users/real"; ln -s real "$E/users/agent"
expect "symbolic link as the policy file" 78 \
	"cannot open $E/users/agent (errno 40)" $CHECK agent

reset; mkdir "$E/real"; chmod 0755 "$E/real"; valid "$E/real/agent"
rm -rf "$E/users"; ln -s real "$E/users"
expect "symbolic link as a directory component" 78 \
	"cannot open policy path $E/users/agent (errno 20)" $CHECK agent

reset; mkfifo "$E/users/agent"; chmod 0644 "$E/users/agent"
expect "FIFO in place of the policy" 78 \
	"$E/users/agent is not a regular file" $CHECK agent

reset; printf 'access fs\0\nrule path-beneath:read-file:/etc\n' > "$E/users/agent"
chmod 0644 "$E/users/agent"
expect "NUL byte in the policy" 78 "$E/users/agent contains a NUL byte" \
	$CHECK agent

reset; { printf 'access fs\n'; dd if=/dev/zero bs=1 count=65537 2>/dev/null \
	| tr '\0' '#'; } > "$E/users/agent"; chmod 0644 "$E/users/agent"
expect "policy above the size ceiling" 78 "$E/users/agent is too large" \
	$CHECK agent

# Review finding 2: a regular file where a directory component should be,
# in the higher-priority tree, must refuse rather than fall through to the
# valid lower-priority file.
reset; rm -rf "$E/users"; valid "$E/users"; valid "$L/users/agent"
expect "regression: non-directory component refuses, no fall-through" 78 \
	"cannot open policy path $E/users/agent (errno 20)" $CHECK agent

reset; valid "$L/users/agent"
expect "vendor user file is found when the admin file is absent" 0 \
	"$L/users/agent would apply" $CHECK agent

reset; valid "$E/users/agent"; valid "$L/users/agent"
expect "admin file wins over the vendor file" 0 \
	"$E/users/agent would apply" $CHECK agent

reset; valid "$L/users/default"
expect "vendor default applies when no user file exists" 0 \
	"$L/users/default would apply" $CHECK agent

reset
expect "no policy at all" 78 "no policy for user agent" $CHECK agent

reset; valid "$E/users/agent"; valid "$L/narrow/readonly"
if $CHECK -V | grep -q 'backend landlock'; then
	expect "narrowing policy is located under narrow/" 0 "would apply" \
		$CHECK -n readonly agent
	reset; valid "$E/users/agent"
	expect "missing narrowing policy" 78 "no narrow policy readonly" \
		$CHECK -n readonly agent
else
	n=$((n + 1)); echo "ok $n - narrowing located # SKIP unveil backend"
	n=$((n + 1)); echo "ok $n - missing narrowing # SKIP unveil backend"
fi

# The seam cases: review findings 3 and 4.
reset; valid "$E/users/seam"
expect "seam: file grows during the read" 78 \
	"$E/users/seam changed while it was being read" $SEAM grow
expect "seam: fstat failure keeps its errno (captured before close)" 78 \
	"cannot stat $E/users/seam (errno 5)" $SEAM eio

rm -rf "$FIXTURE_ROOT"
[ "$failed" = 0 ]

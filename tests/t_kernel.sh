#!/bin/sh
# Layer 4: a confined session on a real Landlock kernel.
#
# Uses the built shell (src/dash, invoked as dashlock through a symbolic
# link), installs a policy for an unprivileged account under the real
# configured directories, and probes the session as that account.  Needs
# root, Landlock in the running kernel, setpriv(1), and the explicit
# DASHLOCK_TESTS_SYSTEM=1, because it writes the real policy directory;
# otherwise SKIP.  The policy files it creates are removed afterwards, and
# it refuses to run if a policy for the test account already exists.

[ "$(id -u)" = 0 ] && [ "${DASHLOCK_TESTS_SYSTEM:-0}" = 1 ] || {
	echo "1..0 # SKIP needs root and DASHLOCK_TESTS_SYSTEM=1"; exit 77; }
[ "$(uname -s)" = Linux ] || { echo "1..0 # SKIP Linux only"; exit 77; }

: "${abs_top_builddir:=$(cd "$(dirname "$0")/.." && pwd)}"
SHELLBIN="$abs_top_builddir/src/dash"
CHECK="$abs_top_builddir/src/dashlock-check"
[ -x "$SHELLBIN" ] && [ -x "$CHECK" ] && [ -x ./t_asuser ] || { echo "Bail out! build the tree first"; exit 99; }
"$CHECK" -V | grep -q 'backend landlock' || { echo "1..0 # SKIP landlock backend only"; exit 77; }
ETC=$("$CHECK" -V | sed 's/.*policy directories \([^ ]*\) and .*/\1/')
UID_T=${DASHLOCK_TEST_UID:-65534}
GID_T=$(getent passwd "$UID_T" | cut -d: -f4)
[ -n "$GID_T" ] || GID_T=$UID_T
KEY=$(getent passwd "$UID_T" | cut -d: -f1)
[ -n "$KEY" ] || KEY=$UID_T
[ -e "$ETC/users/$KEY" ] && { echo "Bail out! $ETC/users/$KEY exists; refusing to touch it"; exit 99; }

WORK=$(mktemp -d /var/dashlock-ktest.XXXXXX) || exit 99
chmod 0755 "$WORK"
cleanup() { rm -f "$ETC/users/$KEY" "$ETC/narrow/t-ro"; rm -rf "$WORK"; }
trap cleanup EXIT

mkdir -p "$ETC/users" "$ETC/narrow"
ln -sf "$SHELLBIN" "$WORK/dashlock"
echo "outside the allowlist" > "$WORK/secret"; chmod 0644 "$WORK/secret"
mkdir "$WORK/box"; chmod 01777 "$WORK/box"

policy() { printf '%s\n' "$@" > "$1"; }
cat > "$ETC/users/$KEY" << EOF
abi-min 1
access fs
rule path-beneath:execute,read-file,read-dir:/usr
rule path-beneath:read-file,read-dir:/etc
rule path-beneath:read-file,read-dir:/proc
rule path-beneath:read-file,write-file:/dev/null
rule path-beneath:read-file,write-file,read-dir,make-reg,remove-file,truncate:$WORK/box
EOF
chmod 0644 "$ETC/users/$KEY"
cat > "$ETC/narrow/t-ro" << EOF
abi-min 1
access fs
rule path-beneath:execute,read-file,read-dir:/usr
rule path-beneath:read-file,read-dir:/etc
rule path-beneath:read-file,write-file:/dev/null
rule path-beneath:read-file,read-dir:$WORK/box
EOF
chmod 0644 "$ETC/narrow/t-ro"

# Landlock present?  The checker's kernel mode asks the kernel.
if ! "$CHECK" -k "$KEY" >/dev/null 2>"$WORK/k.err"; then
	if grep -q 'landlock unavailable' "$WORK/k.err"; then
		echo "1..0 # SKIP $(cat "$WORK/k.err")"; exit 77
	fi
	echo "Bail out! $(cat "$WORK/k.err")"; exit 99
fi

ASUSER="$(pwd)/t_asuser"
as_user() { "$ASUSER" "$UID_T" "$GID_T" "$@"; }
n=0; failed=0
check() {	# check NAME WANT_EXIT WANT_SUBSTRING -- cmd...
	name=$1; want=$2; sub=$3; shift 3
	n=$((n + 1))
	out=$(cd "$WORK" && "$@" 2>&1); rc=$?
	if [ "$rc" != "$want" ]; then
		echo "not ok $n - $name # exit $rc, expected $want: $out"; failed=$((failed + 1))
	elif [ -n "$sub" ] && ! printf '%s' "$out" | grep -qF -- "$sub"; then
		echo "not ok $n - $name # '$sub' not in: $out"; failed=$((failed + 1))
	else
		echo "ok $n - $name"
	fi
}
D="$WORK/dashlock"
echo "1..10"
check "allowed read succeeds" 0 "hosts" as_user "$D" -c 'cat /etc/hosts | head -1; echo hosts'
check "denied read fails with EACCES" 1 "Permission denied" as_user "$D" -c "cat $WORK/secret"
check "the same read succeeds as plain dash (name gate)" 0 "outside the allowlist" as_user "$SHELLBIN" -c "cat $WORK/secret"
check "domain survives execve into another interpreter" 1 "Permission denied" as_user "$D" -c "/bin/sh -c 'cat $WORK/secret'"
check "no_new_privs is set in the session" 0 "NoNewPrivs:	1" as_user "$D" -c 'grep NoNewPrivs /proc/self/status'
check "write inside the allowlist works" 0 "" as_user "$D" -c "echo x > $WORK/box/f && rm $WORK/box/f"
check "narrowing layer removes write access" 1 "Permission denied" as_user "$D" --narrow t-ro -c "touch $WORK/box/g"
printf 'abi-min 1\naccess fs\nabi-max 1\nrule path-beneath:read-file:/etc\n' > "$ETC/users/$KEY"
check "abi-max below the kernel refuses with 78" 78 "exceeds policy abi-max 1" as_user "$D" -c 'echo must-not-run'
printf 'access fs\nfrobnicate\n' > "$ETC/users/$KEY"
check "unknown directive refuses with 78" 78 "unknown directive frobnicate" as_user "$D" -c 'echo must-not-run'
rm -f "$ETC/users/$KEY"
check "missing policy refuses with 78" 78 "no policy for user" as_user "$D" -c 'echo must-not-run'
[ "$failed" = 0 ]

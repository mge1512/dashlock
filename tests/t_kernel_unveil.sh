#!/bin/sh
# Layer 4 on OpenBSD: a confined session under the unveil and pledge
# backend.  Same gating as t_kernel.sh: root, DASHLOCK_TESTS_SYSTEM=1, the
# unveil backend built, and an unprivileged account to run as (doas is
# used to drop privileges, as the installed system would).  SKIP otherwise.

[ "$(uname -s)" = OpenBSD ] || { echo "1..0 # SKIP OpenBSD only"; exit 77; }
[ "$(id -u)" = 0 ] && [ "${DASHLOCK_TESTS_SYSTEM:-0}" = 1 ] || {
	echo "1..0 # SKIP needs root and DASHLOCK_TESTS_SYSTEM=1"; exit 77; }

: "${abs_top_builddir:=$(cd "$(dirname "$0")/.." && pwd)}"
SHELLBIN="$abs_top_builddir/src/dash"
CHECK="$abs_top_builddir/src/dashlock-check"
[ -x "$SHELLBIN" ] && [ -x "$CHECK" ] || { echo "Bail out! build the tree first"; exit 99; }
"$CHECK" -V | grep -q 'backend unveil' || { echo "1..0 # SKIP unveil backend only"; exit 77; }
ETC=$("$CHECK" -V | awk '{ for (i = 1; i <= NF; i++) if ($i == "directories") print $(i + 1) }')
LIB=$("$CHECK" -V | awk '{ print $NF }')
USER_T=${DASHLOCK_TEST_USER:-nobody}
KEY=$(id -un "$USER_T" 2>/dev/null) || { echo "1..0 # SKIP no account $USER_T"; exit 77; }
UID_T=$(id -u "$USER_T"); GID_T=$(id -g "$USER_T")
[ -x ./t_asuser ] || { echo "Bail out! build the tree first"; exit 99; }
ASUSER="$(pwd)/t_asuser"
[ -e "$ETC/users/$KEY" ] && { echo "Bail out! $ETC/users/$KEY exists; refusing to touch it"; exit 99; }

WORK=$(mktemp -d /var/dashlock-ktest.XXXXXX) || exit 99
chmod 0755 "$WORK"
cleanup() { rm -f "$ETC/users/$KEY"; rm -rf "$WORK"; }
trap cleanup EXIT
mkdir -p "$ETC/users"
# copies, not links: the test account must be able to execute them even
# when the build tree sits under a home directory it cannot traverse
cp "$SHELLBIN" "$WORK/dashlock" && cp "$SHELLBIN" "$WORK/dash"
chmod 0755 "$WORK/dashlock" "$WORK/dash"
echo "outside the set" > "$WORK/secret"; chmod 0644 "$WORK/secret"
mkdir "$WORK/box"; chmod 01777 "$WORK/box"
cat > "$ETC/users/$KEY" << END
access fs
rule path-beneath:execute,read-file,read-dir:/bin
rule path-beneath:execute,read-file,read-dir:/sbin
rule path-beneath:execute,read-file,read-dir:/usr
rule path-beneath:read-file,read-dir:/etc
rule path-beneath:read-file,write-file:/dev/null
rule path-beneath:read-file,write-file,read-dir,make-reg,remove-file,truncate:$WORK/box
END
chmod 0644 "$ETC/users/$KEY"

as_user() { "$ASUSER" "$UID_T" "$GID_T" "$@"; }
n=0; failed=0
check() {	# check NAME WANT_EXIT WANT_SUBSTRING -- cmd...
	name=$1; want=$2; sub=$3; shift 3
	n=$((n + 1))
	out=$(cd "$WORK" && as_user "$@" 2>&1); rc=$?
	if [ "$rc" != "$want" ]; then
		echo "not ok $n - $name # exit $rc, expected $want: $out"; failed=$((failed + 1))
	elif [ -n "$sub" ] && ! printf '%s' "$out" | grep -qF -- "$sub"; then
		echo "not ok $n - $name # '$sub' not in: $out"; failed=$((failed + 1))
	else
		echo "ok $n - $name"
	fi
}
D="$WORK/dashlock"
echo "1..9"
check "allowed read succeeds" 0 "localhost" "$D" -c 'cat /etc/hosts'
check "a path outside the set reports ENOENT" 1 "No such file" "$D" -c "cat $WORK/secret"
check "the same read succeeds as plain dash (name gate)" 0 "outside the set" "$WORK/dash" -c "cat $WORK/secret"
check "the set survives execve into another interpreter" 1 "No such file" "$D" -c "/bin/sh -c 'cat $WORK/secret'"
check "write inside the set works" 0 "" "$D" -c "echo x > $WORK/box/f && rm $WORK/box/f"
check "a set-ID binary is refused at exec (dash reports 126)" 126 "Permission denied" "$D" -c 'ping -c1 127.0.0.1'
check "--narrow is refused with 78 before any policy is read" 78 "narrowing is not supported" "$D" --narrow x -c 'echo must-not-run'
printf 'access fs\nscope signal\nrule path-beneath:read-file:/etc\n' > "$ETC/users/$KEY"
check "scope refuses with 78 on this backend" 78 "backend cannot enforce scope" "$D" -c 'echo must-not-run'
rm -f "$ETC/users/$KEY"
if [ -e "$ETC/users/default" ] || [ -e "$LIB/users/default" ]; then
	n=$((n + 1))
	out=$(cd "$WORK" && as_user "$D" -c 'echo ran' 2>&1); rc=$?
	if printf '%s' "$out" | grep -qF 'no policy for user'; then
		echo "not ok $n - default policy is found when the user file is missing # $out"; failed=$((failed + 1))
	else
		echo "ok $n - default policy is found when the user file is missing (exit $rc)"
	fi
else
	check "missing policy refuses with 78" 78 "no policy for user" as_user "$D" -c 'echo must-not-run'
fi
[ "$failed" = 0 ]

#!/bin/sh
# Inertness: under any name other than the trigger name the binary is
# upstream dash, and with the feature disabled the build is upstream dash
# byte for byte.
#
# 1. Byte identity: build the fork with --disable-dashlock and pristine
#    upstream 0.5.13.5 from the same autotools setup, the same flags and a
#    fixed SOURCE_DATE_EPOCH, and compare the two binaries with cmp.
# 2. Corpus: run every script in tests/corpus with the enabled build under
#    the names sh, ash and dash, and with the upstream build, and compare
#    stdout, stderr and exit status.
#
# The upstream source comes from UPSTREAM_SRC (a pristine 0.5.13.5 tree),
# or from the git history of the fork ("Release 0.5.13.5"); without either
# the test reports SKIP.

: "${abs_top_srcdir:=$(cd "$(dirname "$0")/.." && pwd)}"
: "${abs_top_builddir:=$abs_top_srcdir}"
CORPUS="$abs_top_srcdir/tests/corpus"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/dashlock-inert.XXXXXX") || exit 99
trap 'rm -rf "$WORK"' EXIT
export SOURCE_DATE_EPOCH=1700000000
BUILD_CFLAGS=${INERTNESS_CFLAGS:-"-O2 -g0"}

say() { echo "$@"; }
n=0; failed=0
ok()    { n=$((n + 1)); say "ok $n - $1"; }
notok() { n=$((n + 1)); say "not ok $n - $1"; failed=$((failed + 1)); }

# --- upstream source
mkdir -p "$WORK/upstream" "$WORK/fork"
if [ -n "$UPSTREAM_SRC" ]; then
	cp -R "$UPSTREAM_SRC/." "$WORK/upstream/"
elif git -C "$abs_top_srcdir" rev-parse --git-dir >/dev/null 2>&1; then
	rev=$(git -C "$abs_top_srcdir" log --format=%H -1 --grep='^Release 0.5.13.5')
	if [ -z "$rev" ]; then
		say "1..0 # SKIP no upstream release commit in history"
		exit 77
	fi
	git -C "$abs_top_srcdir" archive "$rev" | tar -x -C "$WORK/upstream"
else
	say "1..0 # SKIP set UPSTREAM_SRC to a pristine dash 0.5.13.5 tree"
	exit 77
fi
command -v autoreconf >/dev/null 2>&1 || { say "1..0 # SKIP autoreconf not found"; exit 77; }

# --- fork source: the tracked files as they are in the working tree
if git -C "$abs_top_srcdir" rev-parse --git-dir >/dev/null 2>&1; then
	git -C "$abs_top_srcdir" ls-files -z | (cd "$abs_top_srcdir" && tar -cf - --null -T -) | tar -x -C "$WORK/fork"
else
	cp -R "$abs_top_srcdir/." "$WORK/fork/"
	(cd "$WORK/fork" && rm -rf src/*.o src/dash tests/*.o) 2>/dev/null
fi

say "1..$(( 1 + $(ls "$CORPUS"/*.sh | wc -l) * 3 ))"

build() {
	(cd "$1" && autoreconf -fi && ./configure --disable-dashlock CFLAGS="$BUILD_CFLAGS" && make -j4) >"$1.log" 2>&1
}
if ! build "$WORK/upstream"; then
	say "Bail out! upstream build failed, see $WORK/upstream.log"; exit 99
fi
if ! build "$WORK/fork"; then
	say "Bail out! fork build failed, see $WORK/fork.log"; exit 99
fi
if cmp -s "$WORK/upstream/src/dash" "$WORK/fork/src/dash"; then
	ok "--disable-dashlock build is byte-identical to upstream 0.5.13.5"
else
	notok "--disable-dashlock build differs from upstream 0.5.13.5"
fi

# --- corpus: the enabled build under three names versus upstream
ENABLED="$abs_top_builddir/src/dash"
[ -x "$ENABLED" ] || { say "Bail out! $ENABLED not built"; exit 99; }
# A build without the name gate confines under every name by design, so
# inertness under other names is not one of its properties; the corpus
# is skipped for it and the byte-identity result above still counts.
if ! grep -q '^#define DASHLOCK_NAME_GATE' "$abs_top_builddir/config.h" 2>/dev/null; then
	for script in "$CORPUS"/*.sh; do
		for name in sh ash dash; do
			ok "corpus $(basename "$script" .sh) as $name # SKIP name gate disabled in this build"
		done
	done
	[ "$failed" = 0 ]
	exit $?
fi
mkdir -p "$WORK/names"
for name in sh ash dash; do
	ln -s "$ENABLED" "$WORK/names/$name"
done
for script in "$CORPUS"/*.sh; do
	base=$(basename "$script" .sh)
	SH="$WORK/upstream/src/dash" sh "$script" >"$WORK/expect.out" 2>&1
	echo "exit=$?" >>"$WORK/expect.out"
	for name in sh ash dash; do
		SH="$WORK/names/$name" sh "$script" >"$WORK/got.out" 2>&1
		echo "exit=$?" >>"$WORK/got.out"
		# the binaries print their own argv[0] in messages; normalize it
		sed "s|$WORK/names/$name|SHELL|g" "$WORK/got.out" >"$WORK/got.n"
		sed "s|$WORK/upstream/src/dash|SHELL|g" "$WORK/expect.out" >"$WORK/expect.n"
		if cmp -s "$WORK/expect.n" "$WORK/got.n"; then
			ok "corpus $base as $name matches upstream"
		else
			notok "corpus $base as $name differs from upstream"
			diff "$WORK/expect.n" "$WORK/got.n" | sed 's/^/# /'
		fi
	done
done
[ "$failed" = 0 ]

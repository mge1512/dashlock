# The test suite (dashlock.spec.md, DELIVERABLES: test-suite).  Tests and
# fixtures live here with their own targets, so the diff against upstream
# stays limited to the files the fork already touches.  "make check" runs
# the host-independent layers everywhere; the layers that need root, a
# Landlock kernel, or OpenBSD report SKIP unless DASHLOCK_TESTS_SYSTEM=1
# and the host qualifies.

AM_CPPFLAGS = -include $(top_builddir)/config.h -I$(top_srcdir)/src
DASHLOCK_WARN_CFLAGS =
AM_CFLAGS = $(DASHLOCK_WARN_CFLAGS)

# Where the trust fixtures are built; the root chain must be root-owned.
FIXTURE_ROOT = /var/dashlock-test

AM_TESTS_ENVIRONMENT = \
	abs_top_srcdir='$(abs_top_srcdir)'; export abs_top_srcdir; \
	abs_top_builddir='$(abs_top_builddir)'; export abs_top_builddir;

EXTRA_DIST = \
	unveil_stubs.h t_trust.sh t_kernel.sh t_kernel_unveil.sh \
	t_inertness.sh fuzz_parse.c \
	corpus/01-c-option.sh corpus/02-narrow-under-another-name.sh \
	corpus/03-stdin.sh corpus/04-s-with-args.sh \
	corpus/05-set-e-and-status.sh corpus/06-login-dash.sh

if BUILD_DASHLOCK

# Layer 1 and the contract (both backends), Layer 5 (unveil, stubbed),
# Layer 3 helpers.  Layer 2 is Landlock-specific and is not built on an
# unveil host, where the Landlock headers are absent.
check_PROGRAMS = t_parse t_unveil t_check t_trustseam t_asuser
if !BUILD_DASHLOCK_UNVEIL
check_PROGRAMS += t_sequence
SEQUENCE_TESTS = t_sequence
endif

t_check_CPPFLAGS = $(AM_CPPFLAGS) \
	-DDASHLOCK_TEST_FIXTURE_ROOT='"$(FIXTURE_ROOT)"'
t_trustseam_CPPFLAGS = $(AM_CPPFLAGS) \
	-DDASHLOCK_TEST_FIXTURE_ROOT='"$(FIXTURE_ROOT)"'

TESTS = t_parse t_unveil $(SEQUENCE_TESTS) t_trust.sh t_kernel.sh \
	t_kernel_unveil.sh t_inertness.sh

# The fuzz driver is not a test: build it by hand with a forking fuzzer's
# compiler, for example "make fuzz_parse CC=afl-clang-fast", and run
#   afl-fuzz -i ../policy/users -o findings -- ./fuzz_parse @@
EXTRA_PROGRAMS = fuzz_parse

endif

CLEANFILES = fuzz_parse

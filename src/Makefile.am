AM_YFLAGS = -d

COMMON_CFLAGS = -Wall
COMMON_CPPFLAGS = \
	-DBSD=1 -DSHELL

AM_CFLAGS = $(COMMON_CFLAGS)
AM_CPPFLAGS = -include $(top_builddir)/config.h $(COMMON_CPPFLAGS)
AM_CFLAGS_FOR_BUILD = -g -O2 $(COMMON_CFLAGS) 
AM_CPPFLAGS_FOR_BUILD = $(COMMON_CPPFLAGS)

COMPILE_FOR_BUILD = \
	$(CC_FOR_BUILD) $(DEFAULT_INCLUDES) $(AM_CPPFLAGS_FOR_BUILD) \
	$(CPPFLAGS_FOR_BUILD) \
	$(AM_CFLAGS_FOR_BUILD) $(CFLAGS_FOR_BUILD) 

bin_PROGRAMS = dash

dash_CFILES = \
	alias.c arith_yacc.c arith_yylex.c cd.c error.c eval.c exec.c expand.c \
	histedit.c input.c jobs.c mail.c main.c memalloc.c miscbltin.c \
	mystring.c options.c parser.c redir.c show.c trap.c output.c \
	bltin/printf.c system.c bltin/test.c bltin/times.c var.c

# dashlock.c is deliberately kept out of dash_CFILES: that variable is the
# input to mkinit, and the confinement code must take no part in the shell's
# init machinery.  It is also the only source file that must not include a
# shell header, because main.h redefines errno as (*dash_errno) and
# dash_errno is only assigned inside main().  With the feature disabled the
# object is not linked at all, so a --disable-dashlock build is byte for
# byte the upstream shell (tests/t_inertness.sh checks exactly that).
if BUILD_DASHLOCK
dashlock_CFILES = dashlock.c
else
dashlock_CFILES =
endif

dash_SOURCES = \
	$(dash_CFILES) \
	$(dashlock_CFILES) \
	alias.h arith_yacc.h bltin/bltin.h cd.h dashlock.h error.h eval.h \
	exec.h \
	expand.h \
	init.h input.h jobs.h machdep.h mail.h main.h memalloc.h miscbltin.h \
	myhistedit.h mystring.h options.h output.h parser.h redir.h shell.h \
	show.h system.h trap.h var.h
dash_LDADD = builtins.o init.o nodes.o signames.o syntax.o

# The policy checker is a second translation unit that includes dashlock.c
# (BEHAVIOR validate-policy); it links nothing from the shell proper.
# Warning flags for the fork's own objects only: upstream dash does not
# build under -Wextra -Werror, the fork's code does, and CI passes
#   make DASHLOCK_WARN_CFLAGS="-Wall -Wextra -Werror"
# The checker compiles dashlock.c through its include, so this covers both.
DASHLOCK_WARN_CFLAGS =

if BUILD_DASHLOCK
bin_PROGRAMS += dashlock-check
dashlock_check_SOURCES = dashlock-check.c
dashlock_check_CFLAGS = $(AM_CFLAGS) $(DASHLOCK_WARN_CFLAGS)
endif

HELPERS = mkinit mksyntax mknodes mksignames

BUILT_SOURCES = builtins.h nodes.h syntax.h token.h token_vars.h
CLEANFILES = \
	$(BUILT_SOURCES) $(patsubst %.o,%.c,$(dash_LDADD)) \
	$(HELPERS) builtins.def

man_MANS = dash.1
if BUILD_DASHLOCK
man_MANS += dashlock-check.8
endif
EXTRA_DIST = \
	$(man_MANS) dashlock-check.8 dashlock-check.c dashlock.c \
	mktokens mkbuiltins builtins.def.in mkinit.c \
	mknodes.c nodetypes nodes.c.pat mksyntax.c mksignames.c

token.h token_vars.h: mktokens
	$(AM_V_GEN)$(SHELL) $^

builtins.def: builtins.def.in $(top_builddir)/config.h
	$(AM_V_CC)$(COMPILE) -E -x c -o $@ $<

builtins.c builtins.h: mkbuiltins builtins.def
	$(AM_V_GEN)$(SHELL) $^

init.c: mkinit $(dash_CFILES)
	$(AM_V_GEN)./$^

nodes.c nodes.h: mknodes nodetypes nodes.c.pat
	$(AM_V_GEN)./$^

syntax.c syntax.h: mksyntax
	$(AM_V_GEN)./$^

signames.c: mksignames
	$(AM_V_GEN)./$^

mksyntax: token.h

$(HELPERS): %: %.c
	$(AM_V_CC)$(COMPILE_FOR_BUILD) -o $@ $<

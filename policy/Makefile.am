# Vendor policy files.  Installed under the directory chosen by
# --with-dashlock-libdir, which the shell searches after /etc.  Shipping the
# default here rather than in /etc means a read-only or transactional /usr
# makes it tamper-resistant at runtime.

EXTRA_DIST = users/default narrow/readonly

if BUILD_DASHLOCK
dashlockusersdir = $(DASHLOCK_LIBDIR)/users
dashlocknarrowdir = $(DASHLOCK_LIBDIR)/narrow

dist_dashlockusers_DATA = users/default
dist_dashlocknarrow_DATA = narrow/readonly

# The administrator directories are created empty.  A file placed in
# $(DASHLOCK_ETCDIR)/users masks the vendor file of the same name.
# Explicit mode: the administrator directories decide which policies exist,
# so their permissions must not depend on the umask of the install run.
install-data-hook:
	$(INSTALL) -d -m 0755 $(DESTDIR)$(DASHLOCK_ETCDIR)/users
	$(INSTALL) -d -m 0755 $(DESTDIR)$(DASHLOCK_ETCDIR)/narrow
endif

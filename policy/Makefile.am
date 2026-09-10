# Vendor policy files.  Installed under the directory chosen by
# --with-dashlock-libdir, which the shell searches after /etc.  Shipping the
# default here rather than in /etc means a read-only or transactional /usr
# makes it tamper-resistant at runtime.
#
# The default policy is backend-specific; the build installs the variant
# matching its backend under the name "default".  The narrowing example is
# installed on the landlock backend only: the unveil backend refuses
# --narrow, so a shipped file it can never use would only mislead.

EXTRA_DIST = users/default users/default.unveil narrow/readonly

if BUILD_DASHLOCK
dashlockusersdir = $(DASHLOCK_LIBDIR)/users

if BUILD_DASHLOCK_UNVEIL

install-data-local:
	$(INSTALL) -d -m 0755 $(DESTDIR)$(dashlockusersdir)
	$(INSTALL) -m 0644 $(srcdir)/users/default.unveil \
		$(DESTDIR)$(dashlockusersdir)/default

# The administrator directory is created empty.  A file placed in
# $(DASHLOCK_ETCDIR)/users masks the vendor file of the same name.
# Explicit mode: the administrator directories decide which policies
# exist, so their permissions must not depend on the umask of the install
# run.  No narrow directory: this backend refuses --narrow.
install-data-hook:
	$(INSTALL) -d -m 0755 $(DESTDIR)$(DASHLOCK_ETCDIR)/users

else

dashlocknarrowdir = $(DASHLOCK_LIBDIR)/narrow

dist_dashlockusers_DATA = users/default
dist_dashlocknarrow_DATA = narrow/readonly

# The administrator directories are created empty.  A file placed in
# $(DASHLOCK_ETCDIR)/users masks the vendor file of the same name.
# Explicit mode: the administrator directories decide which policies
# exist, so their permissions must not depend on the umask of the install
# run.
install-data-hook:
	$(INSTALL) -d -m 0755 $(DESTDIR)$(DASHLOCK_ETCDIR)/users
	$(INSTALL) -d -m 0755 $(DESTDIR)$(DASHLOCK_ETCDIR)/narrow

endif
endif

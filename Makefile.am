## Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = nostdinc
ourdefs = -DPATH_RSSH_CONFIG=\"@sysconfdir@/rssh.conf\" -DPATH_CHROOT_HELPER=\"@libexecdir@/rssh_chroot_helper\"
CFLAGS = @defcflags@ @static@ 
bin_PROGRAMS = rssh
libexec_PROGRAMS = rssh_chroot_helper
nodist_rssh_SOURCES = main.c pathnames.h config.h
rssh_SOURCES = rssh.h rsshconf.h rsshconf.c log.c log.h util.c util.h
rssh_chroot_helper_SOURCES = rssh_chroot_helper.c log.c log.h
dist_sysconf_DATA = rssh.conf
man_MANS = rssh.1 rssh.conf.5
EXTRA_DIST = $(man_MANS) CHROOT SECURITY rssh.spec

.c.o:
	$(CC) -c $(DEFS) $(ourdefs) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $<

install-exec-hook:
	chmod u+s $(libexecdir)/rssh_chroot_helper

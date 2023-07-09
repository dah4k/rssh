## Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = nostdinc
ourdefs = -DPATH_RSSH_CONFIG=\"@sysconfdir@/rssh.conf\" -DPATH_CHROOT_HELPER=\"@libexecdir@/rssh_chroot_helper\"
ourflags = @defcflags@ @static@ 
AM_CFLAGS = $(ourflags)
bin_PROGRAMS = rssh
libexec_PROGRAMS = rssh_chroot_helper
nodist_rssh_SOURCES = main.c pathnames.h config.h
rssh_SOURCES = rssh.h rsshconf.h rsshconf.c log.c log.h util.c util.h argvec.c argvec.h
rssh_chroot_helper_SOURCES = rssh_chroot_helper.c log.c log.h argvec.c argvec.h util.c util.h rsshconf.c rsshconf.h rssh.h
# This is different than PATH_RSSH_CONFIG; it is where the default gets
# installed, whereas PATH_RSSH_CONFIG is where rssh looks for the file.
dist_sysconf_DATA = rssh.conf.default
man_MANS = rssh.1 rssh.conf.5
EXTRA_DIST = $(man_MANS) CHROOT SECURITY LICENSE rssh.spec mkchroot.sh conf_convert.sh
base=`echo @PACKAGE_STRING@|tr " " "-"`

.c.o:
	$(CC) -c $(DEFS) $(ourdefs) $(AM_CFLAGS) $(CPPFLAGS) $(LDFLAGS) $<

install-exec-hook:
	chmod u+s $(libexecdir)/rssh_chroot_helper

rpm:	dist
	rpmbuild -ta --sign $(base).tar.gz
	cp /users/ddm/tmp/RPM/i386/$(base)-1.i386.rpm .
	cp /users/ddm/tmp/RPM/$(base)-1.src.rpm .
	gpg -ba --default-key ddm@pizzashack.org $(base).tar.gz
	mv $(base).tar.gz.asc $(base).tar.gz.sig


# rssh configure.ac, copyright 2003-2010 Derek D. Martin
# Process this file with autoconf to produce a configure script.
AC_INIT(rssh, 2.3.4, [rssh-discuss at lists dot sourceforge dot net])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([rssh.1])
AM_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile main.c pathnames.h rssh.conf.5 rssh.spec])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_CHECK_TOOL([STRIP],[strip])

if test yes = "$GCC" ; then
       defcflags="-O2 -Wall -Wshadow"
else
       echo "Using default flags"
fi

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdarg.h ctype.h syslog.h unistd.h errno.h libgen.h wordexp.h pwd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_STAT
AC_CHECK_FUNC(memset, [], [AC_MSG_ERROR([
rssh needs memset() to compile, but it's not available on your system.
Please notify code at pizzashack dot org.
Thanks.
])])  
AC_CHECK_FUNC(strdup, [], [AC_MSG_ERROR([
rssh needs strdup() to compile, but it's not available on your system.
Please notify code at pizzashack dot org.
Thanks.
])])  
AC_CHECK_FUNC(strtol, [], [AC_MSG_ERROR([
rssh needs strtol() to compile, but it's not available on your system.
Please notify code at pizzashack dot org.
Thanks.
])])  
AC_CHECK_FUNC(strerror, [], [AC_MSG_ERROR([
rssh needs strerror() to compile, but it's not available on your system.
Please notify code at pizzashack dot org.
Thanks.
])])  
AC_CHECK_FUNC(wordexp, [], [AC_MSG_ERROR([
rssh needs wordexp() to compile, but it's not available on your system.
Please notify code at pizzashack dot org.
Thanks.
])])  

AC_CHECK_FUNC(basename, , AC_CHECK_LIB(gen, basename))

######################
# Checks for programs

# check for OpenSSH version >= 3.5

AC_MSG_CHECKING([for OpenSSH >= v3.5])

ssh_version=`ssh -V 2>&1 |cut -d '_' -f2 | cut -c 1-3`
ssh_major_version=`echo $ssh_version | cut -d'.' -f 1`
ssh_minor_version=`echo $ssh_version | cut -d'.' -f 2`

# we MUST test to see if the version vars contain characters, as
# numeric comparison tests require that their arguments not be
# quoted.  If they are empty, the test will result in a syntax error.
if test -n "$ssh_major_version" -a -n "$ssh_minor_version"; then
	if test $ssh_major_version -gt 3; then
		AC_MSG_RESULT([yes - v$ssh_version])
		good_ssh=yes
	elif test $ssh_major_version -eq 3 -a $ssh_minor_version -ge 5; then
		AC_MSG_RESULT([yes - v$ssh_version])
		good_ssh=yes
	else
		AC_MSG_RESULT([no - v$ssh_version])
		good_ssh=no
	fi
fi

# Check for scp binary

AC_ARG_WITH(scp,
[  --with-scp              specify path to scp binary],
[scp_path="$withval"], [scp_path=""])

AC_PATH_PROG(scp_path, scp, [], [])
if test -z "$scp_path"; then
	AC_MSG_ERROR([can't find scp - please specify with --with-scp])
fi

if ! test -x "$scp_path"; then
	AC_MSG_WARN([specified scp binary does not exist])
fi

# Check for sftp-server binary

AC_ARG_WITH(sftp-server,
[  --with-sftp-server      specify path to sftp-server binary],
[sftp_path="$withval"], [sftp_path=""])

AC_PATH_PROG(sftp_path, sftp-server, [], [/usr/libexec:/usr/libexec/openssh:/usr/local/libexec/openssh:/usr/lib/openssh:/usr/lib:/usr/local/libexec:/usr/lib/ssh])
if test -z "$sftp_path"; then
	AC_MSG_ERROR([can't find sftp-server - please specify with --with-sftp-server])
fi

if ! test -x "$sftp_path"; then
	AC_MSG_WARN([specified sftp-server binary does not exist])
fi


# CVS, rdist, and rsync might not be installed.  But we don't want to force
# the user to configure bogus paths, so default to /usr/bin/*

# Check for cvs binary

AC_ARG_WITH(cvs,
[  --with-cvs              specify path to cvs binary],
[cvs_path="$withval"], [cvs_path=""])

AC_PATH_PROG(cvs_path, cvs, [], [])
if test -z "$cvs_path"; then
	AC_MSG_WARN([can't find cvs - using /usr/bin/cvs.  Use --with-cvs to override])
	cvs_path=/usr/bin/cvs
fi

if ! test -x "$cvs_path"; then
	AC_MSG_WARN([specified cvs binary does not exist])
fi

# Check for rdist binary

AC_ARG_WITH(rdist,
[  --with-rdist              specify path to rdist binary],
[rdist_path="$withval"], [rdist_path=""])

AC_PATH_PROG(rdist_path, rdist, [], [])
if test -z "$rdist_path"; then
	AC_MSG_WARN([can't find rdist - using /usr/bin/rdist.  Use --with-rdist to override])
	rdist_path=/usr/bin/rdist
fi

if ! test -x "$rdist_path"; then
	AC_MSG_WARN([specified rdist binary does not exist])
fi


# Check for rsync binary

AC_ARG_WITH(rsync,
[  --with-rsync              specify path to rsync binary],
[rsync_path="$withval"], [rsync_path=""])

AC_PATH_PROG(rsync_path, rsync, [], [])
if test -z "$rsync_path"; then
	AC_MSG_WARN([can't find rsync - using /usr/bin/rsync.  Use --with-rsync to override])
	rsync_path=/usr/bin/rsync
fi

if ! test -x "$rsync_path"; then
	AC_MSG_WARN([specified rsync binary does not exist])
fi


# disable static configuration

AC_ARG_ENABLE(static, 
[  --enable-static         enable static compilation [[auto]]],
[static_set="yes"], [static_unset="yes"])

AC_MSG_CHECKING([static compilation])

if test "$good_ssh" = "yes" -a "$static_set" != "yes"; then
	AC_MSG_RESULT([secure SSH found - not compiling rssh statically])
elif test "$enable_static" = "no" ; then
	AC_MSG_RESULT([static compilation DISABLED by configure option]) 
	AC_MSG_WARN([dynamic compilation not reccomended - be sure this is what you want])

else
	static="-static"
	if test "$static_unset" = "yes"; then
		AC_MSG_RESULT([static compilation ENABLED (detected old OpenSSH)])
	else
		AC_MSG_RESULT([static compilation ENABLED by configure option])
	fi
fi

# Do variable substitutions

AC_SUBST(scp_path)
AC_SUBST(sftp_path)
AC_SUBST(cvs_path)
AC_SUBST(rdist_path)
AC_SUBST(rsync_path)
AC_SUBST(prefix)
AC_SUBST(sysconfdir)
AC_SUBST(libexecdir)
AC_SUBST(PACKAGE_VERSION)
AC_SUBST(static)
AC_SUBST(defcflags)
AC_SUBST(CHROOT_HELPER)

AC_OUTPUT

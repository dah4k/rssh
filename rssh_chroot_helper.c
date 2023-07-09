/*
 * chroot_helper.c - functions to deal with chrooting rssh
 * 
 * Copyright 2003-2005 Derek D. Martin ( code at pizzashack dot org ).
 *
 * This program is licensed under a BSD-style license, as follows: 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* SYSTEM INCLUDES */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_ERRNO_H 
#include <errno.h>
#endif /* HAVE_ERRNO_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif /* HAVE_LIBGEN_H */
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif /* HAVE_SYSLOG_H */ 
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif /* HAVE_PWD_H */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */


/* LOCAL INCLUDES */
#include "rssh.h"
#include "rsshconf.h"
#include "pathnames.h"
#include "log.h"
#include "util.h"
#include "argvec.h"

/* GLOBAL VARIABLES */
extern int errno;
char *progname;
char *username;

/* FILE SCOPE VARIABLES */
static int  log_init = 0;

/* FILE SCOPE FUNCTIONS */


void ch_start_logging( void )
{
	/* set up logging - username should be set before this is called */
	if ( log_init ) return;
	log_set_facility(LOG_USER);
	log_set_priority(LOG_INFO);
	log_open();
	log_msg("new session for %s, UID=%d", username, getuid());
	/* all log messages from this point on are errors */
	log_set_priority(LOG_ERR);
	log_init = 1;
}

void ch_fatal_error( char *func, char *arg, char *strerr )
{

	/* drop privileges */
	if ( !geteuid() ) setuid(getuid());
	ch_start_logging();

	/* log error */
	log_msg("%s failed, %s: %s", func, arg, strerr);
	log_close();
	exit(1);
}


/* MAIN PROGRAM */
int main( int argc, char **argv )
{
	struct stat	s;
	ShellOptions_t	opts;
	long int	cmd;
	char		*conv;
	char		**argvec;
	char		*cmd_path;
	char		*homedir;
	struct passwd	uinfo;
	struct passwd	*temp;

	/* 
	 * Unfortunately, in order to maintain security, a lot of the code
	 * from the rssh main program must be duplicated.  Specifically, the
	 * config file must be parsed to get the chroot path, in order to
	 * prevent a user from being able to chroot() arbitrarily, which leads
	 * to easy root compromise if a user has shell access to the system.
	 * build_arg_vector() must be done here instead of in the main
	 * program, in order to prevent a directory transversal attack.
	 */ 

	/*
	 * As a possible future security enhancement, it should be possible to
	 * have rssh_chroot_helper authenticate cryptographically that it was
	 * exec()'d by rssh.  If rssh is SGID to some rssh-users group, it
	 * could store the public key for rssh_chroot_helper in a file which
	 * is only readable by that group.  Since rssh_chroot_helper is
	 * already SUID root, it could store its private key in some file that
	 * is only readable by root.  Obviously, care should be taken that no
	 * user who has shell access to the system can become a member of the
	 * rssh-users group.  The only thing stopping me from coding that now
	 * is my lack of knowledge of cryptographic programming.  
	 *
	 * As a further precaution, all users whose accounts will be protected
	 * by rssh should be in the rssh-users group, and both rssh and
	 * rssh_chroot_helper should be executable only by that group.  This
	 * can be done now, even without any cryptography.
	 */

	/* THIS CODE IS EXPOSED AS ROOT! */

	/* initialize variables to defaults */
	opts.rssh_umask = 022;
	opts.shell_flags = 0;
	opts.chroot_path = NULL;

	/* figure out our name, and give it to the log module */
	progname = strdup(log_make_ident(basename(argv[0])));

	/* get user's passwd info */
	if ( (temp = getpwuid(getuid())) ){
		uinfo = *temp;
		username = uinfo.pw_name;
	}
	else
		/* this probably should never happen */
		username = "unknown user!";

	/* make sure we have enough arguments, or exit with error */
	if ( argc != 3 ) ch_fatal_error(progname, "invalid arguments", 
	                                "wrong number of arguments");

	/* process the config file, don't log */
	if ( !(read_shell_config(&opts, PATH_RSSH_CONFIG, 0)) ){
		ch_fatal_error("read_shell_config()", PATH_RSSH_CONFIG,
				"errors processing configuration file!");
	}

	/* 
	 * opts.chroot_path is directory to chroot to.  Check to make sure it
	 * exists.  If it does, chroot and drop privileges, and cd to it.
	 */

	if ( stat(opts.chroot_path, &s) == -1 )
		ch_fatal_error("stat()", argv[1], strerror(errno));
	if ( chroot(opts.chroot_path) == -1 )
		ch_fatal_error("chroot()", argv[1], strerror(errno));

	/* END OF CODE EXPOSED AS ROOT! */

	setuid(getuid());
	ch_start_logging();

	log_msg("user's home dir is %s", uinfo.pw_dir);

	/* get the user's home dir */ 
	if ( !(homedir = extract_root(opts.chroot_path, uinfo.pw_dir)) ){
		log_msg("couldn't find %s in chroot jail", uinfo.pw_dir);
		homedir = strdup("/");
	}

	log_msg("chrooted to %s", opts.chroot_path);
	log_msg("changing working directory to %s (inside jail)", homedir);

	/* cd into / to avoid possibility of breaking out of the jail */
	if ( chdir("/") )
		ch_fatal_error("chdir()", "/", strerror(errno));

	/* make sure we can change directory to the user's dir */
	if ( chdir(homedir) == -1 )
		log_msg("could not cd to user's home dir: %s", homedir);

	if ( !(argvec = build_arg_vector(argv[2], 0)) )
		ch_fatal_error("build_arg_vector()", argv[2],
				"bad expansion");

	/* 
	 * This is the old way to figure out what program to run.  Since we're
	 * re-parsing the config file in rssh_chroot helper, we could get rid
	 * of this and redetermine it from the command line, and re-parse
	 * whether or not it's ok to run that command.  But, I don't think
	 * that's really necessary, nor worth the effort.  A user who is
	 * restricted by rssh will not be able to gain access to manipulate
	 * this on the command line, and a user who has full shell access
	 * can't gain anything they couldn't already do by manipulating it...
	 * so it seems OK to leave as is.
	 */

	/* argv[1] is "1" if scp, "2" if sftp, ... */
	cmd = strtol(argv[1], &conv, 10);
	if ( *conv ){
		log_msg("command identifier contained invalid chars");
		exit(2);
	}
	
	/* ok... what were we supposed to run? */
	switch (cmd){
	case 1:
		cmd_path = PATH_SCP;
		break;
	case 2:
		cmd_path = PATH_SFTP_SERVER;
		break;
	case 3:
		cmd_path = PATH_CVS;
		break;
	case 4:
		cmd_path = PATH_RDIST;
		break;
	case 5:
		cmd_path = PATH_RSYNC;
		break;
	default:
		log_msg("invalid command specified");
		exit(2);
	}

	/* now run it */
	execv(cmd_path, argvec);

	/* we only get here if the exec fails */
	ch_fatal_error("execv()", cmd_path, strerror(errno));
	/* and we never get here, but it shuts gcc up */
	exit(1);
}


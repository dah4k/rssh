/*
 * chroot_helper.c - functions to deal with chrooting rssh
 * 
 * Copyright 2003 Derek D. Martin ( code at pizzashack dot org ).
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <syslog.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

/* LOCAL INCLUDES */
#include "pathnames.h"
#include "log.h"

/* GLOBAL VARIABLES */
extern int errno;

/* FILE SCOPE VARIABLES */
static char *progname;
static char *username;
static int  log_init = 0;

/* FILE SCOPE FUNCTIONS */


char *get_username( void )
{
	struct passwd	*temp;

	if ( !(temp = getpwuid(getuid()) ) ) return NULL;
	return temp->pw_name;
}


void ch_start_logging( void )
{
	/* set up logging */
	if ( log_init ) return;
	username = get_username();
	log_set_facility(LOG_USER);
	log_set_priority(LOG_INFO);
	log_open();
	log_msg("new session for %s, UID=%d", 
		username ? username : "unknown user",
		getuid());
	/* all log messages from this point on are errors */
	log_set_priority(LOG_ERR);
	log_init = 1;
}

void ch_fatal_syscall( char *func, char *arg, char *strerr )
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
	long int	cmd;
	char		*conv;

	/* figure out our name, and give it to the log module */
	progname = strdup(log_make_ident(basename(argv[0])));

	/* make sure we have enough arguments, or exit with error */
	if ( argc < 5 ) 
		/* cheating, since this isn't a system call problem... */
		ch_fatal_syscall("rssh_chroot_helper", "invalid argument(s)",
				 "not enough arguments");

	/* 
	 * argv[1] is the directory to chroot to.  Check to make sure it
	 * exists.  If it does, chroot and drop privileges, and cd to it.
	 */

	if ( stat(argv[1], &s) == -1 )
		ch_fatal_syscall("stat()", argv[1], strerror(errno));
	if ( chroot(argv[1]) == -1 )
		ch_fatal_syscall("chroot()", argv[1], strerror(errno));

	setuid(getuid());
	ch_start_logging();

	/* make sure we can change directory to the user's dir */
	if ( chdir(argv[3]) == -1 ){
		log_msg("could not cd to user's home dir: %s", argv[3]);
		if ( chdir("/") )
			ch_fatal_syscall("chdir()", "/", strerror(errno));
	}

	/* argv[2] is "1" if scp, "2" if sftp */
	cmd = strtol(argv[2], &conv, 10);
	if ( *conv ){
		log_msg("command identifier contained invalid chars");
		exit(2);
	}
	
	/* ok... what were we supposed to run? */
	switch (cmd){
	case 1:
		argv[3] = PATH_SCP;
		break;
	case 2:
		argv[3] = PATH_SFTP_SERVER;
		break;
	default:
		log_msg("invalid command specified");
		exit(2);
	}

	/* now run it */
	execv(argv[3], &argv[4]);

	/* we only get here if the exec fails */
	ch_fatal_syscall("execv()", argv[3], strerror(errno));
	/* and we never get here, but it shuts gcc up */
	exit(1);
}


/*
 * util.c - utility functions for rssh
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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif /* CTYPE_H */
#ifdef HAVE_WORDEXP_H
#include <wordexp.h>
#endif /* HAVE_WORDEXP_H */
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif /* HAVE_SYSLOG_H */
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif /* HAVE_PWD_H */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

/* LOCAL INCLUDES */
#include "pathnames.h"
#include "rssh.h"
#include "log.h"
#include "rsshconf.h"

extern char *username;
extern char *progname;

/* 
 * build_arg_vector() - return a pointer to a vector of strings which
 *                      represent the arguments of the command to execv().
 */                 
char **build_arg_vector( char *str, size_t reserve )
{

	wordexp_t   	result;
	int		retc;

	result.we_offs = reserve;
	if ( (retc = wordexp(str, &result, WRDE_NOCMD|WRDE_DOOFFS)) ){
		log_set_priority(LOG_ERR);
		switch( retc ){
		case WRDE_BADCHAR:
		case WRDE_CMDSUB:
			fprintf(stderr, "%s: bad characters in arguments\n", 
				progname);
			log_msg("user %s used bad chars in command",
				username);
			break;
		default:
			fprintf(stderr, "%s: error expanding arguments\n", 
				progname);
			log_msg("error expanding arguments for user %s",
				username);
		}
		exit(1);
	}
	return result.we_wordv;
}


void fail( int flags, int argc, char **argv )
{
	char *cmd;	/* string for allowed commands */

	log_set_priority(LOG_ERR);
	/* determine which commands are usable for error message */
	if ( (flags & (RSSH_ALLOW_SCP | RSSH_ALLOW_SFTP)) == 
			(RSSH_ALLOW_SCP | RSSH_ALLOW_SFTP) )
		cmd = " to scp or sftp";
	else if ( flags & RSSH_ALLOW_SCP )
		cmd = " to scp only";
	else if ( flags & RSSH_ALLOW_SFTP )
		cmd = " to sftp only";
	else cmd = "";

	/* print error message to user and log attempt */
	fprintf(stderr, "\nThis account is restricted%s.\n\nIf you "
		"believe this is in error, please contact your system "
		"administrator.\n\n", cmd);
	if ( argc < 3 )
		log_msg("user %s attempted to log in with a shell",
			username);
	else{
		log_msg("user %s attempted to execute forbidden commands",
			username);
		log_msg("command: %s", argv[2]);
	}

	exit(0);
}


/*
 * check_command_line() - take the command line passed to rssh, and verify
 * 			  that the speicified command is one the user is
 * 			  allowed to run.  Return the name of the command
 * 			  which will be run if it is ok, or return NULL if it
 * 			  is not.
 */
char *check_command_line( char *cl, ShellOptions_t *opts )
{
	int	cl_len;		/* length of command line */
	int	len;		/* length of allowed command */

	cl_len = strlen(cl);
	len = strlen(PATH_SFTP_SERVER);
	if ( cl_len < len ) len = cl_len;
	/* check to see if cl starts with an allowed command */
	if ( !(strncmp(cl, PATH_SFTP_SERVER, len)) && 
			(isspace(cl[len]) || cl[len] == '\0') &&
			opts->shell_flags & RSSH_ALLOW_SFTP )
		return PATH_SFTP_SERVER;
	/* strlen of "scp" is always 3 */
	len = 3;
	/* if cl_len is less than 3, then it's not a valid command */
	if ( cl_len < 3 ) return NULL;
	if ( !(strncmp(cl, "scp", len)) && 
			(isspace(cl[len])) &&
			opts->shell_flags & RSSH_ALLOW_SCP ){
		return PATH_SCP;
	}
	return NULL;
}


/*
 * extract_root() - takes a root directory and the full path to some other
 *                  directory, and returns a pointer to a string which
 *                  contains the path of the second directory relative to the
 *                  first.  In the event the second dir is not located
 *                  somewhere in the first, NULL is returned.
 */
char *extract_root( char *root, char *path )
{
	char	*temp;
	int	len;

	len = strlen(root);
	/* get rid of a trailing / from the root path */
	if ( root[len - 1] == '/' ){
	       	root[len - 1] = '\0';
		len--;
	}
	if ( (strncmp(root, path, len)) ) return NULL;
	
	/*
	 * path[len] is the first character of path which is not part of root.
	 * If it is not '/' then we chopped path off in the middle of a path
	 * element, and the result is not reliable.  Assume an error.
	 */
	if ( path[len] != '/' ) return NULL;
	if ( !(temp = strdup(path + len)) ){
		log_set_priority(LOG_ERR);
		log_msg("can't allocate memory in function extract_root()");
		exit(1);
	}
	return temp;
}

/*
 * validate_mask() - takes a string which should be a umask, converts it, and
 *                   validates that it is a valid umask.  Returns true if it's
 *                   good, false if it isn't.  The integer umask is returned
 *                   in the integer pointer mask.
 */
int validate_umask( const char *temp, int *mask )
{
	char	*err = NULL;	/* for strtol() */

	/* convert the umask to a number */
	*mask = strtol(temp, &err, 8);
	if ( *err ) return FALSE;
	/* make sure it's a good umask */
	if ( (*mask < 0) || (*mask > 0777) ) return FALSE;
	return TRUE;
}


/*
 * validate_access() - takes a string which should be the access bits for
 *                     allow_sftp and allow_scp (in that order), and validates
 *                     them.  Returns the bits in the bool pointers of the
 *                     same name, and returns FALSE if the bits are not valid
 */
int validate_access( const char *temp, bool *allow_sftp, 
		     bool *allow_scp )
{
	char	scp[2];
	char	sftp[2];
	char	*err = NULL;	/* for strtol() */

	if ( strlen(temp) != 2 ) return FALSE;
	scp[0] = temp[1];
	scp[1] = '\0';
	sftp[0] = temp[0];
	sftp[1] = '\0';
	*allow_sftp = (char)strtol(sftp, &err, 2);
	if ( *err ) return FALSE;
	err = NULL;
	*allow_scp = (char)strtol(scp, &err, 2);
	if ( *err ) return FALSE;
	return TRUE;
}

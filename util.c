/*
 * util.c - utility functions for rssh
 * 
 * Copyright 2003-2006 Derek D. Martin ( code at pizzashack dot org ).
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
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif /* HAVE_SYSLOG_H */
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif /* HAVE_PWD_H */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif /* HAVE_LIBGEN_H */

/* LOCAL INCLUDES */
#include "pathnames.h"
#include "rssh.h"
#include "log.h"
#include "rsshconf.h"

extern char *username;
extern char *progname;


void fail( int flags, int argc, char **argv )
{
	char *cmd;	/* string for allowed commands */
	int  size = 0;

	log_set_priority(LOG_ERR);

	/* determine which commands are usable for error message */
	if ( flags & RSSH_ALLOW_SCP ) size += 4;   /* "scp" plus a space */
	if ( flags & RSSH_ALLOW_SFTP ) size += 5;
	if ( flags & RSSH_ALLOW_CVS ) size += 4;
	if ( flags & RSSH_ALLOW_RDIST ) size += 6;
	if ( flags & RSSH_ALLOW_RSYNC ) size += 5; /* last one, no space */

	/* create msg indicating what is allowed */
	if ( !size ) cmd = "This user is locked out.";
	else {
		size += 18;
		if ( !(cmd = (char *)malloc(size)) ){
			log_msg("fatal error: out of mem allocating log msg");
			exit(1);
		}
		cmd[0] = '\0';
		strncat(cmd, "Allowed commands: ", size);
		if ( flags & RSSH_ALLOW_SCP )
			strncat(cmd, "scp ", size);
		if ( flags & RSSH_ALLOW_SFTP )
			strncat(cmd, "sftp ", size);
		if ( flags & RSSH_ALLOW_CVS )
			strncat(cmd, "cvs ", size);
		if ( flags & RSSH_ALLOW_RDIST )
			strncat(cmd, "rdist ", size);
		if ( flags & RSSH_ALLOW_RSYNC )
			strncat(cmd, "rsync", size);
	}

	/* print error message to user and log attempt */
	fprintf(stderr, "\nThis account is restricted by rssh.\n"
		"%s\n\nIf you believe this is in error, please contact "
		"your system administrator.\n\n", cmd);
	if ( argc < 3 )
		log_msg("user %s attempted to log in with a shell",
			username);
	else{
		log_msg("user %s attempted to execute forbidden commands",
			username);
		log_msg("command: %s", argv[2]);
	}

	exit(1);
}


/*
 * opt_exist() - takes a string representing a command line, and a single
 *               character representing a command-line option flag (e.g. "-S")
 *               to search for.  If the option exists in the command line,
 *               return TRUE.  This function is a little over-zealous about
 *               returning a match, but in this case that is better than not
 *               being zealous enough.  And frankly, I don't want to spend the
 *               time required to get it 100% right.  It's not worth the
 *               effort.
 */
bool opt_exist(char *cl, char opt)
{
	int	i = 1;
	int	len;

	len = strlen(cl);

	/* process command line character by character */
	if (!(cl[0] == '-')) return FALSE;
	while ( i < (len) ){
		if ( cl[i] == opt ) return TRUE;
		i++;
	}
	return FALSE;
}


bool opt_filter(char **vec, const char opt)
{
	while (vec && *vec){
		if (opt_exist(*vec, opt)){
			fprintf(stderr, "\nillegal insecure %c option", opt);
			log_msg("insecure %c option in scp command line!", opt);
			return TRUE;
		}
		vec++;
	}
	return FALSE;
}


bool check_command( char *cl, ShellOptions_t *opts, char *cmd, int cmdflag )
{
	char	*prog;		/* basename of cmd */
	char 	*tmp = cl;
	bool	need_free = FALSE;
	bool	rc = FALSE;
	int 	i;
	size_t	len;


	if ( opts->shell_flags & cmdflag ){
		/* cl may be a full command line; if so get first word */
		len = strlen(cl);
		for (i=0; i < len && !isspace(*(cl + i)); i++);
		if (i < len){
			if (!(tmp = (char *)malloc(sizeof (char) * (i+1)))){
				log_msg("malloc() failed in check_command()");
				return FALSE;
			}
			need_free = TRUE;
			memcpy(tmp, cl, i);
			tmp[i] = '\0';
		}

		/* compare tmp to cmd and prog for match */
		prog = basename(cmd);
		if ( !(strcmp(tmp, cmd)) || !(strcmp(tmp, prog))){
			log_msg("cmd '%s' approved", prog);
			rc = TRUE;
		}	
	}
	if (need_free) free(tmp);
	return rc;
}


/*
 * check_command_line() - take the command line passed to rssh, and verify
 *			  that the specified command is one the user is
 *			  allowed to run and validate the arguments.  Return the
 *			  path of the command which will be run if it is ok, or
 *			  return NULL if it is not.
 */
char *check_command_line( char **cl, ShellOptions_t *opts )
{

	/* Here we call check_command not to validate, but to match */
	if ( check_command(*cl, opts, PATH_SFTP_SERVER, RSSH_ALLOW_SFTP) )
		return PATH_SFTP_SERVER;

	if ( check_command(*cl, opts, PATH_SCP, RSSH_ALLOW_SCP) ){
		/* filter -S option */
		if ( opt_filter(cl, 'S') ) return NULL;
		return PATH_SCP;
	}

	if ( check_command(*cl, opts, PATH_CVS, RSSH_ALLOW_CVS) ){
		if ( opt_filter(cl, 'e') ) return NULL;
		return PATH_CVS;
	}

	if ( check_command(*cl, opts, PATH_RDIST, RSSH_ALLOW_RDIST) ){
		/* filter -P option */
		if ( opt_filter(cl, 'P') ) return NULL;
		return PATH_RDIST;
	}

	if ( check_command(*cl, opts, PATH_RSYNC, RSSH_ALLOW_RSYNC) ){
		/* filter -e option */
		if ( opt_filter(cl, 'e') ) return NULL;
		while (cl && *cl){
			if ( strstr(*cl, "--rsh" ) ){
				fprintf(stderr, "\ninsecure --rsh= not allowed.");
				log_msg("insecure --rsh option in rsync command line!");
				return NULL;
			}
			cl++;
		}
		return PATH_RSYNC;
	}
	/* No match, return NULL */
	return NULL;
}


/*
 * get_command() - take the command line passed to rssh, and verify
 *		   that the specified command is one the user is allowed to run.
 *		   Return the path of the command which will be run if it is ok,
 *		   or return NULL if it is not.
 */
char *get_command( char *cl, ShellOptions_t *opts )
{

	if ( check_command(cl, opts, PATH_SFTP_SERVER, RSSH_ALLOW_SFTP) )
		return PATH_SFTP_SERVER;
	if ( check_command(cl, opts, PATH_SCP, RSSH_ALLOW_SCP) )
		return PATH_SCP;
	if ( check_command(cl, opts, PATH_CVS, RSSH_ALLOW_CVS) )
		return PATH_CVS;
	if ( check_command(cl, opts, PATH_RDIST, RSSH_ALLOW_RDIST) )
		return PATH_RDIST;
	if ( check_command(cl, opts, PATH_RSYNC, RSSH_ALLOW_RSYNC) )
		return PATH_RSYNC;
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
int validate_access( const char *temp, bool *allow_sftp, bool *allow_scp,
		     bool *allow_cvs, bool *allow_rdist, bool *allow_rsync )
{
	int	i;

#define NUM_ACCESS_BITS 5

	if ( strlen(temp) != NUM_ACCESS_BITS ) return FALSE;
	/* make sure the bits are valid */
	for ( i = 0; i < NUM_ACCESS_BITS; i++ )
		if ( temp[i] < '0' || temp[i] > '1' ) return FALSE;
	/* This is easier to read if we allign the = */
	*allow_rsync = temp[0] - '0';
	*allow_rdist = temp[1] - '0';
	*allow_cvs   = temp[2] - '0';
	*allow_sftp  = temp[3] - '0';
	*allow_scp   = temp[4] - '0';
	return TRUE;
}

/*
 * get_username() - get the username of the user, or return unknown
 *
 */
char *get_username( void )
{
	struct passwd	*temp;

	if ( !(temp = getpwuid(getuid()) ) ) return "unknown user!";
	return temp->pw_name;
}



/*
 * argvec.c - build_arg_vec() for rssh
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
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_WORDEXP_H
#include <wordexp.h>
#endif /* HAVE_WORDEXP_H */
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif /* HAVE_SYSLOG_H */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif /* HAVE_LIBGEN_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif /* HAVE_ERRNO_H */

/* LOCAL INCLUDES */
#include "pathnames.h"
#include "rssh.h"
#include "log.h"
#include "rsshconf.h"

extern char *progname;
extern char *username;

/* 
 * build_arg_vector() - return a pointer to a vector of strings which
 *                      represent the arguments of the command to execv().
 */                 
char **build_arg_vector( char *str, size_t reserve )
{

	wordexp_t   	result;
	int		retc;
#ifdef WRDE_ERRNO
	int		errornum;
	char		*message;
#endif /* WRDE_ERRNO */

	result.we_offs = reserve;
	if ( (retc = wordexp(str, &result, WRDE_NOCMD|WRDE_DOOFFS)) ){
		log_set_priority(LOG_ERR);
		switch( retc ){
		case WRDE_BADCHAR:
		case WRDE_CMDSUB:
			fprintf(stderr, "%s: bad characters in arguments\n", 
				progname);
			log_msg("user %s usedbad chars in command", username);
			break;
#ifdef WRDE_ERRNO
		case WRDE_ERRNO:
			errornum = errno;
			fprintf(stderr, "%s: error expanding arguments\n", 
				progname);
			log_msg("error expanding arguments for user %s",
				username);
			log_msg("wordexp() set errno to %d", errornum);
			message = strdup(strerror(errno));
			log_msg(message);
			break;
#endif /* WRDE_ERRNO */
		case WRDE_NOSPACE:
			fprintf(stderr, "%s: wordexp() allocation failed\n", 
				progname);
			log_msg("wordexp() allocation failed");
			break;
		case WRDE_BADVAL:
			fprintf(stderr, "%s: wordexp() bad value\n", 
				progname);
			log_msg("wordexp() bad value");
			break;
		case WRDE_SYNTAX:
			fprintf(stderr, "%s: wordexp() bad syntax\n", 
				progname);
			log_msg("wordexp() bad syntax");
			break;
#ifdef WRDE_NOSYS
		case WRDE_NOSYS:
			fprintf(stderr, "%s: wordexp() not supported\n", 
				progname);
			log_msg("wordexp() not supported (shouldn't happen)");
			break;
#endif /* WRDE_NOSYS */
		default:
			fprintf(stderr, "%s: error expanding arguments\n", 
				progname);
			log_msg("error expanding arguments for user %s",
				username);
			log_msg("retc = %d (this shouldn't happen)", retc);
		}
		exit(1);
	}
	return result.we_wordv;
}


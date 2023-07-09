/*
 * log.c - log module for logging to syslog
 * 
 * Copyright 2003-2005 Derek D. Martin ( code at pizzashack dot org ).
 *
 * This program is licensed under a BSD-style license, as follows: 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif /* HAVE_LIBGEN_H */
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif /* HAVE_SYSLOG_H */
#ifdef HAVE_STDARG_H
#include <stdarg.h> 
#endif /* HAVE_STDARG_H */


/* LOCAL INCLUDES */

#include "log.h" 


/* FILE SCOPE VARIABLES */
static char *ident = NULL;    /* prefix for log messages (usually progname) */
static int  facility = LOG_USER;
static int  level = LOG_WARNING;


/* 
 * log_set_ident()  - set the ident field for openlog()
 * args: name - character string to set ident to
 */
char *log_set_ident( const char *name )
{
	/* lose the existing value of ident, if there is one */
	if ( ident ){
		free(ident);
		ident = NULL;
	}
	if ( name ) ident = strdup(name);
	return ident;
}


/* 
 * log_make_ident()  - make the ident field for openlog() from a path
 * args: name - character string to set ident to
 * (use to set from argv[0])
 */
char *log_make_ident( const char *name )
{
	char *temp;

	/* lose the existing value of ident, if there is one */
	if ( ident ){
		free(ident);
		ident = NULL;
	}
	/* assign new value to ident from name */
	if ( !name ) return (ident = NULL);
	ident = strdup(basename((char*)name));
	/* remove leading '-' from ident, if there is one */
	if ( ident[0] == '-' ){
		temp = strdup(ident + 1);
		free(ident);
		ident = temp;
	}
	return ident;
}


void log_set_priority( int new_level )
{
	level = new_level;
}


void log_set_facility( int new_fac )
{
	facility = new_fac;
}


void log_open( void )
{
	openlog( ident, LOG_CONS | LOG_PID, facility );
}


void log_close( void )
{
	closelog();
}


/* 
 * lm_create_log_buffer() - this function takes advantage of the return
 *   value of vsnprintf() and the realloc() function to allocate a buffer 
 *   which is either exactly the right size for the message (in the case 
 *   of GLIBC >= 2.1) or at least large enough to hold the entire message.
 */
void log_msg( char *msg, ... )
{

	char    *format_temp = NULL;
	va_list arglist;
	int     length;        /* length of msg */
	int     retc;          /* return code */

	/* 
	 * make a guess how big the message will be -- initially we'll allow
	 * 50 characters for formatting variable args
	 */
	length = 50 + strlen( msg );
	if ( (format_temp = (char *)malloc( length )) == NULL){
		syslog(LOG_ERR, "Could not allocate mem in log_msg(), log.c");
		exit(1);
	}
	memset( format_temp, 0, length );

	/* try to print msg to buffer, until we succeed or fail conclusively */
	va_start( arglist, msg );
	retc = vsnprintf( format_temp, length, msg, arglist );
	va_end( arglist );

	/* 
	 * Check retc to make sure it fit account for differences in libc
	 * versions (grumble)...  Per C99, retc is # of chars that WOULD have
	 * been copied if format_temp was large enough, so make the buffer
	 * that size.
	 */
	if ( retc > length ){

		if ( (format_temp = (char *)realloc( format_temp, retc + 1 )) 
				== NULL ){
			syslog(LOG_ERR, 
				"Could not allocate mem in log_msg(), log.c");
			exit(1);
		}
		va_start( arglist, msg );
		vsnprintf( format_temp, retc + 1, msg, arglist );
		va_end( arglist );
	}
	/* if retc == -1, we must be compiled under pre-C99 libc */
	while ( retc == -1 ){
		length += 50;
		if ( (format_temp = (char *)realloc( format_temp, length )) 
		        == NULL ){
			syslog(LOG_ERR,
				"Could not allocate mem in log_msg(), log.c");
			exit(1);
		}	
		memset( format_temp, 0, length );
		va_start( arglist, msg );
		retc = vsnprintf( format_temp, length, msg, arglist );
		va_end( arglist );
	}
	syslog((facility | level), "%s", format_temp);
	free(format_temp);
}


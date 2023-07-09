/*
 * util.h - headers for utility functions for rssh
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

#ifndef _util_h
#define _util_h

#include "rsshconf.h"

void fail( int flags, int argc, char **argv );
char *check_command_line( char **cl, ShellOptions_t *opts );
char *get_command( char *cl, ShellOptions_t *opts);
char *extract_root( char *root, char *path );
int  validate_umask( const char *temp, int *mask );
int validate_access( const char *temp, bool *allow_sftp, bool *allow_scp,
	       	     bool *allow_cvs, bool *allow_rdist, bool *allow_rsync );
bool opt_exist( char *cl, char opt );
char *get_username( void );

#endif /* _util_h */

/*
 * rsshconf.h - headers and typedefs for rssh config module
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

#ifndef _rssh_config_h
#define _rssh_config_h

/* SYSTEM INCLUDES */
#include <sys/types.h>

/* MACRO DEFINITIONS */

#define CFG_LINE_LEN	1024	/* max lenght of a config file line */
#define CFG_KW_LEN	60	/* length of a keyword */


/* STRUCTURES AND TYPEDEFS */

typedef struct {
	unsigned int	shell_flags;
	mode_t		rssh_umask;
	char		*chroot_path;
} ShellOptions_t;


/* EXTERNALLY VISIBLE FUNCTION DECLARATIONS */
int 	read_shell_config( ShellOptions_t *opts, const char *filename, int log );


#endif /* _rssh_config_h */


/*
 * rssh.h - some global macro definitions for rssh (and helpers)
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

#ifndef TRUE
#define TRUE	1
#endif  /* TRUE */

#ifndef FALSE
#define FALSE	0
#endif /* FALSE */

#ifndef _rssh_h
#define _rssh_h

typedef char bool;

#define RSSH_ALLOW_SCP	 (1 << 0)
#define RSSH_ALLOW_SFTP  (1 << 1)
#define RSSH_ALLOW_CVS   (1 << 2)
#define RSSH_ALLOW_RDIST (1 << 3)
#define RSSH_ALLOW_RSYNC (1 << 4)
#define RSSH_USE_CHROOT	 (1 << 5)

#endif /* _rssh_h */

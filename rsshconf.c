/*
 * rsshconf.c - parse rssh config file
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
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif /* HAVE_SYSLOG_H */
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif /* HAVE_CTYPE_H */

#include <signal.h>

/* LOCAL INCLUDES */
#include "rssh.h"
#include "log.h"
#include "rsshconf.h"
#include "util.h"

/*  MACRO DEFINITIONS */
#define eat_assignment(x)	eat_char_token('=', x, FALSE, TRUE)
#define eat_comment(x)		eat_char_token('#', x, FALSE, TRUE)
/* this amuses me */
#define eat_colon(x)		eat_char_token(':', x, TRUE, FALSE)

/* GLOBALS (defined in main.c) */
extern char *username;

/* FILE SCOPE VARIABLES */
const char *keywords[] = {
	"#",		/* start a comment */
	"allowscp",
	"allowsftp",
	"allowcvs",
	"allowrdist",
	"allowrsync",
	"chrootpath",
	"logfacility",
	"umask",
	"user",
	NULL
};

int log=0;

/* flag to tell config parser to stop processing config file */
static bool got_user_config = FALSE;

/* FUNCTION DECLARATIONS FOR FILE SCOPE FUNCTIONS */

int get_keyword( const char *line, char *keyword, int *end );
int eat_char_token( const char tokchar, const char *line, bool colon,
	            bool ign_spc );
int process_umask( ShellOptions_t *opts, const char *line, const int lineno );
int process_user( ShellOptions_t *opts, const char *line, const int lineno );

int process_allow_scp( ShellOptions_t *opts, const char *line, 
		       const int lineno );

int process_allow_sftp( ShellOptions_t *opts, const char *line, 
		        const int lineno );

int process_allow_cvs( ShellOptions_t *opts, const char *line, 
		        const int lineno );

int process_allow_rdist( ShellOptions_t *opts, const char *line, 
		        const int lineno );

int process_allow_rsync( ShellOptions_t *opts, const char *line, 
		        const int lineno );

int get_token( const char *str, char *buf, const int buflen, 
	       const bool colon, const bool ign_spc );

int process_config_line( ShellOptions_t *opts, FILE *cfg_file, 
		         const char *line, const int lineno );

int process_chroot_path( ShellOptions_t *opts, const char *line,
		         const int lineno );

int process_log_facility( ShellOptions_t *opts, const char *line,
			  const int lineno );

int get_asgn_param( const char *line, const int lineno, char *buf,	
			  const int buflen );


/* EXTERNALLY VISIBLE FUNCTIONS */

/* returns FALSE if there was an error, TRUE if not */
int read_shell_config( ShellOptions_t *opts, const char *filename, int do_log )
{
        FILE 	*cfg_file;		/* config file ptr */
        int 	linenum;		/* cfg file line counter */
	int 	status = TRUE;		/* were all the cfg lines good? */
        char 	line[CFG_LINE_LEN + 1];	/* buffer to hold region */

	log = do_log;
	memset(line, 0, CFG_LINE_LEN + 1);
        cfg_file = fopen(filename, "r");
        if (!cfg_file) {
		if (log){
			log_set_priority(LOG_WARNING);
			log_msg("config file (%s) missing, using defaults", 
				filename);
		}
                opts->shell_flags = RSSH_ALLOW_SCP;
		return FALSE;
        }
        linenum = 0;
        while ( !got_user_config && fgets(line, CFG_LINE_LEN, cfg_file) ) {
                linenum++;
                if ( !(process_config_line(opts, cfg_file, line, linenum)) )
			status = FALSE;
		memset(line, 0, CFG_LINE_LEN + 1);
	}
        fclose(cfg_file);
	return status;
}


/* FILE SCOPE FUNCTIONS */

/* returns FALSE if there was an error, TRUE if not */
int process_config_line( ShellOptions_t	*opts,
	       		 FILE		*cfg_file,
			 const char 	*line,
			 const int	lineno )
{
	char	*newline;		/* location of newline char in line */
	char	tmp[CFG_LINE_LEN + 1];	/* buffer to scan past a \n */
	char	keywrd[CFG_KW_LEN + 1];	/* tmp storage for config keyword */
	int	pos = 0;		/* position in string */

	/* line should contain a \n - if not, line is too long. */
	if ( (newline = strchr(line, '\n')) )
		*newline = '\0';
	else {
		/* there is no newline - log the error and find the EOL */
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("line %d: line too long", lineno);
		}
		while ( fgets(tmp, CFG_LINE_LEN, cfg_file) ){
			if ( (newline = strchr(line, '\n')) )
				break;
		}
		return FALSE;
	}

	/* check for options and set appropriate global */

	switch ( get_keyword(line, keywrd, &pos) ){
	case -1:
		/* a blank line */
		return TRUE;
	case 0:
		/* start a comment - just ignore the line */
		return TRUE;
	case 1:
		/* allow scp */
		if ( !(process_allow_scp(opts, line + pos, lineno) ) )
			return FALSE;
		return TRUE;
	case 2:
		/* allow sftp */
		if ( !(process_allow_sftp(opts, line + pos, lineno) ) )
			return FALSE;
		return TRUE;
	case 3:
		/* allow cvs */
		if ( !(process_allow_cvs(opts, line + pos, lineno) ) )
			return FALSE;
		return TRUE;
	case 4:
		/* allow rdist */
		if ( !(process_allow_rdist(opts, line + pos, lineno) ) )
			return FALSE;
		return TRUE;
	case 5:
		/* allow rsync */
		if ( !(process_allow_rsync(opts, line + pos, lineno) ) )
			return FALSE;
		return TRUE;
	case 6:
		/* default chroot path */
		if ( !(process_chroot_path(opts, line + pos, lineno) ) )
			return FALSE;
		return TRUE;
	case 7:
		/* syslog log facility */
		if ( !(process_log_facility(opts, line + pos, lineno) ) )
			return FALSE;
		return TRUE;
	case 8:
		/* set the user's umask */
		if ( !(process_umask(opts, line + pos, lineno) ) )
			return FALSE;
		return TRUE;
	case 9:
		/* user */
		if ( !(process_user(opts, line + pos, lineno) ) )
			return FALSE;
		return TRUE;
	default:
		/* the keyword is unknown */
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("line %d: syntax error parsing config file",
				       	lineno);
		}
		if ( keywrd[0] && log )
			log_msg("unknown keyword: %s", keywrd);
		return FALSE;
	}
	/* this is never reached, but keeps the compiler quiet */
	return TRUE;
}


/*
 * get_keyword() - Identify a configuration keyword at the beginning of a
 *                 line, and return the index into the keyword array which
 *                 matches the keyword.  Return -1 if no match.  This function
 *                 assumes that keyword points to a buffer of size CFG_KW_LEN
 *                 + 1.  It is not intended to be called by functions outside
 *                 this module, and if called with buffers smaller than
 *                 CFG_KW_LEN + 1, a buffer overflow could result.  The index
 *                 of the character after the last character in the token is
 *                 stored in the variable pointed to by end if a keyword is
 *                 found, or 0 otherwise.
 */
int get_keyword( const char *line, char *keyword, int *end )
{
	int	i = 0;

	/* clear the buffer, so previous calls can't affect it */
	memset(keyword, 0, CFG_KW_LEN + 1);

	/* get a token, and match it against available keywords */
	if ( !( *end = get_token(line, keyword, CFG_KW_LEN + 1, FALSE, FALSE)) )
		return -1;
	while ( keywords[i] != NULL ){
		if ( !(strncmp(keywords[i], keyword, CFG_KW_LEN)) ) return i;
		i++;
	}
	return -1;
}


/* 
 * get_token() - Gets a token from the specified string.  If the token starts
 *               with a quote, include subsequent spaces in the token, up to
 *               the next matching quote.  Otherwise, take up to the next
 *               non-graph character.  Return the index of the first character
 *               after the end of the token, zero if there was no token, and
 *               -1 if there was an unmatched quote.
 *
 *               Valid tokens are '=', space-separated words, or any string
 *               enclosed in quotes.  '=' and whitespace must be treated as
 *               token separators.  We operate on a copy of str, so we can
 *               safely strip out the quotes.
 *
 *               A colon is also treated as a token separator if the bool
 *               parameter colon is set to TRUE.
 *
 *               If the bool parameter ign_spc is true, DO NOT consider space
 *               a token separator, i.e. leave spaces as-is in the string.  We
 *               need this for processing the user config.  It may originally
 *               have been enclosed in quotes to preserve spaces, but after we
 *               call get_asgn_param() on it, the quotes will have been
 *               stripped, leaving only spaces which were part of the
 *               assignment (most likely the chroot path).  We need to treat
 *               those spaces as part of the data, so that we will not
 *               mistakenly split a path on a space which is supposed to be in
 *               the path...
 *
 *               MODIFY THIS FUNCTION ONLY WITH GREAT CARE!  IT IS A BUFFER
 *               OVERFLOW WAITING TO HAPPEN...
 */
int get_token( const char *str, char *buf, const int buflen, 
	       const bool colon, const bool ign_spc )
{
	int	line_len;	/* length of str (what's left of a line) */
	int	len;		/* length of token (or a portion of it)  */
	char	*copy;		/* copy of str, so we can modify it */
	char	*start;		/* beginning of token */
	char	*end;		/* end of token */
	char	*quote[2];	/* location of start and end quotes */
	int	adjust = 0;	/* to add to pos for each quote */
	int	i;

	/* initialize strings and pointers */
	memset(buf, 0, buflen);
	if ( !(copy = strdup(str)) ){
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("OOM error in get_token() (fatal)");
		}
		exit(1);
	}
	start = copy;
	line_len = strlen(copy);

	/* first, skip past initial whitespace */

	while ( isspace(*start) ) start++;
	end = start;
	/* if there's no token to get... */
	if ( *start == '\0' ) return 0;

	/* process character by character to determine end of token */
	while ( end <= (copy + line_len) ){

		/* is it space? */
		if ( !ign_spc && isspace(*end) ){
			end--;
		       	break;
		}

		/* is it an equal sign, or '#'? */
		if ( *end == '=' || *end == '#' || (colon && *end == ':') ){
			/* *end is the token */
			if ( end == start ) break;
			/* else, *end is the next token */
			end--;
			break;
		}

		/* 
		 * Is it a quote? 
		 *
		 * If so, everything between the quotes is part of the token,
		 * so character-by-character processing must be stopped until
		 * after the quote.  However, the quotes are special: they are
		 * not part of the token.  They must be stripped out of the
		 * copy, and the characters after each quote must be moved
		 * down.  Then, the length of the copy (line_len) must be
		 * diminished by the number of stripped quotes (which should
		 * always be 2).  Finally, because the original line will
		 * still have the quotes, we must add the number of quotes
		 * processed to the value of pos before we return it.
		 *
		 * Also, since quotes could theoretically appear anywhere in
		 * the line, we must not assume that the end quote is the end
		 * of the token; processing must continue after it.
		 *
		 */
		if ( *end == '"' || *end == '\'' ){
			quote[0] = end;
			quote[1] = strchr(end + 1, *end);

			/* no matching quote */
			if ( !quote[1] ) return -1;

			/* strip out the quotes */

			len = (int)(quote[1] - quote[0] - 1);
			/* move characters between quotes down one */
			for ( i = 0; i < len; i++ )
				*(quote[0] + i) = *(quote[0] + i + 1);
			/* move chars after quotes (incl. null) down two */
			len = (int)(copy - quote[1] + line_len);
			for ( i = 0; i < len; i++ )
			       *(quote[1] - 1 + i) = *(quote[1] + 1 + i);	
			/* since we lost a pair of quotes, fix line_len */
			line_len -= 2;
			/* update end to last char of quoted string */
			end = quote[1] - 2;
			/* account for removed quotes in the return value */
			adjust += 2;
		}

		/* if we got here, increment end */
		end++;
	}

	/* copy the remainder into buf, and return */
	len = (int)(1 + end - start);
	strncpy(buf, start, ((len > buflen - 1) ? (buflen - 1) : len));
	free(copy);
	return (1 + end + adjust - copy);
}


/* 
 * process_allow_scp() - make sure there are no tokens after the keyword,
 *                       other than a possible comment.  If there are
 *                       additional tokens other than comments, there is a
 *                       syntax error, and FALSE is returned.  Otherwise, the
 *                       line is ok, so opts are set to allow scp, and TRUE is
 *                       returned.
 */
int process_allow_scp( ShellOptions_t *opts, 
		       const char *line,
		       const int lineno )
{
	if ( !eat_comment(line) ){
		if (log) log_msg("line %d: syntax error parsing config file",
				       	lineno);
		return FALSE;
	}
	if (log){
		log_set_priority(LOG_INFO);
		log_msg("allowing scp to all users");
	}
	opts->shell_flags |= RSSH_ALLOW_SCP;
	return TRUE;
}

/* 
 * process_allow_sftp() - make sure there are no tokens after the keyword,
 *                        other than a possible comment.  If there are
 *                        additional tokens other than comments, there is a
 *                        syntax error, and FALSE is returned.  Otherwise, the
 *                        line is ok, so opts are set to allow sftp, and TRUE
 *                        is returned.
 */
int process_allow_sftp( ShellOptions_t *opts, 
		       const char *line,
		       const int lineno )
{
	int pos;

	if ( !(pos = eat_comment(line)) ){
		if (log) log_msg("line %d: syntax error parsing config file", 
				lineno);
		return FALSE;
	}
	if (log){
		log_set_priority(LOG_INFO);
		log_msg("allowing sftp to all users");
	}
	opts->shell_flags |= RSSH_ALLOW_SFTP;
	return TRUE;
}


/* 
 * process_allow_cvs() - make sure there are no tokens after the keyword,
 *                        other than a possible comment.  If there are
 *                        additional tokens other than comments, there is a
 *                        syntax error, and FALSE is returned.  Otherwise, the
 *                        line is ok, so opts are set to allow cvs, and TRUE
 *                        is returned.
 */
int process_allow_cvs( ShellOptions_t *opts, 
		       const char *line,
		       const int lineno )
{
	int pos;

	if ( !(pos = eat_comment(line)) ){
		if (log) log_msg("line %d: syntax error parsing config file", 
				lineno);
		return FALSE;
	}
	if (log){
		log_set_priority(LOG_INFO);
		log_msg("allowing cvs to all users");
	}
	opts->shell_flags |= RSSH_ALLOW_CVS;
	return TRUE;
}


/* 
 * process_allow_rdist() - make sure there are no tokens after the keyword,
 *                        other than a possible comment.  If there are
 *                        additional tokens other than comments, there is a
 *                        syntax error, and FALSE is returned.  Otherwise, the
 *                        line is ok, so opts are set to allow rdist, and TRUE
 *                        is returned.
 */
int process_allow_rdist( ShellOptions_t *opts, 
		       const char *line,
		       const int lineno )
{
	int pos;

	if ( !(pos = eat_comment(line)) ){
		if (log) log_msg("line %d: syntax error parsing config file", 
				lineno);
		return FALSE;
	}
	log_set_priority(LOG_INFO);
	if (log){
		log_msg("allowing rdist to all users");
		opts->shell_flags |= RSSH_ALLOW_RDIST;
	}
	return TRUE;
}


/* 
 * process_allow_rsync() - make sure there are no tokens after the keyword,
 *                        other than a possible comment.  If there are
 *                        additional tokens other than comments, there is a
 *                        syntax error, and FALSE is returned.  Otherwise, the
 *                        line is ok, so opts are set to allow rsync, and TRUE
 *                        is returned.
 */
int process_allow_rsync( ShellOptions_t *opts, 
		       const char *line,
		       const int lineno )
{
	int pos;

	if ( !(pos = eat_comment(line)) ){
		if (log) log_msg("line %d: syntax error parsing config file", 
				lineno);
		return FALSE;
	}
	if (log){
		log_set_priority(LOG_INFO);
		log_msg("allowing rsync to all users");
	}
	opts->shell_flags |= RSSH_ALLOW_RSYNC;
	return TRUE;
}


int process_chroot_path( ShellOptions_t *opts, 
		         const char *line,
		         const int lineno )
{
	char	*temp;		/* to hold the assigned path */

	/* 
	 * older versions of rssh free()'d opts->chroot_path here, but this is
	 * an error.  If the current config line had an error, that left the
	 * chroot_path in an invalid state.  We now wait until after the
	 * new chroot_path is successfully assigned by get_asgn_param() to do
	 * the free() call.  Waiting also allows us to preserve any previous
	 * chroot path if there is an error.
	 */

	if ( !(temp = (char *)malloc(CFG_LINE_LEN + 1)) ){
		if (log) log_msg("fatal error: can't allocate space for chroot path");
		exit(1);
	}
	/* get_asgn_param() eats trailing comments, so we won't */
	if ( !get_asgn_param(line, lineno, temp, CFG_LINE_LEN + 1) ){
		free(temp);
		return FALSE;
	}
	
	/* get rid of any old value for chroot path, assign new one */
	if ( opts->chroot_path ) free(opts->chroot_path);
	if (log){
		log_set_priority(LOG_INFO);
		log_msg("chrooting all users to %s", temp);
	}
	/* we must not free temp, since opts points to it */
	opts->chroot_path = temp;
	opts->shell_flags |= RSSH_USE_CHROOT;
	return TRUE;
}


int process_log_facility( ShellOptions_t *opts,
			  const char *line,
			  const int lineno )
{
	char	*temp;		/* hold log facility assignment */
	char	*facname = NULL;
	int	fac = 0;
	int	pos;

	if ( !(temp = (char *)malloc(CFG_LINE_LEN + 1)) ){
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("fatal error: can't allocate space for log facility");
		}
		exit(1);
	}
	/* this eats trailing comments */
	if ( !(pos = get_asgn_param(line, lineno, temp, CFG_LINE_LEN + 1)) ){
		free(temp);
		return FALSE;
	}
#ifdef LOG_KERN
	if ( !strncmp(temp, "LOG_KERN", CFG_LINE_LEN) ||
	     !strncmp(temp, "kern", CFG_LINE_LEN) ){
		facname = "LOG_KERN";
		fac = LOG_KERN;
	}
#endif /* LOG_KERN */

#ifdef LOG_USER
	if ( !strncmp(temp, "LOG_USER", CFG_LINE_LEN) ||
	     !strncmp(temp, "user", CFG_LINE_LEN) ){
		facname = "LOG_USER";
		fac = LOG_USER;
	}
#endif /* LOG_USER */

#ifdef LOG_MAIL
	if ( !strncmp(temp, "LOG_MAIL", CFG_LINE_LEN) ||
	     !strncmp(temp, "mail", CFG_LINE_LEN) ){
		facname = "LOG_MAIL";
		fac = LOG_MAIL;
	}
#endif /* LOG_MAIL */

#ifdef LOG_DAEMON
	if ( !strncmp(temp, "LOG_DAEMON", CFG_LINE_LEN) ||
	     !strncmp(temp, "daemon", CFG_LINE_LEN) ){
		facname = "LOG_DAEMON";
		fac = LOG_DAEMON;
	}
#endif /* LOG_DAEMON */

#ifdef LOG_AUTH
	if ( !strncmp(temp, "LOG_AUTH", CFG_LINE_LEN) ||
	     !strncmp(temp, "auth", CFG_LINE_LEN) ){
		facname = "LOG_AUTH";
		fac = LOG_AUTH;
	}
#endif /* LOG_AUTH */

#ifdef LOG_AUTHPRIV
	if ( !strncmp(temp, "LOG_AUTHPRIV", CFG_LINE_LEN) ||
	     !strncmp(temp, "authpriv", CFG_LINE_LEN) ){
		facname = "LOG_AUTHPRIV";
		fac = LOG_AUTHPRIV;
	}
#endif /* LOG_AUTHPRIV */

#ifdef LOG_SYSLOG
	if ( !strncmp(temp, "LOG_SYSLOG", CFG_LINE_LEN) ||
	     !strncmp(temp, "syslog", CFG_LINE_LEN) ){
		facname = "LOG_SYSLOG";
		fac = LOG_SYSLOG;
	}
#endif /* LOG_SYSLOG */

#ifdef LOG_LPR
	if ( !strncmp(temp, "LOG_LPR", CFG_LINE_LEN) ||
	     !strncmp(temp, "lpr", CFG_LINE_LEN) ){
		facname = "LOG_LPR";
		fac = LOG_LPR;
	}
#endif /* LOG_LPR */

#ifdef LOG_NEWS
	if ( !strncmp(temp, "LOG_NEWS", CFG_LINE_LEN) ||
	     !strncmp(temp, "news", CFG_LINE_LEN) ){
		facname = "LOG_NEWS";
		fac = LOG_NEWS;
	}
#endif /* LOG_NEWS */

#ifdef LOG_UUCP
	if ( !strncmp(temp, "LOG_UUCP", CFG_LINE_LEN) ||
	     !strncmp(temp, "uucp", CFG_LINE_LEN) ){
		facname = "LOG_UUCP";
		fac = LOG_UUCP;
	}
#endif /* LOG_UUCP */

#ifdef LOG_CRON
	if ( !strncmp(temp, "LOG_CRON", CFG_LINE_LEN) ||
	     !strncmp(temp, "cron", CFG_LINE_LEN) ){
		facname = "LOG_CRON";
		fac = LOG_CRON;
	}
#endif /* LOG_CRON */

#ifdef LOG_FTP
	if ( !strncmp(temp, "LOG_FTP", CFG_LINE_LEN) ||
	     !strncmp(temp, "ftp", CFG_LINE_LEN) ){
		facname = "LOG_FTP";
		fac = LOG_FTP;
	}
#endif /* LOG_FTP */

#ifdef LOG_LOCAL0
	if ( !strncmp(temp, "LOG_LOCAL0", CFG_LINE_LEN) ||
	     !strncmp(temp, "local0", CFG_LINE_LEN) ){
		facname = "LOG_LOCAL0";
		fac = LOG_LOCAL0;
	}
#endif /* LOG_LOCAL0 */

#ifdef LOG_LOCAL1
	if ( !strncmp(temp, "LOG_LOCAL1", CFG_LINE_LEN) ||
	     !strncmp(temp, "local1", CFG_LINE_LEN) ){
		facname = "LOG_LOCAL1";
		fac = LOG_LOCAL1;
	}
#endif /* LOG_LOCAL1 */

#ifdef LOG_LOCAL2
	if ( !strncmp(temp, "LOG_LOCAL2", CFG_LINE_LEN) ||
	     !strncmp(temp, "local2", CFG_LINE_LEN) ){
		facname = "LOG_LOCAL2";
		fac = LOG_LOCAL2;
	}
#endif /* LOG_LOCAL2 */

#ifdef LOG_LOCAL3
	if ( !strncmp(temp, "LOG_LOCAL3", CFG_LINE_LEN) ||
	     !strncmp(temp, "local3", CFG_LINE_LEN) ){
		facname = "LOG_LOCAL3";
		fac = LOG_LOCAL3;
	}
#endif /* LOG_LOCAL3 */

#ifdef LOG_LOCAL4
	if ( !strncmp(temp, "LOG_LOCAL4", CFG_LINE_LEN) ||
	     !strncmp(temp, "local4", CFG_LINE_LEN) ){
		facname = "LOG_LOCAL4";
		fac = LOG_LOCAL4;
	}
#endif /* LOG_LOCAL4 */

#ifdef LOG_LOCAL5
	if ( !strncmp(temp, "LOG_LOCAL5", CFG_LINE_LEN) ||
	     !strncmp(temp, "local5", CFG_LINE_LEN) ){
		facname = "LOG_LOCAL5";
		fac = LOG_LOCAL5;
	}
#endif /* LOG_LOCAL5 */

#ifdef LOG_LOCAL6
	if ( !strncmp(temp, "LOG_LOCAL6", CFG_LINE_LEN) ||
	     !strncmp(temp, "local6", CFG_LINE_LEN) ){
		facname = "LOG_LOCAL6";
		fac = LOG_LOCAL6;
	}
#endif /* LOG_LOCAL6 */

#ifdef LOG_LOCAL7
	if ( !strncmp(temp, "LOG_LOCAL7", CFG_LINE_LEN) ||
	     !strncmp(temp, "local7", CFG_LINE_LEN) ){
		facname = "LOG_LOCAL7";
		fac = LOG_LOCAL7;
	}
#endif /* LOG_LOCAL7 */

	free(temp);
	if ( !eat_comment(line + pos) ){
		if (log) log_msg("line %d: syntax error parsing config file", 
				lineno);
		return FALSE;
	}
	if ( facname ){
		log_set_priority(LOG_INFO);
		if (log) log_msg("setting log facility to %s", facname);
		log_set_facility(fac);
		return TRUE;
	}
	if (log){
		log_msg("line %d: unknown log facility specified", lineno);
		log_set_facility(LOG_USER);
	}
	return FALSE;
}


int process_umask( ShellOptions_t *opts, 
		   const char *line,
		   const int lineno )
{
	char	*temp;		/* to store assignment param */
	int	mask;		/* umask */

	if ( !(temp = (char *)malloc(CFG_LINE_LEN + 1)) ){
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("fatal error: can't allocate space in process_umask()");
		}
		exit(1);
	}
	/* this eats trailing comments */
	if ( !get_asgn_param(line, lineno, temp, CFG_LINE_LEN + 1) ){
		free(temp);
		return FALSE;
	}

	/* convert the umask to a number */
	if ( !validate_umask(temp, &mask) ){
		if (log){
			log_set_priority(LOG_WARNING);
			log_msg("line %d: invalid umask specified, using default 077",
			lineno);
		}
		opts->rssh_umask = 077;
		free(temp);
		return FALSE;
	}
	if (log){
		log_set_priority(LOG_INFO);
		log_msg("setting umask to %#o", mask);
	}
	opts->rssh_umask = mask;
	free(temp);
	return TRUE;
}

int process_user( ShellOptions_t *opts, 
		  const char *line,
		  const int lineno )
{
	char	*temp;			/* to hold user options */
	char	user[CFG_LINE_LEN + 1];	/* username of user entry */
	char	mask[CFG_LINE_LEN + 1]; /* user's umask */
	char	axs[CFG_LINE_LEN + 1];	/* user's access bits */
	char	*path = NULL;		/* user's chroot path */
	int	tmpmask;		/* temporary umask holder */
	int	pos;			/* count into line */
	int	len;			/* add len of token to pos */
	int	optlen;			/* string length of user options */
	bool	allow_scp;
	bool	allow_sftp;
	bool	allow_cvs;
	bool	allow_rdist;
	bool	allow_rsync;

	/* make space for user options */
	if ( !(temp = (char *)malloc(CFG_LINE_LEN + 1)) ){
		if (log) log_msg("fatal error: can't allocate space for user options");
		exit(1);
	}

	/* get the config bits and eat comments */
	if ( !get_asgn_param(line, lineno, temp, CFG_LINE_LEN) ){
		free(temp);
		return FALSE;
	}
	optlen = strlen(temp);

	/* now process individual config bits of temp */
	if ( !(pos = get_token(temp, user, CFG_LINE_LEN + 1, TRUE, TRUE )) ){
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("syntax error parsing config file, line %d", 
					lineno);
		}
		return FALSE;
	}

	/* 
	 * if user != username, we don't care about the rest.  Note that the
	 * bounds of both user and username are already checked, so strcmp()
	 * is ok here.  This allows syntax errors in user lines to go
	 * unnoticed whenever the user line is not for the current user, but
	 * the benefit is we don't spend time processing (potentially) lots of
	 * user lines we don't care about...
	 */
	if ( (strcmp(user, username)) ) return TRUE;
	if (log){
		log_set_priority(LOG_INFO);
		log_msg("line %d: configuring user %s", lineno, user);
	}
	if ( !(len = eat_colon(temp + pos)) ){
		if (log) log_msg("syntax error parsing config file: line %d ", 
				lineno);
		return FALSE;
	}
	pos += len;

	/* do the umask, but validate it last, since it's non-fatal */
	if ( !(len = get_token(temp + pos, mask, CFG_LINE_LEN + 1, 
			       TRUE, FALSE)) ){
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("syntax error parsing user umask, line %d", lineno);
		}
		return FALSE;
	}
	pos += len;

	/* do the access bits */
	if ( !(len = eat_colon(temp + pos)) ){
		if (log) log_msg("syntax error parsing config file: line %d ", 
				lineno);
		return FALSE;
	}
	pos += len;
	if ( !(len = get_token(temp + pos, axs, CFG_LINE_LEN + 1, 
			       TRUE, FALSE)) ){
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("syntax error parsing user access, line %d", lineno);
		}
		return FALSE;
	}
	if ( !validate_access(axs, &allow_sftp, &allow_scp, &allow_cvs,
			      &allow_rdist, &allow_rsync) ){
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("syntax error parsing access bits, line %d", lineno);
		}
		return FALSE;
	}
	pos += len;

	/* handle the chroot path -- both the colon and the path are optional */
	if ( !(len = eat_colon(temp + pos)) ) goto cleanup;
	pos += len;
	if ( !(path = (char *)malloc(CFG_LINE_LEN + 1)) ){
		if (log) log_msg("fatal error: can't allocate space for chroot path");
		exit(1);
	}
	if ( !(len = get_token(temp + pos, path, CFG_LINE_LEN + 1, 
			       TRUE, TRUE)) ){
		free(path);
		path = NULL;
	}
	pos += len;

cleanup:
	/* make sure nothing is left */
	while ( *(temp + pos) != '\0' && isspace(*(temp + pos)) ) pos++;
	if ( *(temp + pos) != '\0' ){
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("syntax error parsing user config: line %d", lineno);
		}
		return FALSE;
	}

	/* now finally validate the umask */
	if ( !validate_umask(mask, &tmpmask) ){
		if (log){
			log_set_priority(LOG_WARNING);
			log_msg("line %d: invalid umask specified, using default",
			lineno);
		}
		tmpmask = 077;
	} 
	if (log){
		log_set_priority(LOG_INFO);
		log_msg("setting %s's umask to %#o", user, tmpmask);
	}
	opts->rssh_umask = tmpmask;

	/* set the rest of the parameters */

	/* clear the default shell flags */
	opts->shell_flags = 0;
	/* now set the user-specific flags */
	if ( allow_scp ){
		if (log) log_msg("allowing scp to user %s", user);
		opts->shell_flags |= RSSH_ALLOW_SCP;
	}
	if ( allow_sftp ){
		if (log) log_msg("allowing sftp to user %s", user);
		opts->shell_flags |= RSSH_ALLOW_SFTP;
	}
	if ( allow_cvs ){
		if (log) log_msg("allowing cvs to user %s", user);
		opts->shell_flags |= RSSH_ALLOW_CVS;
	}
	if ( allow_rdist ){
		if (log) log_msg("allowing rdist to user %s", user);
		opts->shell_flags |= RSSH_ALLOW_RDIST;
	}
	if ( allow_rsync ){
		if (log) log_msg("allowing rsync to user %s", user);
		opts->shell_flags |= RSSH_ALLOW_RSYNC;
	}
	if ( path ){
		if (log) log_msg("chrooting %s to %s", user, path);
		opts->shell_flags |= RSSH_USE_CHROOT;
	}
	opts->chroot_path = path;
	got_user_config = TRUE;
	return TRUE;
}


int get_asgn_param( const char	*line,
			  const int	lineno,
			  char		*buf,	/* stick param in here */
			  const int	buflen )
{
	int	pos;		/* count into line */
	int	len;		/* add len of token to pos */

	/* make sure '=' is next token, otherwise syntax error */
	if ( (pos = eat_assignment(line)) <= 0 ){
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("error parsing config file at line %d: "
			"assignment expected", lineno);
		}
		return FALSE;
	}
	/* get the string parameter of the assignment */
	if ( !(len = get_token((line + pos), buf, buflen, FALSE, FALSE)) ){
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("syntax error parsing config file, line %d", 
				lineno);
		}
		return FALSE;
	}
	pos += len;
	/* check for ending comment */
	if ( !eat_comment(line + pos) ){
		if (log){
			log_set_priority(LOG_ERR);
			log_msg("syntax error parsing config file at line %d", 
				lineno);
		}
		return FALSE;
	}
	return pos;
}

/*
 * eat_char_token() - return position returned by get_token() if next token is
 *                    tokchar, -1 if there was no token, and zero otherwise.
 */
int eat_char_token( const char tokchar, const char *line, bool colon, 
		    bool ign_spc )
{
	char	token[CFG_LINE_LEN + 1];	/* temp storage for token */
	int	pos;

	if ( !(pos = get_token(line, token, CFG_LINE_LEN + 1, colon, ign_spc)) )
		return -1;
	if ( token[0] == tokchar && token[1] == '\0' ) return pos;
	return 0;
}

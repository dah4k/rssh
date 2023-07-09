#!/bin/sh

# conf_convert.sh - convert rssh config files from 2.0 - 2.1.1 format to rssh
#                   version 2.2 format config files.

if [ -z "$TMPDIR" ]; then
	TMPDIR=/tmp
fi

tempdir=`mktemp -d "$TMPDIR/confconv.tempXXXXXX"`
if [ ! -d "$tempdir" ]; then
	echo "$0: unable to make temporary directory"
	exit 1
fi

if [ "$#" != "0"  ]; then

	while [ -n "$1" ]; do

		if [ ! -f "$1" ]; then
			echo "$0: $1 does not exist.  Skipping." >&2
			continue
		fi

		sed 's/^\([# ]*user *= *.*:\)\([01][01][^0-9"'\''].*\)$/\1000\2/' $1 > "$tempdir/tempconf"

		mv "$tempdir/tempconf" "$1.NEW"
		shift
	done

else
	if [ ! -f /etc/rssh.conf ]; then
		echo "/etc/rssh.conf does not exist, and no parameters given." >&2
		exit 2
	fi

	sed 's/^\([# ]*user *= *.*:\)\([01][01][^0-9"'\''].*\)$/\1000\2/' /etc/rssh.conf > "$tempdir/tempconf"
		
	mv "$tempdir/tempconf" "/etc/rssh.conf.NEW"

fi

rm -rf "$tempdir"

exit 0

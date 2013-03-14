#!/bin/bash
set -u

MPSSH_BIN='../mpssh.py'
DEF_OPT='--delay 0'
LUSER='root'

function utest() {
	local ID="$1"
	local MPSSH_OPT="$2"
	local SSH_CMD="$3"
	local FILTER="$4"

	MPSSH_SSHOPT=''
	if [ "$#" -eq 5 ]; then
		local MPSSH_SSHOPT="$5" # or else we can't properly pass it
	fi

	local TMPF="$(tempfile)"

	echo "Test: $ID"
	if [ "$MPSSH_SSHOPT" != '' ]; then
		"$MPSSH_BIN" $DEF_OPT $MPSSH_OPT -O "$MPSSH_SSHOPT" "$SSH_CMD" | eval "$FILTER" > "$TMPF"
	else
		"$MPSSH_BIN" $DEF_OPT $MPSSH_OPT "$SSH_CMD" | eval "$FILTER" > "$TMPF"
	fi
	diff -u "$TMPF" "r/$ID"
	rm "$TMPF"
}

CMD='command1 arg1 arg2'
utest 'echo only header' '-S /bin/echo -u tuser -f ./fakehosts.txt' "$CMD" 'fgrep -v " tuser@"'
utest 'echo only server output' '-S /bin/echo -u tuser -f ./fakehosts.txt' "$CMD" 'fgrep " tuser@" | sort'
utest 'echo only header 2 procs' '-S /bin/echo -p 2 -u tuser -f ./fakehosts.txt' "$CMD" 'fgrep -v " tuser@"'
utest 'exec failed' '-S / --noheader -f ./fakehosts.txt' "$CMD" 'sort'
utest 'echo sshopt default' '--verbose -S /bin/echo -u tuser -f ./fakehosts.txt' "$CMD" 'grep "SSH options"'
utest 'echo sshopt custom'  '--verbose -S /bin/echo -u tuser -f ./fakehosts.txt' "$CMD" 'grep "SSH options"' 'o ConnectTimeout=3'
utest 'ssh killed' '-S ./die.sh -u tuser -f ./fakehosts.txt' "$CMD" 'sort'

CMD='[ -e /etc/mpssh-ok ] && { echo test skipped; exit 0; } ; ulimit -t 1 && while [ 1 ]; do let COUNTER=COUNTER+1; done;'
utest 'killed due to cpu limit' "-u $LUSER -f ./testhosts.txt" "$CMD" 'sort'

CMD='[ -e /etc/mpssh-ok ] && { exit 0; } ; sleep 1; exit 2'
utest 'exit value 2' "-u $LUSER -f ./testhosts.txt" "$CMD" 'sort'
utest 'exit value 2 verbose' "--zeroexit -u $LUSER -f ./testhosts.txt" "$CMD" 'sort'

CMD='[ -e /etc/mpssh-ok ] && { echo skipping ; exit 0; } ; echo "some err string" 1>&2; exit 111'
utest 'exit 111 stderr no-stdout' "-u $LUSER -f ./testhosts.txt" "$CMD" 'sort'
utest 'exit 111 stderr no-stdout opt-ignexit' "--ignexit -u $LUSER -f ./testhosts.txt" "$CMD" 'sort'

CMD='[ -e /etc/mpssh-ok ] && { echo skipping2 ; exit 0; } ; echo -e "some err\nerr-string v2" 1>&2; echo -e "sout-some\ngood-sout-text"; exit 0'
utest 'exit 0 stderr stdout' "-u $LUSER -f ./testhosts.txt" "$CMD" 'sort'
utest 'exit 0 stdout-only singlehost nosort' "--noheader -u $LUSER -f ./singlehost.txt" "$CMD" 'fgrep -- "->"'
utest 'exit 0 stderr-only singlehost nosort' "--noheader -u $LUSER -f ./singlehost.txt" "$CMD" 'fgrep -- "=>"'

CMD='/bin/true    ' # empty space
utest 'exit 0 all empty nosort' "-u $LUSER -f ./testhosts.txt" "$CMD" 'cat'

CMD='echo test'
START="$(date +%s)"
utest 'ssh connection failures' "-u root -f ./failhosts.txt" "$CMD" \
	'sort | perl -pi -e "s/ \d+\.\d+\.\d+\.\d+ / xxx /g"' 'o ConnectTimeout=3'
END="$(date +%s)"
TDIFF="$(( $END - $START ))"
if [ $TDIFF -gt 5 ]; then
	echo "Test took too much time ($TDIFF seconds) -- ConnectTimeout not working?" >&2
fi

CMD='/bin/true'
utest 'bad login user' "-u nobody -f ./testhosts.txt" "$CMD" 'sort | perl -pi -e "s/(Permission denied) .+/\$1 xxx/g"'

CMD='perl -e "print \"x\"x200"'
utest 'long text default' "-u $LUSER -f ./testhosts.txt" "$CMD" 'sort'
utest 'long text maxlen40' "-l 40 -u $LUSER -f ./testhosts.txt" "$CMD" 'sort'

CMD='echo -en "\n\nlala\n\n\n"'
utest 'newline split 1' "-u $LUSER -f ./singlehost.txt" "$CMD" 'cat'
CMD='echo -en "\n\nlala\n"'
utest 'newline split 2' "-u $LUSER -f ./singlehost.txt" "$CMD" 'cat'
CMD='echo -en "\n\nlala"'
utest 'newline split 3' "-u $LUSER -f ./singlehost.txt" "$CMD" 'cat'
CMD='echo -en "lala"'
utest 'newline split 4' "-u $LUSER -f ./singlehost.txt" "$CMD" 'cat'

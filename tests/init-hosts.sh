#!/bin/bash
set -u

[ "$#" -eq 1 ] || {
	echo "Usage: $0 login-username" >&2
	exit 1
}

LUSER="$1" ; shift

cat <<'EOF'
WARNING: This script will *DELETE* or create
a file named "mpssh-ok.flag" on the remote servers!

Press Enter to continue, or CTRL+C to abort...
EOF

read

for srv in test1.mpssh test4.mpssh test7.mpssh; do
	echo -n "$srv... "
	ssh "$LUSER@$srv" touch mpssh-ok.flag || exit 1
	echo 'OK'
done

for srv in test2.mpssh test3.mpssh test50.mpssh test6.mpssh test8.mpssh test9.mpssh; do
	echo -n "$srv... "
	ssh "$LUSER@$srv" rm -f mpssh-ok.flag || exit 1
	echo 'OK'
done

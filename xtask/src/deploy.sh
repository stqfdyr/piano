#!/bin/sh
# Remote half of cargo xtask deploy: fed to sh -s over ssh, run as root.
#
#   install  DIR INSTANCE BINARY   install DIR/BINARY, checked against DIR/BINARY.sha256
#   rollback DIR INSTANCE          go back to /usr/local/bin/piano.prev
#
# DIR is a /tmp/piano-deploy.* directory that also holds the files of contrib/;
# it is removed at the end. INSTANCE is - for the default service. A running
# daemon is switched with piano upgrade, so streams keep playing; one that is
# not running stays stopped. When a step fails, the binary on disk goes back to
# the one that was there and the daemon keeps serving it; when that cannot be done
# either, the message says what is on disk and what runs.
set -eu

die() {
	echo "deploy: $*" >&2
	exit 1
}

[ $# -ge 3 ] || die "usage: install|rollback DIR INSTANCE [BINARY]"
mode=$1 dir=$2 instance=$3
case $dir in
*..* | *[!A-Za-z0-9/._-]*) die "unexpected directory $dir" ;;
/tmp/piano-deploy.*) ;;
*) die "unexpected directory $dir" ;;
esac
trap 'rm -rf "$dir"' EXIT
[ "$(id -u)" -eq 0 ] || die "run as root"

bin=/usr/local/bin/piano
prev=$bin.prev
if [ "$instance" = - ]; then
	config=/etc/piano/piano.toml
	only=
else
	case $instance in
	'' | *[!a-z0-9_-]*) die "bad instance name $instance" ;;
	esac
	config=/etc/piano/$instance.toml
	only=$instance
fi

sum() { sha256sum "$1" | cut -d' ' -f1; }
short() { echo "${1:-?}" | cut -c1-12; }
field() { echo "$1" | cut -d' ' -f"$2"; }
# "PID SHA256" of the daemon answering on the control socket (its own report of the
# binary it runs; empty from daemons older than that report), or nothing when none
# answers (status exits 4). Asks with the installed binary, then with the new one:
# either may be unable to read this configuration or the daemon's reply. Fails, saying
# why, when neither can tell or the control socket is turned off.
daemon() {
	why=
	for b in "$bin" "$new"; do
		[ -x "$b" ] || continue
		rc=0
		json=$("$b" -c "$config" status --json 2>"$dir/status.err") || rc=$?
		case $rc in
		0)
			got=$(printf '%s\n' "$json" | sed -n \
				-e 's/^  "pid": \([0-9][0-9]*\),$/\1/p' \
				-e 's/^    "binary_sha256": "\([0-9a-f]*\)",\{0,1\}$/\1/p' | tr '\n' ' ')
			if [ -n "$(field "$got" 1)" ]; then
				echo "$got"
				return 0
			fi
			why="no pid in the reply of $b status --json"
			;;
		4)
			if "$new" -c "$config" config show | sed -n '/^\[control\]$/,/^\[/p' | grep -qx 'socket = ""'; then
				echo "deploy: the control socket is turned off in $config; deploy needs it" >&2
				return 1
			fi
			return 0
			;;
		*) why="$b status: exit $rc: $(head -c 300 "$dir/status.err")" ;;
		esac
	done
	echo "deploy: $why" >&2
	return 1
}
# What runs, from the output of daemon.
serving() {
	if [ -n "$(field "$1" 1)" ]; then
		echo "pid $(field "$1" 1) serves $(short "$(field "$1" 2)")"
	else
		echo "no daemon answers"
	fi
}
# install.sh keeps the binary it replaces as piano.prev. Its closing advice is what
# this script goes on to do.
install_bin() {
	if [ -n "$only" ]; then
		out=$(sh "$dir/install.sh" --binary "$1" --instance "$only" 2>&1) || {
			printf '%s\n' "$out" >&2
			return 1
		}
	else
		out=$(sh "$dir/install.sh" --binary "$1" 2>&1) || {
			printf '%s\n' "$out" >&2
			return 1
		}
	fi
	printf '%s\n' "$out" | sed -e '/^$/d' -e '/^next:/d'
}

case $mode in
install)
	[ $# -eq 4 ] || die "install needs BINARY"
	case $4 in
	*/* | .*) die "bad binary name $4" ;;
	esac
	(cd "$dir" && sha256sum -c "$4.sha256" >/dev/null) || die "$4: checksum mismatch"
	new=$dir/$4
	chmod 0755 "$new"
	;;
rollback)
	[ -f "$prev" ] || die "no $prev to go back to"
	new=$prev
	;;
*) die "unknown mode $mode" ;;
esac

version=$("$new" --version) || die "$new does not run"
rc=0
"$new" -c "$config" config check >/dev/null || rc=$?
case $rc in
0 | 3) ;;
*) die "$config does not pass config check with $version (a first install is done by hand with install.sh)" ;;
esac

old_sum=
[ -f "$bin" ] && old_sum=$(sum "$bin")
new_sum=$(sum "$new")
before=$(daemon) || die "cannot tell whether a daemon runs; nothing changed"
pid=$(field "$before" 1)

# Puts the binary that was on disk before back; $1 says what went wrong, for the
# message when that cannot be done.
restore() {
	[ -n "$old_sum" ] || return 0
	[ "$(sum "$bin")" != "$old_sum" ] || return 0
	[ "$(sum "$prev")" = "$old_sum" ] ||
		die "$1, and $prev is not the binary that was installed ($(short "$old_sum")): $bin stays $(short "$(sum "$bin")"); put the old one back by hand"
	install_bin "$prev" >/dev/null ||
		die "$1, and putting the previous binary back failed: $bin is $(short "$(sum "$bin")")"
	echo "deploy: put the previous binary back ($(short "$old_sum"))" >&2
}

if ! install_bin "$new"; then
	restore "install.sh failed"
	die "install.sh failed"
fi
if [ "$(sum "$bin")" != "$new_sum" ]; then
	restore "$bin is not the binary deployed"
	die "$bin is not the binary deployed"
fi
echo "deploy: $bin $(short "$old_sum") -> $(short "$new_sum")"

if [ -z "$pid" ]; then
	echo "deploy: no daemon answers on the control socket of $config; installed only"
	exit 0
fi
if [ "$(field "$before" 2)" = "$new_sum" ]; then
	echo "deploy: pid $pid already runs it"
	exit 0
fi
if ! "$bin" -c "$config" upgrade; then
	restore "upgrade failed"
	after=$(daemon) || true
	die "upgrade failed; $(serving "$after")"
fi
# The new process answered piano upgrade already; retry only a status that fails.
after=
for _ in 1 2 3; do
	after=$(daemon) && [ -n "$(field "$after" 1)" ] && break
	sleep 1
done
now=$(field "$after" 1)
reported=$(field "$after" 2)
# A binary older than the report (a rollback) is taken on its new pid alone.
if [ -z "$now" ] || [ "$now" = "$pid" ] || { [ -n "$reported" ] && [ "$reported" != "$new_sum" ]; }; then
	what="after the upgrade pid ${now:-?} does not report the deployed binary"
	restore "$what"
	if "$bin" -c "$config" upgrade >/dev/null; then
		die "$what; went back"
	fi
	back=$(daemon) || true
	die "$what, and switching back failed: $(serving "$back"); run piano upgrade by hand"
fi
[ -n "$reported" ] || echo "deploy: this binary does not report its checksum; going by its new pid"
echo "deploy: pid $pid -> $now, $version"

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
# the one that was there and the daemon keeps serving it.
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
# "PID SHA256" of the daemon answering on the control socket (its own report of the
# binary it runs; empty from daemons older than that report), or nothing.
daemon() {
	[ -x "$bin" ] || return 0
	"$bin" -c "$config" status --json 2>/dev/null | sed -n \
		-e 's/^  "pid": \([0-9][0-9]*\),$/\1/p' \
		-e 's/^    "binary_sha256": "\([0-9a-f]*\)",\{0,1\}$/\1/p' | tr '\n' ' '
}
field() { echo "$1" | cut -d' ' -f"$2"; }
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
before=$(daemon)
pid=$(field "$before" 1)

# Puts the binary that was on disk before back.
restore() {
	[ -n "$old_sum" ] || return 0
	[ "$(sum "$bin")" != "$old_sum" ] || return 0
	if [ "$(sum "$prev")" != "$old_sum" ]; then
		echo "deploy: $prev is not the binary that was installed; restore it by hand" >&2
		return 1
	fi
	install_bin "$prev" >/dev/null && echo "deploy: put the previous binary back ($(short "$old_sum"))" >&2
}

if ! install_bin "$new"; then
	restore
	die "install.sh failed"
fi
if [ "$(sum "$bin")" != "$new_sum" ]; then
	restore
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
	restore
	after=$(daemon)
	die "upgrade failed; pid $(field "$after" 1) serves $(short "$(field "$after" 2)")"
fi
after=$(daemon)
now=$(field "$after" 1)
reported=$(field "$after" 2)
# A binary older than the report (a rollback) is taken on its new pid alone.
if [ -z "$now" ] || [ "$now" = "$pid" ] || { [ -n "$reported" ] && [ "$reported" != "$new_sum" ]; }; then
	restore
	"$bin" -c "$config" upgrade >/dev/null || true
	die "after the upgrade pid ${now:-?} does not report the deployed binary; went back"
fi
[ -n "$reported" ] || echo "deploy: this binary does not report its checksum; going by its new pid"
echo "deploy: pid $pid -> $now, $version"

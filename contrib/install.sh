#!/bin/sh
# Installs or updates piano as a service (systemd or OpenRC). Run as root:
#
#   sh install.sh [--binary PATH] [--instance NAME] [--no-cert-access]
#
# --binary          the piano binary to install (default: ./piano next to this
#                   script, else the one already installed)
# --instance NAME   OpenRC only: a second service piano.NAME reading
#                   /etc/piano/NAME.toml
# --no-cert-access  leave the permissions of certificate files alone
#
# Safe to run again: the binary is replaced in one step (the old one is kept as
# piano.prev; --binary /usr/local/bin/piano.prev goes back), the configuration and
# /etc/conf.d files are kept, the service is neither enabled nor restarted. To
# switch a running service to a new binary without dropping streams, run
# piano upgrade afterwards.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
bin_dir=/usr/local/bin
piano=$bin_dir/piano
user=piano
binary=
instance=
cert_access=yes

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "  $*"; }

while [ $# -gt 0 ]; do
	case $1 in
	--binary) [ $# -ge 2 ] || die "--binary needs a path"; binary=$2; shift 2 ;;
	--instance) [ $# -ge 2 ] || die "--instance needs a name"; instance=$2; shift 2 ;;
	--no-cert-access) cert_access=no; shift ;;
	-h | --help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) die "unknown argument: $1" ;;
	esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"
case $instance in
'' | *[!a-z0-9_-]*) [ -z "$instance" ] || die "instance names use a-z, 0-9, _ and -" ;;
esac

if [ -d /run/systemd/system ]; then
	init=systemd
elif command -v openrc-run >/dev/null 2>&1; then
	init=openrc
else
	die "neither systemd nor OpenRC is running"
fi
[ -z "$instance" ] || [ "$init" = openrc ] || die "--instance is for OpenRC only"

if [ -z "$binary" ] && [ -x "$here/piano" ]; then
	binary=$here/piano
fi
if [ -n "$binary" ]; then
	version=$("$binary" --version) || die "$binary does not run"
elif [ -x "$piano" ]; then
	version=$("$piano" --version)
else
	die "no binary: pass --binary PATH"
fi

if [ -n "$instance" ]; then
	service=piano.$instance
	config=/etc/piano/$instance.toml
else
	service=piano
	config=/etc/piano/piano.toml
fi

echo "installing $version for $init"

# User and group.
if ! id "$user" >/dev/null 2>&1; then
	nologin=/usr/sbin/nologin
	[ -x "$nologin" ] || nologin=/sbin/nologin
	if command -v useradd >/dev/null 2>&1; then
		useradd --system --user-group --home-dir /var/lib/piano --no-create-home \
			--shell "$nologin" "$user"
	else
		addgroup -S "$user"
		adduser -S -D -H -h /var/lib/piano -s "$nologin" -G "$user" "$user"
	fi
	say "created user $user"
fi

# Binary: a new file renamed over the old one, so a running daemon keeps its own
# until piano upgrade.
if [ -n "$binary" ]; then
	install -d -m 0755 "$bin_dir"
	install -m 0755 "$binary" "$bin_dir/.piano.new"
	# The binary replaced stays as piano.prev: --binary $piano.prev goes back.
	if [ -f "$piano" ] && ! cmp -s "$piano" "$bin_dir/.piano.new"; then
		ln -f "$piano" "$bin_dir/.piano.prev.new"
		mv -f "$bin_dir/.piano.prev.new" "$piano.prev"
		say "$piano.prev: the binary replaced"
	fi
	mv -f "$bin_dir/.piano.new" "$piano"
	say "$piano: $version"
fi

# Directories. systemd creates the runtime, state and log directories itself;
# making them here as well keeps both managers alike.
install -d -m 0750 -o root -g "$user" /etc/piano
install -d -m 0750 -o "$user" -g "$user" /var/lib/piano /var/log/piano

# Configuration.
new_config=no
if [ ! -e "$config" ]; then
	umask 027
	cat >"$config" <<'EOF'
# piano configuration; see README.md. Check with: piano config check

[tls]
cert = "/etc/letsencrypt/live/media.example.com/fullchain.pem"
key  = "/etc/letsencrypt/live/media.example.com/privkey.pem"

[access]
# Client addresses and networks allowed to connect.
allow = ["203.0.113.7", "2001:db8:1:2::/64"]

[[site]]
host     = "media.example.com"
upstream = "https://emby.example.net"
EOF
	new_config=yes
	say "wrote an example $config"
fi
chgrp "$user" "$config"
chmod 0640 "$config"

if [ "$new_config" = no ]; then
	rc=0
	"$piano" -c "$config" config check || rc=$?
	case $rc in
	0 | 3) ;;
	*) die "$config does not pass config check" ;;
	esac
fi

# Certificates: the daemon runs as $user and rereads them when they change, so it
# needs read access to the key files and every directory above them. certbot keeps
# the group and group bits of a private key when it renews it.
# as_user CMD PATH: sh -c CMD as $user with PATH as $1, never parsed as shell code.
as_user() { su -s /bin/sh -c "$1" "$user" sh "$2"; }
grant() {
	p=$1
	for target in "$p" "$(readlink -f "$p")"; do
		# One directory per line, top down: names may hold spaces.
		dirs=
		d=$(dirname "$target")
		while [ "$d" != / ]; do
			dirs="$d
$dirs"
			d=$(dirname "$d")
		done
		while IFS= read -r d; do
			[ -n "$d" ] || continue
			as_user 'test -x "$1"' "$d" && continue
			[ "$(stat -c %U:%G "$d")" = root:root ] ||
				die "$user cannot enter $d (owner $(stat -c %U:%G "$d")); grant it access by hand"
			chgrp "$user" "$d"
			chmod g+rx "$d"
			say "$d: group $user may enter"
		done <<-EOF
			$dirs
		EOF
		as_user 'test -r "$1"' "$target" && continue
		[ "$(stat -c %U:%G "$target")" = root:root ] ||
			die "$user cannot read $target (owner $(stat -c %U:%G "$target")); grant it access by hand"
		chgrp "$user" "$target"
		chmod g+r "$target"
		say "$target: group $user may read"
	done
}
if [ "$new_config" = no ] && [ "$cert_access" = yes ]; then
	# A failing su would read as "cannot enter" and regroup every directory above.
	as_user true / ||
		die "cannot run commands as $user with su; run again with --no-cert-access and let $user read the certificate and key by hand"
	# config show writes a path as a basic string, or as a literal one when it holds
	# a quote or a backslash; a basic string with escapes is not read.
	paths=$("$piano" -c "$config" config show | sed -nE \
		-e 's/^[[:space:]]*(cert|key)[[:space:]]*=[[:space:]]*"([^"\\]*)"[[:space:]]*$/\2/p' \
		-e "s/^[[:space:]]*(cert|key)[[:space:]]*=[[:space:]]*'([^']*)'[[:space:]]*\$/\\2/p")
	[ "$(printf '%s\n' "$paths" | grep -c .)" -eq 2 ] ||
		die "cannot read the certificate and key paths from piano config show; run again with --no-cert-access"
	while IFS= read -r f; do
		grant "$f"
	done <<-EOF
		$(printf '%s\n' "$paths" | sort -u)
	EOF
fi

# Service.
case $init in
systemd)
	install -m 0644 "$here/piano.service" /etc/systemd/system/piano.service
	systemctl daemon-reload
	say "/etc/systemd/system/piano.service"
	;;
openrc)
	install -m 0755 "$here/piano.initd" /etc/init.d/piano
	say "/etc/init.d/piano"
	if [ -n "$instance" ]; then
		ln -sfn piano "/etc/init.d/$service"
		say "/etc/init.d/$service"
	fi
	if [ ! -e "/etc/conf.d/$service" ]; then
		install -m 0644 "$here/piano.confd" "/etc/conf.d/$service"
		[ -z "$instance" ] ||
			sed -i "s|^#PIANO_CONFIG=.*|PIANO_CONFIG=\"$config\"|" "/etc/conf.d/$service"
		say "/etc/conf.d/$service"
	fi
	;;
esac
if [ -d /etc/logrotate.d ]; then
	install -m 0644 "$here/piano.logrotate" /etc/logrotate.d/piano
	say "/etc/logrotate.d/piano"
fi

echo
if [ "$new_config" = yes ]; then
	echo "next: edit $config, then run this script again"
	exit 0
fi
running=no
"$piano" -c "$config" status >/dev/null 2>&1 && running=yes
if [ "$running" = yes ]; then
	echo "next: piano -c $config upgrade    # switch to the installed binary, streams keep playing"
else
	case $init in
	systemd) echo "next: systemctl enable --now piano" ;;
	openrc) echo "next: rc-update add $service default && rc-service $service start" ;;
	esac
fi

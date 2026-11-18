#!/bin/sh
# intergate tunnel, without installing anything: downloads the intergate
# client matching {{.Dashboard}}, checks it against the release's
# SHA256SUMS, runs it and deletes it when it ends.
#
#   curl -fsSL {{.URL}} | sh -s -- SUBDOMAIN [--http PORT] [--tcp NAME=PORT] [--udp NAME=PORT] [-i KEY]
#
# --cache (first) keeps the client in ~/.cache/intergate/<version> to start
# faster next time. INTERGATE_DOWNLOAD_URL replaces GitHub with a directory
# holding intergate-<os>-<arch>.tar.gz and SHA256SUMS.
#
# --install keeps the tunnel open instead, as a service started at boot:
# it installs intergate-tunnel in /usr/local/bin (with sudo), adds the
# subdomain with its own key for this machine, and installs the service.
# New ports take --allow ADDRESS (or --allow any). With --user too, all of
# it is yours: ~/.local/bin, ~/.config/intergate-tunnel and a user service.
set -eu

REPO="jgermade/intergate"
VERSION='{{.Version}}'
SERVER='{{.Server}}'
HOST_KEY='{{.HostKey}}'

die() {
	printf 'intergate: %s\n' "$*" >&2
	exit 1
}
need() { command -v "$1" >/dev/null 2>&1; }

fetch() {
	if need curl; then
		curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$1"
	elif need wget; then
		wget -q --tries=3 --timeout=20 -O "$2" "$1"
	else
		die "curl or wget is needed to download the client"
	fi
}

sha256() {
	if need sha256sum; then
		sha256sum "$1" | awk '{ print $1 }'
	elif need shasum; then
		shasum -a 256 "$1" | awk '{ print $1 }'
	elif need openssl; then
		openssl dgst -sha256 "$1" | awk '{ print $NF }'
	else
		die "no sha256sum, shasum or openssl here to check the download with"
	fi
}

DASHBOARD='{{.Dashboard}}'

cache=0
if [ "${1:-}" = --cache ]; then
	cache=1
	shift
fi
# --install, anywhere: the rest goes to intergate-tunnel add.
install=0
n=$#
while [ "$n" -gt 0 ]; do
	a=$1
	shift
	n=$((n - 1))
	if [ "$a" = --install ]; then install=1; else set -- "$@" "$a"; fi
done
[ $# -gt 0 ] || die "usage: sh -s -- SUBDOMAIN [--http PORT] [--tcp NAME=PORT] [--udp NAME=PORT]"

os=$(uname -s)
arch=$(uname -m)
case "$os" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "the intergate client is built for Linux and macOS, and this is $os" ;;
esac
case "$arch" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) die "there is no intergate build for $arch" ;;
esac
if [ "$os" = darwin ] && [ "$arch" = amd64 ] &&
	[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
	arch=arm64
fi
target="$os-$arch"
name=intergate
[ "$install" = 0 ] || name=intergate-tunnel
asset="$name-$target.tar.gz"

# The server's own version, so the client speaks its language; a server
# built from source asks for the latest release.
VERSION=${INTERGATE_VERSION:-$VERSION}
if [ -n "${INTERGATE_DOWNLOAD_URL:-}" ]; then
	base=${INTERGATE_DOWNLOAD_URL%/}
elif [ -n "$VERSION" ]; then
	base="https://github.com/$REPO/releases/download/v${VERSION#v}"
else
	base="https://github.com/$REPO/releases/latest/download"
fi

dir=""
if [ "$cache" = 1 ] && [ -n "$VERSION" ]; then
	dir="${XDG_CACHE_HOME:-$HOME/.cache}/intergate/${VERSION#v}"
fi
bin="$dir/$name-$target/$name"
if [ -z "$dir" ] || [ ! -x "$bin" ]; then
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/intergate.XXXXXX")
	trap 'rm -rf "$tmp"' EXIT
	trap 'exit 130' INT TERM
	fetch "$base/$asset" "$tmp/$asset" || die "could not download $base/$asset"
	fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not download $base/SHA256SUMS"
	want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/SHA256SUMS")
	[ -n "$want" ] || die "SHA256SUMS does not list $asset"
	[ "$(sha256 "$tmp/$asset")" = "$want" ] || die "$asset does not match its checksum"
	if [ -n "$dir" ]; then
		mkdir -p "$dir"
		tar -xzf "$tmp/$asset" -C "$dir" || die "could not unpack $asset"
	else
		tar -xzf "$tmp/$asset" -C "$tmp" || die "could not unpack $asset"
		bin="$tmp/$name-$target/$name"
	fi
fi
[ -x "$bin" ] || die "$asset has no $name binary in it"

if [ "$install" = 0 ]; then
	"$bin" tunnel --server "$SERVER" --host-key "$HOST_KEY" "$@"
	exit
fi

# The service: the machine's own tunnels, which need root, or with --user
# the user's, in ~/.local/bin.
user=0
for a in "$@"; do [ "$a" != --user ] || user=1; done
root() {
	if [ "$user" = 1 ] || [ "$(id -u)" = 0 ]; then
		"$@"
	elif need sudo; then
		sudo "$@"
	else
		die "installing the service needs root, and sudo is not installed: run this as root, or add --user"
	fi
}
dest=${INTERGATE_INSTALL_DIR:-/usr/local/bin}
[ "$user" = 0 ] || dest=${INTERGATE_INSTALL_DIR:-$HOME/.local/bin}
sub=$1
shift
root mkdir -p "$dest"
root cp "$bin" "$dest/.intergate-tunnel.new"
root mv -f "$dest/.intergate-tunnel.new" "$dest/intergate-tunnel"
echo "Installed $dest/intergate-tunnel."
tty=/dev/null
if (: </dev/tty) 2>/dev/null; then tty=/dev/tty; fi
root "$dest/intergate-tunnel" add "$sub" --dashboard "$DASHBOARD" --host-key "$HOST_KEY" "$@" <"$tty"
if [ "$user" = 1 ]; then
	"$dest/intergate-tunnel" install --user
else
	root "$dest/intergate-tunnel" install
fi

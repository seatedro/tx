#!/bin/sh
# Installs tx and txd from a release of seatedro/tx:
#
#     curl -fsSL https://github.com/seatedro/tx/releases/latest/download/install.sh | sh
#
# With --txd, it then runs `txd --install`, which keeps txd running for
# this user as a service, so tx can connect to this machine. A txd that
# was already running restarts with the new build; its sessions keep
# running.
#
# TX_VERSION picks a release, such as 0.0.0-nightly.20261031, instead of
# the latest. TX_INSTALL_DIR is where tx and txd go, ~/.local/bin unless
# it's set.
set -eu

releases=https://github.com/seatedro/tx/releases

main() {
    txd=no
    for arg in "$@"; do
        case $arg in
        --txd) txd=yes ;;
        *) fail "unknown option $arg; the only option is --txd" ;;
        esac
    done

    platform=$(platform)
    dir=${TX_INSTALL_DIR:-$HOME/.local/bin}
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    # SHA256SUMS names each platform's tarball, and the version is in the
    # name.
    if [ -n "${TX_VERSION:-}" ]; then
        fetch "$releases/download/v$TX_VERSION/SHA256SUMS" "$tmp/SHA256SUMS"
    else
        fetch "$releases/latest/download/SHA256SUMS" "$tmp/SHA256SUMS"
    fi
    suffix="-$platform.tar.gz"
    name=$(awk -v suffix="$suffix" 'substr($2, length($2) - length(suffix) + 1) == suffix { print $2 }' "$tmp/SHA256SUMS")
    [ -n "$name" ] || fail "the release has no build for $platform"
    version=${name#tx-}
    version=${version%"$suffix"}

    fetch "$releases/download/v$version/$name" "$tmp/$name"
    want=$(awk -v name="$name" '$2 == name { print $1 }' "$tmp/SHA256SUMS")
    got=$(sha256 "$tmp/$name")
    [ "$got" = "$want" ] || fail "$name doesn't have the SHA-256 that SHA256SUMS gives"
    tar -xzf "$tmp/$name" -C "$tmp"

    # Renamed into place: a running txd keeps its own file, and copying
    # over a running binary fails on Linux.
    mkdir -p "$dir"
    for binary in tx txd; do
        cp "$tmp/tx-$version-$platform/$binary" "$dir/.$binary.new"
        mv -f "$dir/.$binary.new" "$dir/$binary"
    done
    echo "installed tx and txd $version in $dir"

    if [ "$txd" = yes ]; then
        running=$(service_running)
        "$dir/txd" --install
        # `txd --install` leaves a running server alone.
        if [ "$running" = yes ]; then restart_service; fi
    fi

    case ":$PATH:" in
    *":$dir:"*) ;;
    *) echo "$dir isn't in PATH; add it to run tx and txd by name" ;;
    esac
}

# The platform's name in release tarballs.
platform() {
    case $(uname -s) in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) fail "no builds for $(uname -s)" ;;
    esac
    case $(uname -m) in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) fail "no builds for $(uname -m)" ;;
    esac
    echo "$os-$arch"
}

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$2" "$1" || fail "can't download $1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1" || fail "can't download $1"
    else
        fail "downloading needs curl or wget"
    fi
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d ' ' -f 1
    else
        fail "checking the download needs sha256sum or shasum"
    fi
}

# The service `txd --install` sets up: the systemd user unit, or the
# LaunchAgent, both named txd.
launchd_target() {
    uid=$(id -u)
    if launchctl print "gui/$uid" >/dev/null 2>&1; then echo "gui/$uid/txd"; else echo "user/$uid/txd"; fi
}

service_running() {
    case $(uname -s) in
    Linux) systemctl --user --quiet is-active txd.service 2>/dev/null && echo yes || echo no ;;
    Darwin) launchctl print "$(launchd_target)" 2>/dev/null | grep -q 'state = running' && echo yes || echo no ;;
    esac
}

restart_service() {
    case $(uname -s) in
    Linux) systemctl --user restart txd.service ;;
    Darwin) launchctl kickstart -k "$(launchd_target)" ;;
    esac
    echo "restarted txd"
}

fail() {
    echo "install.sh: $1" >&2
    exit 1
}

main "$@"

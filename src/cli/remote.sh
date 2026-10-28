# The remote half of remote.zig. tx runs it over ssh as
#
#     sh -c SCRIPT tx STEP DIR URL MEMBER SHA256 TXD_ARG...
#
# DIR is under ~/.local/share/tx. STEP is one of:
#
#   run       Runs DIR/txd, or else txd from PATH. With neither, prints
#             "need SYSTEM MACHINE PREVIOUS" and exits with 3. PREVIOUS is
#             "upgrade" when another DIR under ~/.local/share/tx has a txd,
#             and "first" otherwise.
#   download  Downloads the release tarball at URL, takes the file MEMBER
#             out of it, checks that file's SHA-256, and runs it as
#             DIR/txd. Exits with 4 when any of that fails.
#   copy      Saves stdin as DIR/txd and runs it.
#
# URL, MEMBER and SHA256 are empty except for download. The script has no
# backslashes, since fish reads them even in single quotes.

step=$1
dir=$HOME/.local/share/tx/$2
url=$3
member=$4
sha256=$5
shift 5

# Runs txd.part as txd. The rename means a partly written txd never takes
# the place of a complete one.
run_part() {
    chmod 755 "$dir/txd.part" && mv "$dir/txd.part" "$dir/txd" && exec "$dir/txd" "$@"
}

download() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$2" "$1"
    else
        wget -qO "$2" "$1"
    fi
}

case $step in
run)
    if [ -x "$dir/txd" ]; then
        exec "$dir/txd" "$@"
    fi
    if command -v txd >/dev/null 2>&1; then
        exec txd "$@"
    fi
    previous=first
    for old in "$HOME"/.local/share/tx/*/txd; do
        if [ -x "$old" ]; then
            previous=upgrade
        fi
    done
    echo "need $(uname -s) $(uname -m) $previous"
    exit 3
    ;;

download)
    mkdir -p "$dir" || exit 4
    tarball=$dir/download.tar.gz
    download "$url" "$tarball" && tar -xzOf "$tarball" "$member" >"$dir/txd.part"
    status=$?
    rm -f "$tarball"
    if [ "$status" -ne 0 ]; then
        rm -f "$dir/txd.part"
        exit 4
    fi

    sum=$(sha256sum "$dir/txd.part" 2>/dev/null || shasum -a 256 "$dir/txd.part")
    if [ "${sum%% *}" != "$sha256" ]; then
        rm -f "$dir/txd.part"
        echo "the downloaded txd has the wrong SHA-256" >&2
        exit 4
    fi
    run_part "$@"
    ;;

copy)
    mkdir -p "$dir" && cat >"$dir/txd.part" && run_part "$@"
    ;;
esac

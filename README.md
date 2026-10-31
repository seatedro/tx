# tx

A remote terminal, meant to replace ssh and mosh, built on QUIC and
[libghostty-vt](https://github.com/ghostty-org/ghostty). Sessions keep
running on the server, survive network changes and sleep, and can be
reattached from anywhere.

tx is early and changes often. Don't rely on it yet.

## Install

Each night that main changes, it is published as a release,
`0.0.0-nightly.YYYYMMDD`. To install tx and txd from the latest in
`~/.local/bin`, on Linux or macOS:

    curl -fsSL https://github.com/seatedro/tx/releases/latest/download/install.sh | sh

On a machine that tx connects to, add `--txd`, which keeps txd running as a
service for your user. Run it again to upgrade; sessions keep running.

    curl -fsSL https://github.com/seatedro/tx/releases/latest/download/install.sh | sh -s -- --txd

## Use

    tx [USER@]HOST          # attach the detached session, or start one
    tx --new HOST           # start another session
    tx --list HOST          # list sessions
    tx --attach ID HOST     # attach session ID
    tx --kill ID HOST       # end session ID
    tx HOST COMMAND...      # run COMMAND, as ssh does
    tx -t HOST COMMAND...   # run COMMAND on a terminal, as ssh -t does

tx takes ssh's options, read as ssh reads them, so tools that run ssh can
run tx: `GIT_SSH_COMMAND=tx git clone ssh://host/repo`, `rsync -e tx`. `-p`
is txd's port. Options for features tx lacks, such as `-L`, are refused.
tx connects to the `HostName`, as the `User`, that ssh's config gives the
host, as `ssh -G` prints them, so `tx pulsar` reaches what `ssh pulsar`
does.

`~.` detaches. A new session gets the client's `TERM`, `COLORTERM`, `LANG`
and `LC_*`, and the terminfo entry for its `TERM`, so `xterm-ghostty` and
`xterm-kitty` work on hosts whose ncurses lacks them. txd compiles the entry
with the host's `tic`; without it, the session's `TERM` is `xterm-256color`.

tx logs in with the same keys as ssh: the SSH agent's Ed25519 and RSA keys,
then `~/.ssh/id_ed25519`. txd accepts the keys in `~/.ssh/authorized_keys`.
Without a user from `-l`, the destination or ssh's config, tx names none,
and txd logs you in to the account it runs as.

The first time tx connects to a host, it shows the host's key fingerprint
and asks whether to trust it, as ssh does. `txd --install` prints the same
fingerprint on the host. tx trusts the key without asking when
`~/.ssh/known_hosts` lists it for the host, or when Tailscale says the host
is one of your own nodes: yours, and not tagged. tx records the key in
`~/.config/tx/known_hosts`.

### Clipboard

On a Linux host, programs share the clipboard of the Mac you run tx on,
text and images: txd runs a Wayland server that does only the clipboard,
and sessions get `WAYLAND_DISPLAY`. Ctrl-V of a screenshot in Claude Code or
Codex works as it does locally. Claude Code needs wl-clipboard on the host.

Programs read the clipboard only within 5 seconds of a paste: Ctrl-V, or
any paste into the terminal. Other reads, such as Neovim's `"+p`, get
nothing. Copies on the host, such as Neovim's `"+y`, go to the Mac's
clipboard. Nothing is shared while the pasteboard holds what a password
manager marked as concealed.

## Server

txd runs on the host as your user. `install.sh --txd` sets it up as a user
service: systemd on Linux, launchd on macOS, or a background process
elsewhere. `txd --uninstall` ends the host's sessions, and removes the
service and txd's files. tx never runs ssh, and never installs anything on
a host.

Each session runs in a process of its own, so a restart or upgrade of txd
leaves sessions running, and attached clients reconnect to the new txd.

On a machine where Tailscale is up, txd listens only on its tailnet
addresses and loopback, so that only your tailnet reaches it. Elsewhere it
listens on every address. The port is 8739, on UDP. `txd --listen` picks
the addresses: `tailnet`, or an address and port.

## Build

Needs Zig 0.17.0, or `nix develop`.

    zig build               # zig-out/bin/tx and zig-out/bin/txd
    zig build test
    zig build fuzz --fuzz   # fuzz what a client reaches before it logs in, and Wayland's wire format
    zig build release       # static Linux and macOS builds in zig-out/release

## License

MIT

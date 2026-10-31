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
    tx --uninstall HOST     # end the sessions, and remove txd from HOST
    tx HOST COMMAND...      # run COMMAND, as ssh does
    tx -t HOST COMMAND...   # run COMMAND on a terminal, as ssh -t does

tx takes ssh's options, read as ssh reads them, so tools that run ssh can
run tx: `GIT_SSH_COMMAND=tx git clone ssh://host/repo`, `rsync -e tx`. `-p`
is txd's port. Options for features tx lacks, such as `-L`, are refused.
tx connects to the `HostName`, as the `User`, that ssh's config gives the
host, as `ssh -G` prints them, so `tx pulsar` reaches what `ssh pulsar`
does.

Linked as `ssh` in a directory ahead of ssh in `PATH`, tx takes ssh's
place: `-p` is then sshd's port, and txd keeps its own, 8739. The ssh that
tx runs for installs gets the same options, and the real ssh runs instead
for what tx can't do, such as `-L`, or a host without txd.

    ln -s "$(command -v tx)" ~/.local/bin/ssh

`~.` detaches. A new session gets the client's `TERM`, `COLORTERM`, `LANG`
and `LC_*`, and the terminfo entry for its `TERM`, so `xterm-ghostty` and
`xterm-kitty` work on hosts whose ncurses lacks them. txd compiles the entry
with the host's `tic`; without it, the session's `TERM` is `xterm-256color`.

tx logs in with the same keys as ssh: the SSH agent's Ed25519 and RSA keys,
then `~/.ssh/id_ed25519`. txd accepts the keys in `~/.ssh/authorized_keys`.

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

tx copies txd to a host that has none, and sets it up as a user service:
systemd on Linux, launchd on macOS, or a background process elsewhere.
It asks before the first copy to a host. `tx --uninstall HOST` ends the
host's sessions, and removes txd, its service and its files, after asking
too. `--yes` skips the questions.
Each session runs in a process of its own, so a restart or upgrade of txd
leaves sessions running, and attached clients reconnect to the new txd.
A txd older than 88d63d9 runs sessions inside itself, and its sessions
end when it is replaced.

txd uses Single Packet Authorization (SPA): it answers only clients that
hold its SPA key, which tx reads over ssh along with the host key. To
anyone else the port looks closed. `txd --open` answers every client.

## Build

Needs Zig 0.17.0, or `nix develop`.

    zig build               # zig-out/bin/tx and zig-out/bin/txd
    zig build test
    zig build fuzz --fuzz   # fuzz what a client reaches before it logs in, and Wayland's wire format
    zig build release       # static Linux and macOS builds in zig-out/release

## License

MIT

# tx

A remote terminal, meant to replace ssh and mosh, built on QUIC and
[libghostty-vt](https://github.com/ghostty-org/ghostty). Sessions keep
running on the server, survive network changes and sleep, and can be
reattached from anywhere.

tx is early and changes often. Don't rely on it yet.

## Use

    tx [USER@]HOST          # attach the detached session, or start one
    tx --new HOST           # start another session
    tx --list HOST          # list sessions
    tx --attach ID HOST     # attach session ID
    tx --kill ID HOST       # end session ID
    tx --uninstall HOST     # end the sessions, and remove txd from HOST

`~.` detaches. A new session gets the client's `TERM`, `COLORTERM`, `LANG`
and `LC_*`.

tx logs in with the same keys as ssh: the SSH agent's Ed25519 and RSA keys,
then `~/.ssh/id_ed25519`. txd accepts the keys in `~/.ssh/authorized_keys`.

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
    zig build fuzz --fuzz   # fuzz what a client reaches before it logs in
    zig build release       # static Linux and macOS builds in zig-out/release

## License

MIT

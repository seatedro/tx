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

`~.` detaches.

tx logs in with the same keys as ssh: the SSH agent's Ed25519 and RSA keys,
then `~/.ssh/id_ed25519`. txd accepts the keys in `~/.ssh/authorized_keys`.

## Build

Needs Zig 0.17.0, or `nix develop`.

    zig build            # zig-out/bin/tx and zig-out/bin/txd
    zig build test
    zig build release    # static Linux and macOS builds in zig-out/release
